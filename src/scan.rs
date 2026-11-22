use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

use crate::autowrap::{detect_config_path, ClientTarget};
use crate::lockfile::{LockDrift, ShieldLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,
    pub server: String,
    pub tool: Option<String>,
    pub message: String,
    pub diff: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub grade: char,
    pub score: i32,
    pub servers_scanned: usize,
    pub tools_inspected: usize,
    pub findings: Vec<Finding>,
}

struct ServerSpec {
    name: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
}

struct ProbedServer {
    spec: ServerSpec,
    tools: Vec<Value>,
}

#[derive(Default)]
struct TrifectaBuckets {
    private_data: BTreeSet<String>,
    untrusted_input: BTreeSet<String>,
    external_comms: BTreeSet<String>,
}

pub async fn run_lock_command(
    client: ClientTarget,
    file_override: Option<PathBuf>,
    out_path: PathBuf,
) -> Result<()> {
    let config_path = resolve_mcp_config(client, file_override)?;
    let specs = load_server_specs(&config_path)?;
    if specs.is_empty() {
        bail!("No stdio MCP servers found in {}", config_path.display());
    }

    let mut lock = ShieldLock::empty();
    let mut total_tools = 0usize;

    for spec in specs {
        eprint!("Probing '{}' ... ", spec.name);
        match probe_server_tools(&spec).await {
            Ok(tools) => {
                eprintln!("pinned {} tools", tools.len());
                total_tools += tools.len();
                let cmd_display = format!("{} {}", spec.command, spec.args.join(" "));
                lock.pin_server(&spec.name, cmd_display.trim(), &tools);
            }
            Err(err) => {
                eprintln!("SKIPPED ({})", err);
            }
        }
    }

    lock.save(&out_path)?;
    println!(
        "\n\x1b[32m[LOCKED]\x1b[0m Pinned {} tools across {} servers -> {}",
        total_tools,
        lock.servers.len(),
        out_path.display()
    );
    Ok(())
}

pub async fn run_scan_command(
    client: ClientTarget,
    file_override: Option<PathBuf>,
    lock_path: PathBuf,
    json_output: bool,
) -> Result<()> {
    let config_path = resolve_mcp_config(client, file_override)?;
    let specs = load_server_specs(&config_path)?;
    if specs.is_empty() {
        bail!("No stdio MCP servers found in {}", config_path.display());
    }

    let mut probed = Vec::new();
    let mut findings = Vec::new();

    for spec in specs {
        if !json_output {
            eprint!("Scanning '{}' ... ", spec.name);
        }
        match probe_server_tools(&spec).await {
            Ok(tools) => {
                if !json_output {
                    eprintln!("{} tools", tools.len());
                }
                probed.push(ProbedServer { spec, tools });
            }
            Err(err) => {
                if !json_output {
                    eprintln!("FAILED ({})", err);
                }
                findings.push(Finding {
                    severity: Severity::Low,
                    category: "PROBE_ERROR".into(),
                    server: spec.name,
                    tool: None,
                    message: format!("Could not complete MCP handshake: {}", err),
                    diff: None,
                });
            }
        }
    }

    let tools_inspected: usize = probed.iter().map(|s| s.tools.len()).sum();

    // 1. Lockfile verification (Rug-Pull Detection)
    if lock_path.exists() {
        match ShieldLock::load(&lock_path) {
            Ok(lock) => {
                for ps in &probed {
                    for drift in lock.verify_server(&ps.spec.name, &ps.tools) {
                        match drift {
                            LockDrift::UnpinnedServer { server } => findings.push(Finding {
                                severity: Severity::High,
                                category: "UNPINNED_SERVER".into(),
                                server,
                                tool: None,
                                message: "Server missing from shield.lock — run `agent-shield lock` to pin schemas".into(),
                                diff: None,
                            }),
                            LockDrift::ToolAdded { server, tool, actual_hash } => findings.push(Finding {
                                severity: Severity::High,
                                category: "RUG_PULL_NEW_TOOL".into(),
                                server,
                                tool: Some(tool.clone()),
                                message: format!("Unpinned new tool '{}' appeared (sha256: {}..)", tool, &actual_hash[..12]),
                                diff: None,
                            }),
                            LockDrift::ToolRemoved { server, tool } => findings.push(Finding {
                                severity: Severity::Medium,
                                category: "SCHEMA_DRIFT".into(),
                                server,
                                tool: Some(tool.clone()),
                                message: format!("Previously pinned tool '{}' was removed", tool),
                                diff: None,
                            }),
                            LockDrift::SchemaMutated { server, tool, expected_hash, actual_hash, diff } => {
                                findings.push(Finding {
                                    severity: Severity::Critical,
                                    category: "RUG_PULL_MUTATION".into(),
                                    server,
                                    tool: Some(tool.clone()),
                                    message: format!(
                                        "Tool '{}' schema mutated! ({}.. -> {}..)",
                                        tool,
                                        &expected_hash[..10],
                                        &actual_hash[..10]
                                    ),
                                    diff: Some(diff),
                                });
                            }
                        }
                    }
                }
            }
            Err(e) => findings.push(Finding {
                severity: Severity::Medium,
                category: "LOCKFILE_ERROR".into(),
                server: "global".into(),
                tool: None,
                message: format!("Could not read {}: {}", lock_path.display(), e),
                diff: None,
            }),
        }
    } else {
        findings.push(Finding {
            severity: Severity::High,
            category: "UNPINNED_SCHEMAS".into(),
            server: "global".into(),
            tool: None,
            message: format!(
                "No {} found — all {} tools are vulnerable to silent rug-pull mutations (run `agent-shield lock`)",
                lock_path.display(),
                tools_inspected
            ),
            diff: None,
        });
    }

    // 2. Per-tool poisoning scanner (hidden Unicode, XML directives, covert instructions)
    run_tool_poisoning_checks(&probed, &mut findings)?;

    // 3. Cross-server tool shadowing & name collisions
    run_shadowing_checks(&probed, &mut findings)?;

    // 4. Cross-server Lethal Trifecta capability graph
    run_lethal_trifecta_check(&probed, &mut findings);

    // Sort highest severity first
    findings.sort_by_key(|f| f.severity);

    let (score, grade) = compute_grade(&findings);
    let report = ScanReport {
        grade,
        score,
        servers_scanned: probed.len(),
        tools_inspected,
        findings,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_scorecard(&report);
    }

    if report
        .findings
        .iter()
        .any(|f| f.severity == Severity::Critical)
    {
        std::process::exit(2);
    }

    Ok(())
}

fn run_tool_poisoning_checks(probed: &[ProbedServer], findings: &mut Vec<Finding>) -> Result<()> {
    let tag_re = Regex::new(r"(?i)<\s*(important|system|instructions|secret|hidden|override)\s*>")?;
    let directive_re = Regex::new(
        r"(?i)(ignore\s+(all\s+)?(previous|prior)\s+instructions|do\s+not\s+(tell|mention|inform)\s+the\s+user|before\s+(calling|using)\s+this\s+tool.*read|pass\s+(the\s+)?contents?\s+of\s+.*(\.env|\.ssh|id_rsa|config)|silently\s+(execute|send|read|exfiltrate)|sidenote\s*:)",
    )?;

    for ps in probed {
        for tool in &ps.tools {
            let tool_name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            // Collect ALL strings from description + nested inputSchema descriptions
            let mut texts = Vec::new();
            collect_strings(tool, &mut texts);
            let combined = texts.join("\n");

            let hidden_chars = count_hidden_unicode(&combined);
            if hidden_chars > 0 {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: "UNICODE_SMUGGLING".into(),
                    server: ps.spec.name.clone(),
                    tool: Some(tool_name.to_string()),
                    message: format!(
                        "Detected {} invisible Unicode/BiDi tag characters hidden inside tool metadata",
                        hidden_chars
                    ),
                    diff: None,
                });
            }

            if tag_re.is_match(&combined) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: "TOOL_POISONING".into(),
                    server: ps.spec.name.clone(),
                    tool: Some(tool_name.to_string()),
                    message: "Hidden prompt-injection XML directive tag found inside tool schema/description".into(),
                    diff: None,
                });
            }

            if let Some(m) = directive_re.find(&combined) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: "TOOL_POISONING".into(),
                    server: ps.spec.name.clone(),
                    tool: Some(tool_name.to_string()),
                    message: format!(
                        "Covert agent coercion directive in metadata: \"{}\"",
                        m.as_str()
                    ),
                    diff: None,
                });
            }

            let desc_len = tool
                .get("description")
                .and_then(|v| v.as_str())
                .map(str::len)
                .unwrap_or(0);
            if desc_len > 1200 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: "BLOATED_METADATA".into(),
                    server: ps.spec.name.clone(),
                    tool: Some(tool_name.to_string()),
                    message: format!(
                        "Unusually large tool description ({} chars) — common hiding place for indirect prompt injection",
                        desc_len
                    ),
                    diff: None,
                });
            }
        }
    }

    Ok(())
}

fn run_shadowing_checks(probed: &[ProbedServer], findings: &mut Vec<Finding>) -> Result<()> {
    // Map every tool name -> list of servers exposing it
    let mut tool_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ps in probed {
        for tool in &ps.tools {
            if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
                tool_owners
                    .entry(name.to_string())
                    .or_default()
                    .push(ps.spec.name.clone());
            }
        }
    }

    // A. Duplicate tool names across different servers
    for (tool_name, owners) in &tool_owners {
        if owners.len() > 1 {
            findings.push(Finding {
                severity: Severity::High,
                category: "TOOL_COLLISION".into(),
                server: owners.join(", "),
                tool: Some(tool_name.clone()),
                message: format!(
                    "Tool '{}' is exposed by multiple servers ({}) — vulnerable to tool-name shadowing",
                    tool_name,
                    owners.join(", ")
                ),
                diff: None,
            });
        }
    }

    // B. Server A's metadata attempting to alter/hijack Server B's tool behavior
    let hijack_verb_re = Regex::new(
        r"(?i)\b(instead|override|redirect|forward|bcc|always\s+use|never\s+use|before\s+calling|also\s+call|modify\s+the\s+behavior)\b",
    )?;

    for ps in probed {
        for tool in &ps.tools {
            let cur_tool = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let desc = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !hijack_verb_re.is_match(desc) {
                continue;
            }

            for (other_tool, owners) in &tool_owners {
                if other_tool.len() < 4 || other_tool == cur_tool {
                    continue;
                }
                if owners.iter().all(|o| o == &ps.spec.name) {
                    continue;
                }
                let ref_re = Regex::new(&format!(r"(?i)\b{}\b", regex::escape(other_tool)))?;
                if ref_re.is_match(desc) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: "CROSS_SERVER_SHADOWING".into(),
                        server: ps.spec.name.clone(),
                        tool: Some(cur_tool.to_string()),
                        message: format!(
                            "Tool '{}' references external tool '{}' (owned by {}) alongside override directives",
                            cur_tool,
                            other_tool,
                            owners.join("/")
                        ),
                        diff: None,
                    });
                }
            }
        }
    }

    Ok(())
}

fn run_lethal_trifecta_check(probed: &[ProbedServer], findings: &mut Vec<Finding>) {
    let mut buckets = TrifectaBuckets::default();

    for ps in probed {
        for tool in &ps.tools {
            let name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let desc = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let text = format!("{} {}", name, desc);

            if has_any(
                &text,
                &[
                    "read_file",
                    "filesystem",
                    "directory",
                    "sql",
                    "postgres",
                    "sqlite",
                    "database",
                    "query",
                    "env",
                    "secret",
                    "keychain",
                    "credential",
                    "local file",
                    "ssh",
                    "private",
                ],
            ) {
                buckets.private_data.insert(ps.spec.name.clone());
            }

            if has_any(
                &text,
                &[
                    "fetch",
                    "scrape",
                    "browse",
                    "browser",
                    "search_web",
                    "web_search",
                    "url",
                    "github",
                    "issue",
                    "pull_request",
                    "email",
                    "inbox",
                    "slack",
                    "discord",
                    "rss",
                    "webpage",
                ],
            ) {
                buckets.untrusted_input.insert(ps.spec.name.clone());
            }

            if has_any(
                &text,
                &[
                    "send_email",
                    "send_message",
                    "post_",
                    "webhook",
                    "upload",
                    "curl",
                    "http_post",
                    "bash",
                    "shell",
                    "exec",
                    "run_command",
                    "terminal",
                    "git_push",
                    "create_comment",
                ],
            ) {
                buckets.external_comms.insert(ps.spec.name.clone());
            }
        }
    }

    if !buckets.private_data.is_empty()
        && !buckets.untrusted_input.is_empty()
        && !buckets.external_comms.is_empty()
    {
        let p: Vec<_> = buckets.private_data.into_iter().collect();
        let u: Vec<_> = buckets.untrusted_input.into_iter().collect();
        let e: Vec<_> = buckets.external_comms.into_iter().collect();

        findings.push(Finding {
            severity: Severity::Critical,
            category: "LETHAL_TRIFECTA".into(),
            server: "fleet".into(),
            tool: None,
            message: format!(
                "Cross-server exfiltration chain active: Private Data [{}] + Untrusted Input [{}] + External Comms [{}]",
                p.join(", "),
                u.join(", "),
                e.join(", ")
            ),
            diff: None,
        });
    }
}

fn compute_grade(findings: &[Finding]) -> (i32, char) {
    let mut score = 100i32;
    for f in findings {
        score -= match f.severity {
            Severity::Critical => 35,
            Severity::High => 15,
            Severity::Medium => 7,
            Severity::Low => 3,
        };
    }
    let score = score.clamp(0, 100);
    let grade = match score {
        90..=100 => 'A',
        75..=89 => 'B',
        60..=74 => 'C',
        40..=59 => 'D',
        _ => 'F',
    };
    (score, grade)
}

fn print_scorecard(report: &ScanReport) {
    let grade_color = match report.grade {
        'A' => "\x1b[1;32m",
        'B' => "\x1b[1;36m",
        'C' => "\x1b[1;33m",
        _ => "\x1b[1;31m",
    };

    let crit = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let med = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();

    println!("\n======================================================================");
    println!(
        "  agent-shield MCP Security Audit  |  Grade: {}{} ({}/100)\x1b[0m",
        grade_color, report.grade, report.score
    );
    println!(
        "  Servers: {}  |  Tools: {}  |  Critical: {}  High: {}  Medium: {}",
        report.servers_scanned, report.tools_inspected, crit, high, med
    );
    println!("======================================================================");

    if report.findings.is_empty() {
        println!(
            "  \x1b[32mPASS\x1b[0m No poisoning, shadowing, rug-pull, or trifecta risks detected."
        );
        return;
    }

    for (idx, f) in report.findings.iter().enumerate() {
        let prefix = if idx + 1 == report.findings.len() {
            "└──"
        } else {
            "├──"
        };
        let sev_badge = match f.severity {
            Severity::Critical => "\x1b[1;31m[CRITICAL]\x1b[0m",
            Severity::High => "\x1b[1;33m[HIGH]    \x1b[0m",
            Severity::Medium => "\x1b[36m[MEDIUM]  \x1b[0m",
            Severity::Low => "\x1b[90m[LOW]     \x1b[0m",
        };
        let target = match &f.tool {
            Some(t) => format!("{}::{}", f.server, t),
            None => f.server.clone(),
        };
        println!(
            "{} {} ({}) {}: {}",
            prefix, sev_badge, f.category, target, f.message
        );
        if let Some(diff) = &f.diff {
            print!("{}", diff);
        }
    }
    println!();
}

/// Spawns a stdio MCP server briefly, runs `initialize` + `tools/list`, and exits cleanly.
async fn probe_server_tools(spec: &ServerSpec) -> Result<Vec<Value>> {
    let mut cmd = Command::new(&spec.command);
    cmd.args(&spec.args)
        .envs(&spec.env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn '{}'", spec.command))?;

    let mut stdin = child.stdin.take().context("missing stdin")?;
    let stdout = child.stdout.take().context("missing stdout")?;
    let mut reader = BufReader::new(stdout).lines();

    let probe_fut = async {
        // 1. initialize
        let init_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "agent-shield-scan", "version": "0.2.0" }
            }
        });
        stdin
            .write_all(format!("{}\n", init_req).as_bytes())
            .await?;
        stdin.flush().await?;
        let _ = read_jsonrpc_by_id(&mut reader, 1).await?;

        // 2. notifications/initialized
        let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        stdin.write_all(format!("{}\n", notif).as_bytes()).await?;
        stdin.flush().await?;

        // 3. tools/list
        let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
        stdin
            .write_all(format!("{}\n", list_req).as_bytes())
            .await?;
        stdin.flush().await?;

        let resp = read_jsonrpc_by_id(&mut reader, 2).await?;
        let tools = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        Ok::<Vec<Value>, anyhow::Error>(tools)
    };

    let result = timeout(Duration::from_secs(8), probe_fut)
        .await
        .context("timed out after 8s")?;

    let _ = child.kill().await;
    result
}

async fn read_jsonrpc_by_id(
    lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    expected_id: u64,
) -> Result<Value> {
    while let Some(line) = lines.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
            continue; // Ignore stray startup logs
        };
        if val.get("id").and_then(|i| i.as_u64()) == Some(expected_id) {
            return Ok(val);
        }
    }
    bail!("server closed stdout before replying to id={}", expected_id)
}

fn resolve_mcp_config(client: ClientTarget, file_override: Option<PathBuf>) -> Result<PathBuf> {
    let path = match file_override {
        Some(p) => p,
        None => detect_config_path(client)?,
    };
    if !path.exists() {
        bail!(
            "MCP config not found at {}. Pass --file <path>.",
            path.display()
        );
    }
    Ok(path)
}

fn load_server_specs(path: &Path) -> Result<Vec<ServerSpec>> {
    let raw = fs::read_to_string(path)?;
    let root: Value = serde_json::from_str(&raw)?;
    let Some(servers) = root.get("mcpServers").and_then(|v| v.as_object()) else {
        return Ok(Vec::new());
    };

    let mut specs = Vec::new();
    for (name, val) in servers {
        let Some(obj) = val.as_object() else { continue };
        let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) else {
            continue;
        };
        let args: Vec<String> = obj
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // Unwrap in-memory if already wrapped by agent-shield
        let (final_cmd, final_args) = unwrap_command_in_memory(cmd, &args);

        let mut env = BTreeMap::new();
        if let Some(env_obj) = obj.get("env").and_then(|v| v.as_object()) {
            for (k, v) in env_obj {
                if let Some(s) = v.as_str() {
                    env.insert(k.clone(), s.to_string());
                }
            }
        }

        specs.push(ServerSpec {
            name: name.clone(),
            command: final_cmd,
            args: final_args,
            env,
        });
    }

    Ok(specs)
}

fn unwrap_command_in_memory(cmd: &str, args: &[String]) -> (String, Vec<String>) {
    let is_shield = Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("agent-shield"))
        .unwrap_or(false);

    if is_shield {
        if let Some(pos) = args.iter().position(|a| a == "--") {
            if let Some(orig_cmd) = args.get(pos + 1) {
                return (orig_cmd.clone(), args[pos + 2..].to_vec());
            }
        }
    }
    (cmd.to_string(), args.to_vec())
}

fn collect_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => arr.iter().for_each(|i| collect_strings(i, out)),
        Value::Object(map) => map.values().for_each(|val| collect_strings(val, out)),
        _ => {}
    }
}

fn count_hidden_unicode(s: &str) -> usize {
    s.chars()
        .filter(|&c| {
            matches!(
                c as u32,
                0x200B..=0x200D | 0x2060 | 0xFEFF | 0x202A..=0x202E | 0x2066..=0x2069 | 0xE0000..=0xE007F
            )
        })
        .count()
}

fn has_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}
