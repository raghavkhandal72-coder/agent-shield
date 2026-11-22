use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::rules::{RuleAction, RuleDecision, RuleEngine};

pub async fn run_fuzz(
    rules_dir: Option<PathBuf>,
    workspace: Option<PathBuf>,
    target: Vec<String>,
) -> Result<()> {
    if rules_dir.is_none() && target.is_empty() {
        bail!("Provide --rules <dir> and/or a target MCP server command after `--`");
    }

    let mut passed = 0usize;
    let mut failed = 0usize;

    println!("=========================================================================");
    println!("  agent-shield fuzz  |  Policy Self-Test & Local MCP Boundary QA");
    println!("=========================================================================");

    if let Some(dir) = rules_dir.as_deref() {
        let (p, f) = run_rule_pack_tests(dir)?;
        passed += p;
        failed += f;
    }

    if !target.is_empty() {
        let (p, f) = run_server_qa(&target, workspace.as_deref()).await?;
        passed += p;
        failed += f;
    }

    println!("-------------------------------------------------------------------------");
    if failed == 0 {
        println!("\x1b[32mResult: {} passed, 0 failed\x1b[0m", passed);
        Ok(())
    } else {
        println!(
            "\x1b[31mResult: {} passed, {} failed\x1b[0m",
            passed, failed
        );
        std::process::exit(2);
    }
}

/// Runs embedded `should_block` and `should_allow` assertions inside every YAML rule pack.
fn run_rule_pack_tests(dir: &Path) -> Result<(usize, usize)> {
    let files = RuleEngine::list_yaml_files(dir)?;
    if files.is_empty() {
        bail!("No .yaml/.yml rule packs found in {}", dir.display());
    }

    let mut passed = 0usize;
    let mut failed = 0usize;

    for path in files {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.yaml");

        let pack = match RuleEngine::load_pack_file(&path) {
            Ok(p) => p,
            Err(err) => {
                println!(
                    "\x1b[31m[FAIL]\x1b[0m Rule Pack: {} (parse error: {})",
                    file_name, err
                );
                failed += 1;
                continue;
            }
        };

        let expected_action = pack.action;
        let tests = pack.tests.clone();
        let total_cases = tests.should_block.len() + tests.should_allow.len();

        let engine = match RuleEngine::from_packs(vec![pack]) {
            Ok(e) => e,
            Err(err) => {
                println!(
                    "\x1b[31m[FAIL]\x1b[0m Rule Pack: {} (compile error: {})",
                    file_name, err
                );
                failed += 1;
                continue;
            }
        };

        let mut failures = Vec::new();

        for (i, tc) in tests.should_block.iter().enumerate() {
            let decision = engine.evaluate(&tc.tool, &tc.args);
            let ok = match expected_action {
                RuleAction::Block => matches!(decision, RuleDecision::Block { .. }),
                RuleAction::Warn => !matches!(decision, RuleDecision::Allow),
            };
            if !ok {
                failures.push(format!(
                    "should_block[{}] tool='{}' unexpectedly allowed",
                    i, tc.tool
                ));
            }
        }

        for (i, tc) in tests.should_allow.iter().enumerate() {
            let decision = engine.evaluate(&tc.tool, &tc.args);
            if !matches!(decision, RuleDecision::Allow) {
                failures.push(format!(
                    "should_allow[{}] tool='{}' false positive: {:?}",
                    i, tc.tool, decision
                ));
            }
        }

        if failures.is_empty() {
            println!(
                "\x1b[32m[PASS]\x1b[0m Rule Pack: {:<26} ({}/{} assertions)",
                file_name, total_cases, total_cases
            );
            passed += 1;
        } else {
            println!(
                "\x1b[31m[FAIL]\x1b[0m Rule Pack: {:<26} ({} failure(s))",
                file_name,
                failures.len()
            );
            for msg in failures {
                println!("       -> {}", msg);
            }
            failed += 1;
        }
    }

    Ok((passed, failed))
}

/// Spawns a local stdio MCP server and runs benign schema resilience + boundary canary checks.
async fn run_server_qa(target: &[String], workspace: Option<&Path>) -> Result<(usize, usize)> {
    let mut cmd = Command::new(&target[0]);
    cmd.args(&target[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    if let Some(ws) = workspace {
        cmd.current_dir(ws);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn target MCP server '{}'", target[0]))?;

    let mut stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let mut lines = BufReader::new(stdout).lines();

    let mut passed = 0usize;
    let mut failed = 0usize;

    let outcome: Result<()> = async {
        // 1. Handshake + tools/list
        let _ = rpc_call(
            &mut stdin,
            &mut lines,
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "agent-shield-fuzz", "version": "0.2.0" }
            }),
        )
        .await
        .context("initialize handshake failed")?;

        let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        stdin.write_all(format!("{}\n", notif).as_bytes()).await?;
        stdin.flush().await?;

        let list_resp = rpc_call(&mut stdin, &mut lines, 2, "tools/list", json!({}))
            .await
            .context("tools/list failed")?;
        let tools = list_resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();

        if tools.is_empty() {
            println!("\x1b[33m[WARN]\x1b[0m Target exposed 0 tools; skipping per-tool QA checks");
            return Ok(());
        }

        let sample_tool = tools[0]
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // 2. Malformed / null arguments resilience
        match rpc_call(
            &mut stdin,
            &mut lines,
            3,
            "tools/call",
            json!({ "name": sample_tool, "arguments": Value::Null }),
        )
        .await
        {
            Ok(_) => {
                println!(
                    "\x1b[32m[PASS]\x1b[0m Schema QA: '{}' handled null/malformed args without crashing",
                    sample_tool
                );
                passed += 1;
            }
            Err(e) => {
                println!(
                    "\x1b[31m[FAIL]\x1b[0m Schema QA: '{}' crashed or timed out on null args ({})",
                    sample_tool, e
                );
                failed += 1;
                return Ok(());
            }
        }

        // 3. Oversized payload (64KB benign ASCII) resilience
        let big_str = "A".repeat(65_536);
        match rpc_call(
            &mut stdin,
            &mut lines,
            4,
            "tools/call",
            json!({ "name": sample_tool, "arguments": { "input": big_str } }),
        )
        .await
        {
            Ok(_) => {
                println!(
                    "\x1b[32m[PASS]\x1b[0m Schema QA: '{}' survived 64KB payload gracefully",
                    sample_tool
                );
                passed += 1;
            }
            Err(e) => {
                println!(
                    "\x1b[31m[FAIL]\x1b[0m Schema QA: '{}' crashed or hung on 64KB payload ({})",
                    sample_tool, e
                );
                failed += 1;
                return Ok(());
            }
        }

        // 4. Non-destructive workspace boundary canary check (read-only file tools only)
        if let Some((read_tool, path_key)) = find_read_file_tool(&tools) {
            let canary = "../agent_shield_canary_nonexistent.txt";
            let mut args_map = serde_json::Map::new();
            args_map.insert(path_key.clone(), Value::String(canary.into()));

            match rpc_call(
                &mut stdin,
                &mut lines,
                5,
                "tools/call",
                json!({ "name": read_tool, "arguments": Value::Object(args_map) }),
            )
            .await
            {
                Ok(resp) => {
                    let rejected = resp.get("error").is_some()
                        || resp
                            .get("result")
                            .and_then(|r| r.get("isError"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                    if rejected {
                        println!(
                            "\x1b[32m[PASS]\x1b[0m Boundary : '{}' rejected out-of-workspace canary path",
                            read_tool
                        );
                        passed += 1;
                    } else {
                        println!(
                            "\x1b[31m[FAIL]\x1b[0m Boundary : '{}' accepted out-of-workspace canary path without error",
                            read_tool
                        );
                        failed += 1;
                    }
                }
                Err(e) => {
                    println!("\x1b[31m[FAIL]\x1b[0m Boundary : canary probe failed ({})", e);
                    failed += 1;
                }
            }
        }

        Ok(())
    }
    .await;

    let _ = child.kill().await;
    outcome?;
    Ok((passed, failed))
}

fn find_read_file_tool(tools: &[Value]) -> Option<(String, String)> {
    for tool in tools {
        let name = tool.get("name").and_then(|v| v.as_str())?;
        let lower = name.to_ascii_lowercase();
        if lower.contains("read_file") || lower.contains("get_file") {
            let key = tool
                .get("inputSchema")
                .and_then(|s| s.get("properties"))
                .and_then(|p| p.as_object())
                .and_then(|props| {
                    ["path", "file_path", "filepath", "file", "filename"]
                        .iter()
                        .find(|&&k| props.contains_key(k))
                        .map(|&k| k.to_string())
                })
                .unwrap_or_else(|| "path".to_string());
            return Some((name.to_string(), key));
        }
    }
    None
}

async fn rpc_call(
    stdin: &mut ChildStdin,
    lines: &mut Lines<BufReader<ChildStdout>>,
    id: u64,
    method: &str,
    params: Value,
) -> Result<Value> {
    let req = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params
    });
    stdin.write_all(format!("{}\n", req).as_bytes()).await?;
    stdin.flush().await?;

    timeout(Duration::from_secs(5), async {
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if val.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return Ok(val);
            }
        }
        bail!("server closed stdout before replying to id={}", id)
    })
    .await
    .context("timed out after 5s")?
}
