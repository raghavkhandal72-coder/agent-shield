mod autowrap;
mod fuzz;
mod lockfile;
mod policy;
mod proxy;
mod rules;
mod sandbox;
mod scan;
mod scanner;
mod taint;
mod ui;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use lockfile::ShieldLock;
use policy::{Decision, Mode, PolicyEngine, ShieldConfig};
use proxy::ProxyContext;
use rules::{RuleDecision, RuleEngine};
use sandbox::SandboxConfig;
use scanner::ResponseScanner;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use taint::{TaintConfig, TaintEngine};

#[derive(Parser)]
#[command(
    name = "agent-shield",
    version,
    about = "Local Rust security firewall, OS sandbox, rug-pull lockfile & TUI for MCP servers"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wrap any stdio MCP server behind agent-shield
    Wrap {
        /// Logical server name shown in TUI & matched against shield.lock
        #[arg(long, default_value = "mcp", alias = "server-name")]
        name: String,

        /// Path to shield.toml policy file (uses secure defaults if omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Override enforcement mode (enforce | audit)
        #[arg(short, long, value_enum)]
        mode: Option<Mode>,

        /// Restrict filesystem access strictly inside this workspace directory
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Directory of community YAML rule packs (e.g. ./rules)
        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// Optional shield.lock path to block mid-session tool schema rug-pulls
        #[arg(long)]
        lockfile: Option<PathBuf>,

        /// Enforce OS-native sandbox (Linux Landlock / macOS Seatbelt / Windows Job Object)
        #[arg(long)]
        sandbox: bool,

        /// Fail closed if host OS kernel cannot enforce sandboxing
        #[arg(long)]
        sandbox_strict: bool,

        /// Hard-block outbound comms whenever Private Data + Untrusted Input are both active
        #[arg(long)]
        strict_trifecta: bool,

        /// Target MCP server command and arguments after `--`
        #[arg(last = true, required = true)]
        target: Vec<String>,
    },

    /// Generate a starter shield.toml policy file
    Init {
        #[arg(short, long, default_value = "shield.toml")]
        out: PathBuf,
    },

    /// Dry-run a tool call JSON against policy + optional YAML rule packs
    Check {
        #[arg(short, long)]
        config: Option<PathBuf>,

        #[arg(short, long)]
        workspace: Option<PathBuf>,

        #[arg(long)]
        rules_dir: Option<PathBuf>,

        /// MCP tool name (e.g. read_file, run_sql_query)
        #[arg(long)]
        tool: String,

        /// JSON object of tool arguments
        #[arg(long)]
        args: String,
    },

    /// Show recent firewall events from ~/.agent-shield/audit.jsonl
    Logs {
        #[arg(short = 'n', long, default_value_t = 25)]
        lines: usize,
    },

    /// Auto-wrap (or unwrap) MCP servers in Claude Desktop or Cursor config
    AutoWrap {
        #[arg(long, value_enum, default_value_t = autowrap::ClientTarget::Claude)]
        client: autowrap::ClientTarget,

        #[arg(short, long)]
        file: Option<PathBuf>,

        #[arg(short, long, value_enum, default_value_t = Mode::Enforce)]
        mode: Mode,

        #[arg(short, long)]
        config: Option<PathBuf>,

        #[arg(short, long)]
        workspace: Option<PathBuf>,

        #[arg(long)]
        bin: Option<String>,

        #[arg(long)]
        dry_run: bool,

        #[arg(long)]
        unwrap: bool,
    },

    /// Audit configured MCP servers for tool poisoning, shadowing, rug-pulls & Lethal Trifecta
    Scan {
        #[arg(long, value_enum, default_value_t = autowrap::ClientTarget::Claude)]
        client: autowrap::ClientTarget,

        #[arg(short, long)]
        file: Option<PathBuf>,

        #[arg(long, default_value = "shield.lock")]
        lockfile: PathBuf,

        #[arg(long)]
        json: bool,
    },

    /// Cryptographically pin all MCP tool schemas (SHA-256) into shield.lock
    Lock {
        #[arg(long, value_enum, default_value_t = autowrap::ClientTarget::Claude)]
        client: autowrap::ClientTarget,

        #[arg(short, long)]
        file: Option<PathBuf>,

        #[arg(short, long, default_value = "shield.lock")]
        out: PathBuf,
    },

    /// Run YAML rule pack self-tests and/or safe MCP server schema & boundary QA
    Fuzz {
        /// Directory containing community *.yaml rule packs
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Workspace directory for target server boundary checks
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Optional target MCP server command after `--`
        #[arg(last = true)]
        target: Vec<String>,
    },

    /// Launch interactive Burp-style live TUI dashboard (traffic, taint radar & token burn)
    Ui {
        #[arg(short, long)]
        audit_file: Option<PathBuf>,
    },
}

pub fn write_rich_audit_event(
    server: &str,
    tool: &str,
    direction: &str,
    action: &str,
    detail: &str,
    payload: &str,
) {
    let Some(home) = policy::home_dir() else {
        return;
    };
    let dir = home.join(".agent-shield");
    let _ = fs::create_dir_all(&dir);
    let log_path = dir.join("audit.jsonl");

    let tokens_est = (payload.len() / 4).max(1);
    let preview: String = payload.chars().take(4096).collect();

    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "server": server,
        "tool": tool,
        "direction": direction,
        "action": action,
        "detail": detail,
        "tokens_est": tokens_est,
        "payload": preview,
    });

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "{}", entry);
    }
}

pub fn write_audit_event(direction: &str, action: &str, detail: &str) {
    write_rich_audit_event("system", "-", direction, action, detail, "");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Wrap {
            name,
            config,
            mode,
            workspace,
            rules_dir,
            lockfile,
            sandbox: use_sandbox,
            sandbox_strict,
            strict_trifecta,
            target,
        } => {
            if target.is_empty() {
                bail!("No MCP server command provided after `--`");
            }

            let cfg = ShieldConfig::load(config.as_deref())?;
            let policy_engine = PolicyEngine::new(&cfg, mode, workspace.clone())?;
            let response_scanner = ResponseScanner::new(cfg.scanner)?;

            let rule_engine = match rules_dir.as_deref() {
                Some(dir) => {
                    let loaded = RuleEngine::load_dir(dir)?;
                    eprintln!(
                        "[agent-shield] loaded {} YAML rule pack(s) from {}",
                        loaded.len(),
                        dir.display()
                    );
                    loaded
                }
                None => {
                    let default_rules = PathBuf::from("rules");
                    if default_rules.is_dir() {
                        RuleEngine::load_dir(&default_rules).unwrap_or_else(|_| RuleEngine::empty())
                    } else {
                        RuleEngine::empty()
                    }
                }
            };

            let loaded_lock = match lockfile.as_deref() {
                Some(p) => {
                    let lock = ShieldLock::load(p)?;
                    eprintln!("[agent-shield] rug-pull lockfile active: {}", p.display());
                    Some(lock)
                }
                None => None,
            };

            let sandbox_cfg = if use_sandbox {
                let ws = match workspace {
                    Some(w) => w,
                    None => std::env::current_dir()
                        .context("could not resolve current directory for sandbox")?,
                };
                let mut sb = SandboxConfig::new(ws);
                sb.strict = sandbox_strict;
                Some(sb)
            } else {
                None
            };

            let taint_cfg = TaintConfig {
                enabled: true,
                strict_trifecta,
                ..TaintConfig::default()
            };
            let taint_engine = TaintEngine::new(taint_cfg)?;

            let ctx = ProxyContext {
                server_name: name,
                policy: policy_engine,
                rules: rule_engine,
                scanner: response_scanner,
                taint: taint_engine,
                lockfile: loaded_lock,
                sandbox: sandbox_cfg,
            };

            eprintln!(
                "[agent-shield] protecting '{}': {} {:?}",
                ctx.server_name,
                target[0],
                &target[1..]
            );
            proxy::run_proxy(&target[0], &target[1..], ctx).await?;
        }

        Commands::Init { out } => {
            if out.exists() {
                bail!("{} already exists; refusing to overwrite", out.display());
            }
            fs::write(&out, DEFAULT_TOML)
                .with_context(|| format!("Failed to write {}", out.display()))?;
            println!("Created starter policy at {}", out.display());
        }

        Commands::Check {
            config,
            workspace,
            rules_dir,
            tool,
            args,
        } => {
            let cfg = ShieldConfig::load(config.as_deref())?;
            let engine = PolicyEngine::new(&cfg, Some(Mode::Enforce), workspace)?;
            let rule_engine = match rules_dir.as_deref() {
                Some(dir) => RuleEngine::load_dir(dir)?,
                None => {
                    let default_rules = PathBuf::from("rules");
                    if default_rules.is_dir() {
                        RuleEngine::load_dir(&default_rules).unwrap_or_else(|_| RuleEngine::empty())
                    } else {
                        RuleEngine::empty()
                    }
                }
            };

            let parsed_args: serde_json::Value =
                serde_json::from_str(&args).context("--args must be valid JSON")?;

            let mock_frame = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": tool, "arguments": parsed_args }
            });

            match engine.evaluate_tool_call(&mock_frame) {
                Decision::Block(r) => {
                    println!("BLOCKED (policy): {}", r);
                    std::process::exit(2);
                }
                Decision::AuditAlert(r) => println!("AUDIT_ALERT (policy): {}", r),
                Decision::Allow => {}
            }

            match rule_engine.evaluate(&tool, &parsed_args) {
                RuleDecision::Block {
                    rule_id, rule_name, ..
                } => {
                    println!("BLOCKED (rule {}): {}", rule_id, rule_name);
                    std::process::exit(2);
                }
                RuleDecision::Warn {
                    rule_id, rule_name, ..
                } => {
                    println!("WARN (rule {}): {}", rule_id, rule_name);
                }
                RuleDecision::Allow => println!("ALLOW"),
            }
        }

        Commands::Logs { lines } => {
            let log_path = policy::home_dir()
                .context("Could not determine home directory")?
                .join(".agent-shield")
                .join("audit.jsonl");

            if !log_path.exists() {
                println!("No audit logs yet at {}", log_path.display());
                return Ok(());
            }

            let content = fs::read_to_string(&log_path)?;
            let all: Vec<&str> = content.lines().collect();
            let start = all.len().saturating_sub(lines);
            for line in &all[start..] {
                println!("{}", line);
            }
        }

        Commands::AutoWrap {
            client,
            file,
            mode,
            config,
            workspace,
            bin,
            dry_run,
            unwrap,
        } => {
            autowrap::run_auto_wrap(autowrap::AutoWrapOptions {
                client,
                file_override: file,
                mode,
                config,
                workspace,
                shield_bin: bin,
                dry_run,
                unwrap,
            })?;
        }

        Commands::Scan {
            client,
            file,
            lockfile,
            json,
        } => {
            scan::run_scan_command(client, file, lockfile, json).await?;
        }

        Commands::Lock { client, file, out } => {
            scan::run_lock_command(client, file, out).await?;
        }

        Commands::Fuzz {
            rules,
            workspace,
            target,
        } => {
            fuzz::run_fuzz(rules, workspace, target).await?;
        }

        Commands::Ui { audit_file } => {
            ui::run_tui(audit_file)?;
        }
    }

    Ok(())
}

const DEFAULT_TOML: &str = r#"[global]
mode = "enforce" # "enforce" or "audit"
allowed_roots = [] # Optional: e.g. ["C:/projects/my-app"] or ["/workspace"]

[deny]
tools = []
paths = [
  "**/.env*",
  "**/.ssh/**",
  "**/.aws/**",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/*credentials*"
]
commands = [
  "(?i)\\brm\\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\\b",
  "(?i)curl\\s+.*\\|\\s*(ba)?sh",
  "(?i)powershell.*-(enc|encodedcommand)\\b"
]

[scanner]
block_prompt_injection = true
redact_secrets_in_response = true
strip_invisible_unicode = true
"#;
