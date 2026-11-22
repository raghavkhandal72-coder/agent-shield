mod autowrap;
mod policy;
mod proxy;
mod scanner;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};
use policy::{Decision, Mode, PolicyEngine, ShieldConfig};
use scanner::ResponseScanner;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "agent-shield",
    version,
    about = "Zero-latency local security firewall for MCP servers & AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wrap any stdio MCP server behind agent-shield
    Wrap {
        /// Path to shield.toml policy file (uses secure defaults if omitted)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Override enforcement mode (enforce | audit)
        #[arg(short, long, value_enum)]
        mode: Option<Mode>,

        /// Restrict filesystem access strictly inside this workspace directory
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Target MCP server command and arguments after `--`
        #[arg(last = true, required = true)]
        target: Vec<String>,
    },

    /// Generate a starter shield.toml policy file
    Init {
        #[arg(short, long, default_value = "shield.toml")]
        out: PathBuf,
    },

    /// Dry-run a tool call JSON against your current policy
    Check {
        #[arg(short, long)]
        config: Option<PathBuf>,

        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// MCP tool name (e.g. read_file, run_command)
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
        /// Target MCP client config to auto-detect
        #[arg(long, value_enum, default_value_t = autowrap::ClientTarget::Claude)]
        client: autowrap::ClientTarget,

        /// Custom path to mcp.json / claude_desktop_config.json
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Enforcement mode written into wrapped entries
        #[arg(short, long, value_enum, default_value_t = Mode::Enforce)]
        mode: Mode,

        /// Optional shield.toml path to pass to wrapped servers
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Optional workspace jail directory
        #[arg(short, long)]
        workspace: Option<PathBuf>,

        /// Override agent-shield binary path (defaults to current executable path)
        #[arg(long)]
        bin: Option<String>,

        /// Preview modified JSON without writing to disk
        #[arg(long)]
        dry_run: bool,

        /// Remove agent-shield wrapper and restore original server commands
        #[arg(long)]
        unwrap: bool,
    },
}

pub fn write_audit_event(direction: &str, action: &str, detail: &str) {
    let Some(home) = policy::home_dir() else { return };
    let dir = home.join(".agent-shield");
    let _ = fs::create_dir_all(&dir);
    let log_path = dir.join("audit.jsonl");

    let entry = json!({
        "ts": Utc::now().to_rfc3339(),
        "direction": direction,
        "action": action,
        "detail": detail,
    });

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "{}", entry);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Wrap {
            config,
            mode,
            workspace,
            target,
        } => {
            if target.is_empty() {
                bail!("No MCP server command provided after `--`");
            }
            let cfg = ShieldConfig::load(config.as_deref())?;
            let policy_engine = PolicyEngine::new(&cfg, mode, workspace)?;
            let response_scanner = ResponseScanner::new(cfg.scanner)?;

            let cmd = &target[0];
            let args = &target[1..];

            eprintln!("[agent-shield] protecting MCP server: {} {:?}", cmd, args);
            proxy::run_proxy(cmd, args, policy_engine, response_scanner).await?;
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
            tool,
            args,
        } => {
            let cfg = ShieldConfig::load(config.as_deref())?;
            let engine = PolicyEngine::new(&cfg, Some(Mode::Enforce), workspace)?;
            let parsed_args: serde_json::Value =
                serde_json::from_str(&args).context("--args must be valid JSON")?;

            let mock_frame = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": parsed_args
                }
            });

            match engine.evaluate_tool_call(&mock_frame) {
                Decision::Allow => println!("ALLOW"),
                Decision::AuditAlert(r) => println!("AUDIT_ALERT: {}", r),
                Decision::Block(r) => {
                    println!("BLOCKED: {}", r);
                    std::process::exit(2);
                }
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
