use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::ValueEnum;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

use crate::policy::{home_dir, Mode};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ClientTarget {
    Claude,
    Cursor,
}

impl std::fmt::Display for ClientTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientTarget::Claude => write!(f, "claude"),
            ClientTarget::Cursor => write!(f, "cursor"),
        }
    }
}

impl Default for ClientTarget {
    fn default() -> Self {
        ClientTarget::Claude
    }
}

pub struct AutoWrapOptions {
    pub client: ClientTarget,
    pub file_override: Option<PathBuf>,
    pub mode: Mode,
    pub config: Option<PathBuf>,
    pub workspace: Option<PathBuf>,
    pub shield_bin: Option<String>,
    pub dry_run: bool,
    pub unwrap: bool,
}

pub fn run_auto_wrap(opts: AutoWrapOptions) -> Result<()> {
    let config_path = match opts.file_override {
        Some(p) => p,
        None => detect_config_path(opts.client)?,
    };

    if !config_path.exists() {
        bail!(
            "MCP config not found at {}. Pass --file <path> to specify manually.",
            config_path.display()
        );
    }

    let raw = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))?;
    let mut root: Value = serde_json::from_str(&raw)
        .with_context(|| format!("Invalid JSON in {}", config_path.display()))?;

    let servers = root
        .get_mut("mcpServers")
        .and_then(|v| v.as_object_mut())
        .context("No `mcpServers` object found in config")?;

    let shield_bin = opts.shield_bin.unwrap_or_else(default_shield_bin);
    let mut changed = 0usize;
    let mut skipped = 0usize;

    for (name, entry) in servers.iter_mut() {
        let Some(obj) = entry.as_object_mut() else {
            skipped += 1;
            continue;
        };

        if opts.unwrap {
            if unwrap_entry(obj) {
                println!("[UNWRAPPED] {}", name);
                changed += 1;
            } else {
                println!("[SKIP] {} (not wrapped by agent-shield)", name);
                skipped += 1;
            }
        } else {
            match wrap_entry(obj, &shield_bin, &opts.mode, opts.config.as_deref(), opts.workspace.as_deref()) {
                WrapResult::Wrapped => {
                    println!("[WRAPPED] {}", name);
                    changed += 1;
                }
                WrapResult::AlreadyWrapped => {
                    println!("[SKIP] {} (already protected)", name);
                    skipped += 1;
                }
                WrapResult::NotStdio => {
                    println!("[SKIP] {} (no stdio `command` field — likely HTTP/SSE)", name);
                    skipped += 1;
                }
            }
        }
    }

    if changed == 0 {
        println!("No changes needed ({} skipped).", skipped);
        return Ok(());
    }

    let updated_json = serde_json::to_string_pretty(&root)?;

    if opts.dry_run {
        println!("\n--- DRY RUN (no files modified) ---\n{}", updated_json);
        return Ok(());
    }

    // Create timestamped backup before overwriting
    let backup_path = create_backup(&config_path)?;
    fs::write(&config_path, format!("{}\n", updated_json))
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    println!("\nUpdated: {}", config_path.display());
    println!("Backup : {}", backup_path.display());
    println!(
        "Done ({} updated, {} skipped). Restart your MCP client to apply.",
        changed, skipped
    );

    Ok(())
}

enum WrapResult {
    Wrapped,
    AlreadyWrapped,
    NotStdio,
}

fn wrap_entry(
    obj: &mut Map<String, Value>,
    shield_bin: &str,
    mode: &Mode,
    policy_config: Option<&Path>,
    workspace: Option<&Path>,
) -> WrapResult {
    let Some(orig_cmd) = obj.get("command").and_then(|v| v.as_str()).map(str::to_string) else {
        return WrapResult::NotStdio;
    };

    if is_shield_binary(&orig_cmd) {
        return WrapResult::AlreadyWrapped;
    }

    let orig_args: Vec<String> = obj
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    let mode_str = match mode {
        Mode::Enforce => "enforce",
        Mode::Audit => "audit",
    };

    let mut new_args: Vec<Value> = vec![
        Value::String("wrap".into()),
        Value::String("--mode".into()),
        Value::String(mode_str.into()),
    ];

    if let Some(cfg) = policy_config {
        new_args.push(Value::String("--config".into()));
        new_args.push(Value::String(cfg.to_string_lossy().into_owned()));
    }

    if let Some(ws) = workspace {
        new_args.push(Value::String("--workspace".into()));
        new_args.push(Value::String(ws.to_string_lossy().into_owned()));
    }

    new_args.push(Value::String("--".into()));
    new_args.push(Value::String(orig_cmd));
    for arg in orig_args {
        new_args.push(Value::String(arg));
    }

    obj.insert("command".into(), Value::String(shield_bin.to_string()));
    obj.insert("args".into(), Value::Array(new_args));

    WrapResult::Wrapped
}

fn unwrap_entry(obj: &mut Map<String, Value>) -> bool {
    let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) else {
        return false;
    };
    if !is_shield_binary(cmd) {
        return false;
    }

    let Some(args) = obj.get("args").and_then(|v| v.as_array()) else {
        return false;
    };

    let Some(sep_idx) = args.iter().position(|v| v.as_str() == Some("--")) else {
        return false;
    };

    let rest = &args[sep_idx + 1..];
    let Some(orig_cmd) = rest.first().and_then(|v| v.as_str()).map(str::to_string) else {
        return false;
    };
    let orig_args: Vec<Value> = rest[1..].to_vec();

    obj.insert("command".into(), Value::String(orig_cmd));
    if orig_args.is_empty() {
        obj.remove("args");
    } else {
        obj.insert("args".into(), Value::Array(orig_args));
    }

    true
}

fn is_shield_binary(cmd: &str) -> bool {
    Path::new(cmd)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|stem| stem.eq_ignore_ascii_case("agent-shield"))
        .unwrap_or(false)
}

fn default_shield_bin() -> String {
    // Absolute path avoids GUI apps failing to locate agent-shield in PATH
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "agent-shield".to_string())
}

fn detect_config_path(client: ClientTarget) -> Result<PathBuf> {
    let home = home_dir().context("Could not determine home directory")?;

    match client {
        ClientTarget::Cursor => Ok(home.join(".cursor").join("mcp.json")),
        ClientTarget::Claude => {
            if cfg!(target_os = "windows") {
                let appdata = std::env::var_os("APPDATA")
                    .map(PathBuf::from)
                    .context("APPDATA environment variable not set")?;
                Ok(appdata.join("Claude").join("claude_desktop_config.json"))
            } else if cfg!(target_os = "macos") {
                Ok(home
                    .join("Library")
                    .join("Application Support")
                    .join("Claude")
                    .join("claude_desktop_config.json"))
            } else {
                Ok(home
                    .join(".config")
                    .join("Claude")
                    .join("claude_desktop_config.json"))
            }
        }
    }
}

fn create_backup(path: &Path) -> Result<PathBuf> {
    let stamp = Utc::now().format("%Y%m%d-%H%M%S");
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mcp_config.json");
    let backup = path.with_file_name(format!("{}.bak.{}", file_name, stamp));
    fs::copy(path, &backup)
        .with_context(|| format!("Failed to create backup at {}", backup.display()))?;
    Ok(backup)
}
