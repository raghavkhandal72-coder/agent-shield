use anyhow::{Context, Result};
use clap::ValueEnum;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Enforce,
    Audit,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Enforce => write!(f, "enforce"),
            Mode::Audit => write!(f, "audit"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ShieldConfig {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub deny: DenyConfig,
    #[serde(default)]
    pub scanner: crate::scanner::ScannerConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub allowed_roots: Vec<String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            allowed_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DenyConfig {
    #[serde(default = "default_deny_paths")]
    pub paths: Vec<String>,
    #[serde(default = "default_deny_commands")]
    pub commands: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

impl Default for DenyConfig {
    fn default() -> Self {
        Self {
            paths: default_deny_paths(),
            commands: default_deny_commands(),
            tools: Vec::new(),
        }
    }
}

fn default_deny_paths() -> Vec<String> {
    vec![
        "**/.env*".into(),
        "**/.ssh/**".into(),
        "**/.aws/**".into(),
        "**/.gnupg/**".into(),
        "**/id_rsa*".into(),
        "**/id_ed25519*".into(),
        "**/*credentials*".into(),
        "/etc/shadow".into(),
        "/etc/passwd".into(),
    ]
}

fn default_deny_commands() -> Vec<String> {
    vec![
        r"(?i)\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b".into(),
        r"(?i)curl\s+.*\|\s*(ba)?sh".into(),
        r"(?i)wget\s+.*\|\s*(ba)?sh".into(),
        r"(?i)powershell.*-(enc|encodedcommand)\b".into(),
        r"(?i)\b(nc|ncat)\s+.*-e\b".into(),
        r"(?i)chmod\s+777\b".into(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    AuditAlert(String),
    Block(String),
}

pub struct PolicyEngine {
    mode: Mode,
    base_dir: PathBuf,
    allowed_roots: Vec<PathBuf>,
    deny_paths: GlobSet,
    deny_commands: Vec<(String, Regex)>,
    deny_tools: Vec<String>,
}

impl ShieldConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => {
                let raw = fs::read_to_string(p)
                    .with_context(|| format!("Failed to read config: {}", p.display()))?;
                let cfg: ShieldConfig = toml::from_str(&raw)
                    .with_context(|| format!("Invalid TOML in {}", p.display()))?;
                Ok(cfg)
            }
            None => Ok(ShieldConfig::default()),
        }
    }
}

impl PolicyEngine {
    pub fn new(
        cfg: &ShieldConfig,
        mode_override: Option<Mode>,
        workspace_override: Option<PathBuf>,
    ) -> Result<Self> {
        let base_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        let mut glob_builder = GlobSetBuilder::new();
        for pat in &cfg.deny.paths {
            let normalized_pat = pat.replace('\\', "/");
            let glob = Glob::new(&normalized_pat)
                .with_context(|| format!("Invalid deny path glob: {}", pat))?;
            glob_builder.add(glob);
        }
        let deny_paths = glob_builder.build()?;

        let mut deny_commands = Vec::new();
        for pat in &cfg.deny.commands {
            let re =
                Regex::new(pat).with_context(|| format!("Invalid deny command regex: {}", pat))?;
            deny_commands.push((pat.clone(), re));
        }

        let mut allowed_roots = Vec::new();
        for root in &cfg.global.allowed_roots {
            allowed_roots.push(resolve_path(root, &base_dir));
        }
        if let Some(ws) = workspace_override {
            allowed_roots.push(resolve_path(&ws.to_string_lossy(), &base_dir));
        }

        Ok(Self {
            mode: mode_override.unwrap_or(cfg.global.mode),
            base_dir,
            allowed_roots,
            deny_paths,
            deny_commands,
            deny_tools: cfg.deny.tools.clone(),
        })
    }

    pub fn evaluate_tool_call(&self, msg: &Value) -> Decision {
        let Some(params) = msg.get("params") else {
            return Decision::Allow;
        };

        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        // 1. Explicitly denied tool names
        if self.deny_tools.iter().any(|t| t == tool_name) {
            return self.verdict(format!("tool '{}' is explicitly denied", tool_name));
        }

        // 2. Recursively inspect all arguments
        if let Some(args) = params.get("arguments") {
            if let Some(reason) = self.inspect_value(None, args) {
                return self.verdict(format!("tool '{}' -> {}", tool_name, reason));
            }
        }

        Decision::Allow
    }

    fn verdict(&self, reason: String) -> Decision {
        match self.mode {
            Mode::Enforce => Decision::Block(reason),
            Mode::Audit => Decision::AuditAlert(reason),
        }
    }

    fn inspect_value(&self, key: Option<&str>, val: &Value) -> Option<String> {
        match val {
            Value::String(s) => self.inspect_string(key, s),
            Value::Array(items) => {
                for item in items {
                    if let Some(reason) = self.inspect_value(key, item) {
                        return Some(reason);
                    }
                }
                None
            }
            Value::Object(map) => {
                for (k, v) in map {
                    if let Some(reason) = self.inspect_value(Some(k.as_str()), v) {
                        return Some(reason);
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn inspect_string(&self, key: Option<&str>, raw: &str) -> Option<String> {
        // A. Dangerous command check on every string value
        for (pat, re) in &self.deny_commands {
            if re.is_match(raw) {
                return Some(format!("matched denied command pattern '{}'", pat));
            }
        }

        // B. Path traversal + sensitive path check
        if is_path_key(key) || looks_like_path(raw) {
            let raw_slash = raw.replace('\\', "/");

            // Check raw form first (catches relative ".env" or "sub/.env.local")
            if self.deny_paths.is_match(&raw_slash)
                || self
                    .deny_paths
                    .is_match(format!("/{}", raw_slash.trim_start_matches('/')))
            {
                return Some(format!("blocked sensitive path '{}'", raw));
            }

            // Resolve symlinks, `~`, and `..` segments
            let resolved = resolve_path(raw, &self.base_dir);
            let resolved_slash = resolved.to_string_lossy().replace('\\', "/");

            if self.deny_paths.is_match(&resolved_slash) {
                return Some(format!(
                    "blocked sensitive path '{}' (resolved to '{}')",
                    raw, resolved_slash
                ));
            }

            // Workspace jail enforcement (if --workspace or allowed_roots is set)
            if !self.allowed_roots.is_empty() {
                let inside_allowed = self
                    .allowed_roots
                    .iter()
                    .any(|root| resolved.starts_with(root));
                if !inside_allowed {
                    return Some(format!(
                        "path traversal outside allowed workspace: '{}' -> '{}'",
                        raw, resolved_slash
                    ));
                }
            }
        }

        None
    }
}

fn is_path_key(key: Option<&str>) -> bool {
    let Some(k) = key else { return false };
    let k = k.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "path"
            | "file"
            | "filepath"
            | "file_path"
            | "filename"
            | "dir"
            | "directory"
            | "cwd"
            | "uri"
            | "target"
            | "source"
            | "src"
            | "dest"
            | "destination"
            | "folder"
    )
}

fn looks_like_path(s: &str) -> bool {
    s.contains('/')
        || s.contains('\\')
        || s.contains("..")
        || s.starts_with('~')
        || s.starts_with("file://")
        || s.starts_with(".env")
}

/// Resolves `~`, relative paths, `..` traversal, and symlinks even when the leaf file doesn't exist yet.
pub fn resolve_path(raw: &str, base_dir: &Path) -> PathBuf {
    let cleaned = raw.trim().trim_start_matches("file://");
    let expanded = expand_tilde(cleaned);
    let candidate = PathBuf::from(expanded);
    let abs = if candidate.is_absolute() {
        candidate
    } else {
        base_dir.join(candidate)
    };

    if let Ok(canon) = fs::canonicalize(&abs) {
        return strip_windows_verbatim(canon);
    }

    // Walk up to the nearest existing ancestor so symlinks in parent folders cannot bypass checks
    let mut tail = Vec::new();
    let mut cur = abs.as_path();
    while !cur.exists() {
        if let Some(name) = cur.file_name() {
            tail.push(name.to_os_string());
        } else {
            break;
        }
        match cur.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
            _ => break,
        }
    }

    let mut resolved = fs::canonicalize(cur)
        .map(strip_windows_verbatim)
        .unwrap_or_else(|_| cur.to_path_buf());

    for part in tail.into_iter().rev() {
        resolved.push(part);
    }

    normalize_lexical(&resolved)
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => match stack.last() {
                Some(Component::Normal(_)) => {
                    stack.pop();
                }
                Some(Component::RootDir) | Some(Component::Prefix(_)) => {}
                _ => stack.push(comp),
            },
            c => stack.push(c),
        }
    }
    stack.iter().collect()
}

fn strip_windows_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        p
    }
}

fn expand_tilde(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        if let Some(home) = home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    } else if s == "~" {
        if let Some(home) = home_dir() {
            return home.to_string_lossy().into_owned();
        }
    }
    s.to_string()
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}
