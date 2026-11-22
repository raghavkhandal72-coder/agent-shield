use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use similar::{ChangeTag, TextDiff};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldLock {
    pub version: u32,
    pub generated_at: String,
    pub servers: BTreeMap<String, LockedServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedServer {
    pub command: String,
    pub tools: BTreeMap<String, LockedTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedTool {
    pub sha256: String,
    pub canonical_schema: String,
}

#[derive(Debug, Clone)]
pub enum LockDrift {
    UnpinnedServer {
        server: String,
    },
    ToolAdded {
        server: String,
        tool: String,
        actual_hash: String,
    },
    ToolRemoved {
        server: String,
        tool: String,
    },
    SchemaMutated {
        server: String,
        tool: String,
        expected_hash: String,
        actual_hash: String,
        diff: String,
    },
}

impl ShieldLock {
    pub fn empty() -> Self {
        Self {
            version: 1,
            generated_at: Utc::now().to_rfc3339(),
            servers: BTreeMap::new(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read lockfile: {}", path.display()))?;
        let lock: ShieldLock = serde_json::from_str(&raw)
            .with_context(|| format!("Corrupt lockfile JSON at {}", path.display()))?;
        Ok(lock)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{}\n", json))
            .with_context(|| format!("Failed to write lockfile: {}", path.display()))?;
        Ok(())
    }

    pub fn pin_server(&mut self, server_name: &str, command: &str, tools: &[Value]) {
        let mut locked_tools = BTreeMap::new();
        for tool in tools {
            let Some(name) = tool.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let (sha256, canonical_schema) = hash_tool_schema(tool);
            locked_tools.insert(
                name.to_string(),
                LockedTool {
                    sha256,
                    canonical_schema,
                },
            );
        }

        self.generated_at = Utc::now().to_rfc3339();
        self.servers.insert(
            server_name.to_string(),
            LockedServer {
                command: command.to_string(),
                tools: locked_tools,
            },
        );
    }

    /// Verifies live `tools/list` output against pinned hashes and returns exact rug-pull diffs.
    pub fn verify_server(&self, server_name: &str, live_tools: &[Value]) -> Vec<LockDrift> {
        let Some(pinned) = self.servers.get(server_name) else {
            return vec![LockDrift::UnpinnedServer {
                server: server_name.to_string(),
            }];
        };

        let mut drifts = Vec::new();
        let mut seen = BTreeMap::new();

        for tool in live_tools {
            let Some(name) = tool.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            let (actual_hash, actual_schema) = hash_tool_schema(tool);
            seen.insert(name.to_string(), true);

            match pinned.tools.get(name) {
                None => drifts.push(LockDrift::ToolAdded {
                    server: server_name.to_string(),
                    tool: name.to_string(),
                    actual_hash,
                }),
                Some(locked) if locked.sha256 != actual_hash => {
                    let diff = render_ansi_diff(&locked.canonical_schema, &actual_schema);
                    drifts.push(LockDrift::SchemaMutated {
                        server: server_name.to_string(),
                        tool: name.to_string(),
                        expected_hash: locked.sha256.clone(),
                        actual_hash,
                        diff,
                    });
                }
                Some(_) => {}
            }
        }

        for locked_name in pinned.tools.keys() {
            if !seen.contains_key(locked_name) {
                drifts.push(LockDrift::ToolRemoved {
                    server: server_name.to_string(),
                    tool: locked_name.clone(),
                });
            }
        }

        drifts
    }
}

/// Canonicalizes a tool JSON object (recursive sorted keys) and computes SHA-256.
pub fn hash_tool_schema(tool: &Value) -> (String, String) {
    let canonical = canonicalize_value(tool);
    let pretty = serde_json::to_string_pretty(&canonical).unwrap_or_default();
    let digest = Sha256::digest(pretty.as_bytes());
    (hex::encode(digest), pretty)
}

fn canonicalize_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut sorted = Map::new();
            for (k, val) in entries {
                sorted.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

/// Renders a concise red/green terminal diff showing only changed hunks with 2 lines of context.
pub fn render_ansi_diff(old: &str, new: &str) -> String {
    let diff = TextDiff::from_lines(old, new);
    let mut out = String::new();

    for group in diff.grouped_ops(2) {
        for op in group {
            for change in diff.iter_changes(&op) {
                match change.tag() {
                    ChangeTag::Delete => {
                        out.push_str(&format!("    \x1b[31m- {}\x1b[0m", change));
                    }
                    ChangeTag::Insert => {
                        out.push_str(&format!("    \x1b[32m+ {}\x1b[0m", change));
                    }
                    ChangeTag::Equal => {
                        out.push_str(&format!("    \x1b[90m  {}\x1b[0m", change));
                    }
                }
                if change.missing_newline() {
                    out.push('\n');
                }
            }
        }
    }

    out
}
