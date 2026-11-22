use anyhow::{bail, Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Warn,
}

impl Default for RuleAction {
    fn default() -> Self {
        Self::Block
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl Default for RuleSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub severity: RuleSeverity,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
    #[serde(default)]
    pub tests: RuleTests,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleMatch {
    /// Tool name globs (e.g. ["*sql*", "*postgres*"]). Empty = matches all tools.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Regex patterns checked against every string inside `params.arguments`.
    #[serde(default)]
    pub arg_regex: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RuleTests {
    #[serde(default)]
    pub should_block: Vec<RuleTestCase>,
    #[serde(default)]
    pub should_allow: Vec<RuleTestCase>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleTestCase {
    pub tool: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleDecision {
    Allow,
    Warn {
        rule_id: String,
        rule_name: String,
        severity: RuleSeverity,
    },
    Block {
        rule_id: String,
        rule_name: String,
        severity: RuleSeverity,
    },
}

struct CompiledRule {
    id: String,
    name: String,
    severity: RuleSeverity,
    action: RuleAction,
    tool_globs: Option<GlobSet>,
    arg_regexes: Vec<Regex>,
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn load_pack_file(path: &Path) -> Result<RulePack> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
        let pack: RulePack = serde_yaml::from_str(&raw)
            .with_context(|| format!("Invalid YAML in {}", path.display()))?;
        Ok(pack)
    }

    pub fn list_yaml_files(dir: &Path) -> Result<Vec<PathBuf>> {
        if !dir.exists() {
            bail!("Rules directory does not exist: {}", dir.display());
        }
        let mut files = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let is_yaml = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
                .unwrap_or(false);
            if path.is_file() && is_yaml {
                files.push(path);
            }
        }
        files.sort();
        Ok(files)
    }

    pub fn load_dir(dir: &Path) -> Result<Self> {
        let files = Self::list_yaml_files(dir)?;
        let mut packs = Vec::with_capacity(files.len());
        for path in files {
            packs.push(Self::load_pack_file(&path)?);
        }
        Self::from_packs(packs)
    }

    pub fn from_packs(packs: Vec<RulePack>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(packs.len());

        for pack in packs {
            let tool_globs = if pack.matcher.tools.is_empty() {
                None
            } else {
                let mut gb = GlobSetBuilder::new();
                for pat in &pack.matcher.tools {
                    let g = GlobBuilder::new(pat)
                        .case_insensitive(true)
                        .build()
                        .with_context(|| format!("Invalid tool glob '{}' in rule '{}'", pat, pack.id))?;
                    gb.add(g);
                }
                Some(gb.build()?)
            };

            let mut arg_regexes = Vec::with_capacity(pack.matcher.arg_regex.len());
            for pat in &pack.matcher.arg_regex {
                let re = Regex::new(pat)
                    .with_context(|| format!("Invalid regex '{}' in rule '{}'", pat, pack.id))?;
                arg_regexes.push(re);
            }

            compiled.push(CompiledRule {
                id: pack.id,
                name: pack.name,
                severity: pack.severity,
                action: pack.action,
                tool_globs,
                arg_regexes,
            });
        }

        Ok(Self { rules: compiled })
    }

    pub fn evaluate(&self, tool_name: &str, args: &Value) -> RuleDecision {
        if self.rules.is_empty() {
            return RuleDecision::Allow;
        }

        let mut arg_strings = Vec::new();
        collect_strings(args, &mut arg_strings);

        let mut pending_warn: Option<RuleDecision> = None;

        for rule in &self.rules {
            if let Some(globs) = &rule.tool_globs {
                if !globs.is_match(tool_name) {
                    continue;
                }
            }

            let matched = if rule.arg_regexes.is_empty() {
                // Rule with tool filter only (no regex) matches any call to that tool
                rule.tool_globs.is_some()
            } else {
                arg_strings
                    .iter()
                    .any(|s| rule.arg_regexes.iter().any(|re| re.is_match(s)))
            };

            if matched {
                match rule.action {
                    RuleAction::Block => {
                        return RuleDecision::Block {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                        };
                    }
                    RuleAction::Warn => {
                        if pending_warn.is_none() {
                            pending_warn = Some(RuleDecision::Warn {
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                severity: rule.severity,
                            });
                        }
                    }
                }
            }
        }

        pending_warn.unwrap_or(RuleDecision::Allow)
    }
}

fn collect_strings(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => arr.iter().for_each(|i| collect_strings(i, out)),
        Value::Object(map) => map.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}
