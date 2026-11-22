use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Block,
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub tool: String,
    pub args: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTests {
    #[serde(default)]
    pub should_block: Vec<TestCase>,
    #[serde(default)]
    pub should_allow: Vec<TestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchClause {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub arg_regex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleYaml {
    pub id: String,
    pub name: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default = "default_action")]
    pub action: RuleAction,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(rename = "match")]
    pub match_rule: MatchClause,
    #[serde(default)]
    pub tests: Option<RuleTests>,
}

fn default_severity() -> String {
    "medium".to_string()
}

fn default_action() -> RuleAction {
    RuleAction::Block
}

#[derive(Clone)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub action: RuleAction,
    #[allow(dead_code)]
    pub description: String,
    pub tool_matchers: Vec<GlobMatcher>,
    pub arg_regexes: Vec<Regex>,
    pub tests: Option<RuleTests>,
    pub source_file: String,
}

#[derive(Debug, Clone)]
pub enum RuleVerdict {
    Block {
        rule_id: String,
        name: String,
        severity: String,
        matched: String,
    },
    Warn {
        rule_id: String,
        name: String,
        severity: String,
        matched: String,
    },
}

#[derive(Clone, Default)]
pub struct RuleEngine {
    pub rules: Vec<CompiledRule>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_dir(dir: &Path) -> Result<Self> {
        let mut engine = Self::new();
        if !dir.exists() || !dir.is_dir() {
            return Ok(engine);
        }

        let entries = fs::read_dir(dir)
            .with_context(|| format!("Failed to read rules directory: {}", dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "yaml" || ext == "yml" {
                    let content = fs::read_to_string(&path)
                        .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
                    let rule_yaml: RuleYaml = serde_yaml::from_str(&content)
                        .with_context(|| format!("Failed to parse YAML rule: {}", path.display()))?;
                    let compiled = engine.compile_rule(
                        rule_yaml,
                        path.file_name().and_then(|s| s.to_str()).unwrap_or("rule.yaml"),
                    )?;
                    engine.rules.push(compiled);
                }
            }
        }

        Ok(engine)
    }

    fn compile_rule(&self, raw: RuleYaml, source_file: &str) -> Result<CompiledRule> {
        let mut tool_matchers = Vec::new();
        for pat in &raw.match_rule.tools {
            let glob = Glob::new(pat)
                .with_context(|| format!("Invalid tool glob '{}' in rule {}", pat, raw.id))?;
            tool_matchers.push(glob.compile_matcher());
        }

        let mut arg_regexes = Vec::new();
        for reg in &raw.match_rule.arg_regex {
            let re = Regex::new(reg)
                .with_context(|| format!("Invalid regex '{}' in rule {}", reg, raw.id))?;
            arg_regexes.push(re);
        }

        Ok(CompiledRule {
            id: raw.id,
            name: raw.name,
            severity: raw.severity,
            action: raw.action,
            description: raw.description,
            tool_matchers,
            arg_regexes,
            tests: raw.tests,
            source_file: source_file.to_string(),
        })
    }

    pub fn evaluate(&self, tool: &str, args: &Value) -> Option<RuleVerdict> {
        let mut string_args = Vec::new();
        extract_strings(args, &mut string_args);

        for rule in &self.rules {
            // Check tool name glob match (if empty, matches all tools)
            let tool_matches = if rule.tool_matchers.is_empty() {
                true
            } else {
                rule.tool_matchers.iter().any(|m| m.is_match(tool))
            };

            if !tool_matches {
                continue;
            }

            // Check arg regexes against all string arguments
            for text in &string_args {
                for re in &rule.arg_regexes {
                    if re.is_match(text) {
                        return match rule.action {
                            RuleAction::Block => Some(RuleVerdict::Block {
                                rule_id: rule.id.clone(),
                                name: rule.name.clone(),
                                severity: rule.severity.clone(),
                                matched: text.chars().take(80).collect(),
                            }),
                            RuleAction::Warn => Some(RuleVerdict::Warn {
                                rule_id: rule.id.clone(),
                                name: rule.name.clone(),
                                severity: rule.severity.clone(),
                                matched: text.chars().take(80).collect(),
                            }),
                        };
                    }
                }
            }
        }

        None
    }
}

fn extract_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                extract_strings(item, out);
            }
        }
        Value::Object(map) => {
            for val in map.values() {
                extract_strings(val, out);
            }
        }
        _ => {}
    }
}
