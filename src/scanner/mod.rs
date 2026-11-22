use anyhow::Result;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub block_prompt_injection: bool,
    #[serde(default = "default_true")]
    pub redact_secrets_in_response: bool,
    #[serde(default = "default_true")]
    pub strip_invisible_unicode: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            block_prompt_injection: true,
            redact_secrets_in_response: true,
            strip_invisible_unicode: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub sanitized_json: String,
    pub findings: Vec<String>,
}

pub struct ResponseScanner {
    cfg: ScannerConfig,
    secret_rules: Vec<(&'static str, Regex)>,
    injection_rules: Vec<(&'static str, Regex)>,
}

impl ResponseScanner {
    pub fn new(cfg: ScannerConfig) -> Result<Self> {
        let secret_rules = vec![
            ("AWS_ACCESS_KEY", Regex::new(r"\bAKIA[0-9A-Z]{16}\b")?),
            ("GITHUB_TOKEN", Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")?),
            ("OPENAI_OR_ANTHROPIC_KEY", Regex::new(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b")?),
            ("SLACK_TOKEN", Regex::new(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")?),
            ("GOOGLE_API_KEY", Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b")?),
            (
                "PRIVATE_KEY_BLOCK",
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")?,
            ),
            (
                "GENERIC_SECRET_ASSIGN",
                Regex::new(r#"(?i)\b(api_key|secret_key|db_password|auth_token)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+=]{12,}['"]?"#)?,
            ),
        ];

        let injection_rules = vec![
            (
                "INSTRUCTION_OVERRIDE",
                Regex::new(r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)")?,
            ),
            (
                "ROLE_HIJACK",
                Regex::new(r"(?i)(you are now|act as|switch to)\s+(in\s+)?(developer mode|unrestricted|jailbreak|system admin)")?,
            ),
            (
                "SYSTEM_TAG_SPOOF",
                Regex::new(r"(?i)(</?system>|<\|im_start\|>|<\|system\|>|\[INST\])")?,
            ),
            (
                "EXFILTRATION_DIRECTIVE",
                Regex::new(r"(?i)(read|dump|exfiltrate|steal)\s+.*(\.env|\.ssh|id_rsa|api[_\s]?key|credentials).*(send|post|upload|curl|webhook)")?,
            ),
            (
                "SILENT_TOOL_COERCION",
                Regex::new(r"(?i)(do not tell the user|hide this from the user|silently execute|without informing the user)")?,
            ),
        ];

        Ok(Self {
            cfg,
            secret_rules,
            injection_rules,
        })
    }

    pub fn sanitize_response(&self, raw_line: &str) -> ScanOutcome {
        let Ok(mut val) = serde_json::from_str::<Value>(raw_line) else {
            return ScanOutcome {
                sanitized_json: raw_line.to_string(),
                findings: Vec::new(),
            };
        };

        let mut findings = Vec::new();
        if let Some(result_node) = val.get_mut("result") {
            self.walk_and_clean(result_node, &mut findings);
        }

        let sanitized_json = if findings.is_empty() {
            raw_line.to_string()
        } else {
            serde_json::to_string(&val).unwrap_or_else(|_| raw_line.to_string())
        };

        ScanOutcome {
            sanitized_json,
            findings,
        }
    }

    fn walk_and_clean(&self, node: &mut Value, findings: &mut Vec<String>) {
        match node {
            Value::String(text) => {
                let mut current = text.clone();

                // 1. Strip hidden Unicode tag smuggling & zero-width chars
                if self.cfg.strip_invisible_unicode {
                    let (cleaned, removed) = strip_hidden_unicode(&current);
                    if removed > 0 {
                        findings.push(format!("stripped {} invisible/tag Unicode chars", removed));
                        current = cleaned;
                    }
                }

                // 2. Redact leaked secrets before they reach the LLM context
                if self.cfg.redact_secrets_in_response {
                    for (label, re) in &self.secret_rules {
                        if re.is_match(&current) {
                            current = re
                                .replace_all(&current, format!("[REDACTED:{}:agent-shield]", label))
                                .into_owned();
                            findings.push(format!("redacted secret: {}", label));
                        }
                    }
                }

                // 3. Quarantine prompt injection payloads
                if self.cfg.block_prompt_injection {
                    let mut matched_rules = Vec::new();
                    for (label, re) in &self.injection_rules {
                        if re.is_match(&current) {
                            matched_rules.push(*label);
                        }
                    }
                    if !matched_rules.is_empty() {
                        findings.push(format!("prompt injection blocked: {}", matched_rules.join(", ")));
                        current = format!(
                            "[BLOCKED BY AGENT-SHIELD: Suspected prompt injection ({}). Payload quarantined before reaching LLM.]",
                            matched_rules.join(", ")
                        );
                    }
                }

                *text = current;
            }
            Value::Array(arr) => {
                for item in arr {
                    self.walk_and_clean(item, findings);
                }
            }
            Value::Object(map) => {
                for v in map.values_mut() {
                    self.walk_and_clean(v, findings);
                }
            }
            _ => {}
        }
    }
}

fn strip_hidden_unicode(input: &str) -> (String, usize) {
    let mut out = String::with_capacity(input.len());
    let mut removed = 0usize;

    for ch in input.chars() {
        let code = ch as u32;
        let is_hidden = matches!(
            code,
            0x200B..=0x200D   // Zero-width space / joiners
            | 0x2060          // Word joiner
            | 0xFEFF          // BOM / ZWNBSP
            | 0x202A..=0x202E // BiDi overrides (Trojan Source)
            | 0x2066..=0x2069 // BiDi isolates
            | 0xE0000..=0xE007F // Unicode Tags block (classic invisible prompt injection)
        );

        if is_hidden {
            removed += 1;
        } else {
            out.push(ch);
        }
    }

    (out, removed)
}
