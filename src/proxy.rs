use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::lockfile::{LockDrift, ShieldLock};
use crate::policy::{Decision, PolicyEngine};
use crate::rules::{RuleDecision, RuleEngine};
use crate::sandbox::{spawn_sandboxed, SandboxConfig};
use crate::scanner::ResponseScanner;
use crate::taint::{TaintEngine, TaintVerdict};

pub struct ProxyContext {
    pub server_name: String,
    pub policy: PolicyEngine,
    pub rules: RuleEngine,
    pub scanner: ResponseScanner,
    pub taint: TaintEngine,
    pub lockfile: Option<ShieldLock>,
    pub sandbox: Option<SandboxConfig>,
}

pub async fn run_proxy(cmd: &str, args: &[String], ctx: ProxyContext) -> Result<()> {
    // 1. Spawn real MCP server (inside OS-native sandbox if --sandbox was passed)
    let (mut child, _sandbox_guard) = if let Some(ref sb_cfg) = ctx.sandbox {
        let (c, guard) = spawn_sandboxed(cmd, args, sb_cfg)?;
        (c, Some(guard))
    } else {
        let c = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("failed to spawn MCP server '{}'", cmd))?;
        (c, None)
    };

    let mut child_stdin = child.stdin.take().context("failed to open child stdin")?;
    let child_stdout = child.stdout.take().context("failed to open child stdout")?;

    let mut client_in = BufReader::new(io::stdin()).lines();
    let mut server_out = BufReader::new(child_stdout).lines();
    let mut client_out = io::stdout();

    // Maps JSON-RPC request ID -> (tool_name, tool_args) so Direction B knows which tool replied
    let mut pending_calls: HashMap<String, (String, Value)> = HashMap::new();

    loop {
        tokio::select! {
            // ================================================================
            // Direction A: MCP Client -> agent-shield -> MCP Server
            // ================================================================
            line = client_in.next_line() => {
                let Some(raw) = line? else { break; };
                if raw.trim().is_empty() { continue; }

                if let Ok(msg) = serde_json::from_str::<Value>(&raw) {
                    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

                    if method == "tools/call" {
                        let tool_name = msg
                            .get("params")
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        let tool_args = msg
                            .get("params")
                            .and_then(|p| p.get("arguments"))
                            .cloned()
                            .unwrap_or_else(|| json!({}));

                        // Gate 1: Core Policy Engine (path traversal, workspace jail, shell guard)
                        match ctx.policy.evaluate_tool_call(&msg) {
                            Decision::Block(reason) => {
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "BLOCK", &reason, &raw,
                                );
                                eprintln!("\x1b[1;31m[agent-shield] BLOCKED:\x1b[0m {}", reason);
                                send_jsonrpc_error(
                                    &mut client_out,
                                    msg.get("id"),
                                    -32001,
                                    &format!("Blocked by agent-shield: {}", reason),
                                ).await?;
                                continue;
                            }
                            Decision::AuditAlert(reason) => {
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "AUDIT_ALERT", &reason, &raw,
                                );
                                eprintln!("\x1b[1;33m[agent-shield] AUDIT ALERT:\x1b[0m {}", reason);
                            }
                            Decision::Allow => {}
                        }

                        // Gate 2: Community YAML Rule Packs
                        match ctx.rules.evaluate(tool_name, &tool_args) {
                            RuleDecision::Block { rule_id, rule_name, .. } => {
                                let reason = format!("Rule [{}] {}: blocked '{}'", rule_id, rule_name, tool_name);
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "RULE_BLOCK", &reason, &raw,
                                );
                                eprintln!("\x1b[1;31m[agent-shield] {}\x1b[0m", reason);
                                send_jsonrpc_error(
                                    &mut client_out,
                                    msg.get("id"),
                                    -32005,
                                    &format!("Blocked by agent-shield: {}", reason),
                                ).await?;
                                continue;
                            }
                            RuleDecision::Warn { rule_id, rule_name, .. } => {
                                let reason = format!("Rule [{}] {} matched '{}'", rule_id, rule_name, tool_name);
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "RULE_WARN", &reason, &raw,
                                );
                                eprintln!("\x1b[1;33m[agent-shield] WARN:\x1b[0m {}", reason);
                            }
                            RuleDecision::Allow => {}
                        }

                        // Gate 3: Cross-Server Taint & Encoding-Aware DLP (Base64 / Hex / URL / Rev)
                        match ctx.taint.check_outbound_call(&ctx.server_name, tool_name, &tool_args) {
                            TaintVerdict::BlockDlp { encoding, label, source_server, source_tool } => {
                                let reason = format!(
                                    "Cross-server DLP block: {} ({}) from {}::{} detected in '{}'",
                                    label, encoding, source_server, source_tool, tool_name
                                );
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "DLP_BLOCK", &reason, &raw,
                                );
                                eprintln!("\x1b[1;31m[agent-shield] {}\x1b[0m", reason);
                                send_jsonrpc_error(
                                    &mut client_out,
                                    msg.get("id"),
                                    -32003,
                                    &format!("Blocked by agent-shield: {}", reason),
                                ).await?;
                                continue;
                            }
                            TaintVerdict::BlockTrifecta { private_servers, untrusted_servers } => {
                                let reason = format!(
                                    "Lethal Trifecta active (private={:?}, untrusted={:?}) -> blocked '{}'",
                                    private_servers, untrusted_servers, tool_name
                                );
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "TRIFECTA_BLOCK", &reason, &raw,
                                );
                                eprintln!("\x1b[1;31m[agent-shield] {}\x1b[0m", reason);
                                send_jsonrpc_error(
                                    &mut client_out,
                                    msg.get("id"),
                                    -32004,
                                    &format!("Blocked by agent-shield: {}", reason),
                                ).await?;
                                continue;
                            }
                            TaintVerdict::WarnTrifecta { private_servers, untrusted_servers } => {
                                let reason = format!(
                                    "Lethal Trifecta warning (private={:?}, untrusted={:?}) -> '{}'",
                                    private_servers, untrusted_servers, tool_name
                                );
                                crate::write_rich_audit_event(
                                    &ctx.server_name, tool_name, "outbound", "TRIFECTA_WARN", &reason, &raw,
                                );
                                eprintln!("\x1b[1;33m[agent-shield] {}\x1b[0m", reason);
                            }
                            TaintVerdict::Allow => {}
                        }

                        // Passed all outbound gates -> track ID for response correlation & log ALLOW
                        if let Some(id) = msg.get("id") {
                            if pending_calls.len() > 1024 {
                                pending_calls.clear();
                            }
                            pending_calls.insert(id.to_string(), (tool_name.to_string(), tool_args));
                        }
                        crate::write_rich_audit_event(
                            &ctx.server_name, tool_name, "outbound", "ALLOW", "forwarded tool call", &raw,
                        );
                    }
                }

                // Forward clean frame to real MCP Server
                child_stdin.write_all(raw.as_bytes()).await?;
                child_stdin.write_all(b"\n").await?;
                child_stdin.flush().await?;
            }

            // ================================================================
            // Direction B: MCP Server -> agent-shield -> MCP Client
            // ================================================================
            line = server_out.next_line() => {
                let Some(raw) = line? else { break; };
                if raw.trim().is_empty() { continue; }

                let mut resp_tool = "response".to_string();

                if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                    // Gate 1: Mid-Session Rug-Pull Verification against shield.lock
                    if let Some(ref lock) = ctx.lockfile {
                        if let Some(tools) = parsed
                            .get("result")
                            .and_then(|r| r.get("tools"))
                            .and_then(|t| t.as_array())
                        {
                            let drifts = lock.verify_server(&ctx.server_name, tools);
                            if !drifts.is_empty() {
                                let (summary, diff_payload) = summarize_drifts(&drifts);
                                crate::write_rich_audit_event(
                                    &ctx.server_name,
                                    "tools/list",
                                    "inbound",
                                    "RUG_PULL_BLOCKED",
                                    &summary,
                                    &diff_payload,
                                );
                                eprintln!(
                                    "\x1b[1;31m[agent-shield] RUG-PULL BLOCKED on '{}':\x1b[0m {}\n{}",
                                    ctx.server_name, summary, diff_payload
                                );
                                send_jsonrpc_error(
                                    &mut client_out,
                                    parsed.get("id"),
                                    -32002,
                                    &format!(
                                        "Blocked by agent-shield: tool schema rug-pull detected on '{}' ({})",
                                        ctx.server_name, summary
                                    ),
                                ).await?;
                                continue;
                            }
                        }
                    }

                    // Gate 2: Taint Fingerprint Ingestion (MUST run BEFORE secret redaction)
                    if let Some(id) = parsed.get("id") {
                        if let Some((tool_name, tool_args)) = pending_calls.remove(&id.to_string()) {
                            resp_tool = tool_name.clone();
                            let tainted = ctx.taint.ingest_response(
                                &ctx.server_name,
                                &tool_name,
                                &tool_args,
                                &raw,
                            );
                            if tainted > 0 {
                                eprintln!(
                                    "[agent-shield] Taint Engine armed {} SHA-256 anchor(s) from {}::{}",
                                    tainted, ctx.server_name, tool_name
                                );
                            }
                        }
                    }
                }

                // Gate 3: Inbound Response Scanner (Unicode stripping, secret redaction, prompt injection)
                let outcome = ctx.scanner.sanitize_response(&raw);
                if !outcome.findings.is_empty() {
                    let summary = outcome.findings.join("; ");
                    crate::write_rich_audit_event(
                        &ctx.server_name,
                        &resp_tool,
                        "inbound",
                        "SANITIZED",
                        &summary,
                        &outcome.sanitized_json,
                    );
                    eprintln!("\x1b[1;33m[agent-shield] SANITIZED:\x1b[0m {}", summary);
                } else {
                    crate::write_rich_audit_event(
                        &ctx.server_name,
                        &resp_tool,
                        "inbound",
                        "ALLOW",
                        "clean server response",
                        &outcome.sanitized_json,
                    );
                }

                // Forward clean/sanitized JSON-RPC frame to MCP Client
                client_out.write_all(outcome.sanitized_json.as_bytes()).await?;
                client_out.write_all(b"\n").await?;
                client_out.flush().await?;
            }
        }
    }

    let _ = child.wait().await;
    Ok(())
}

async fn send_jsonrpc_error(
    client_out: &mut io::Stdout,
    id: Option<&Value>,
    code: i64,
    message: &str,
) -> Result<()> {
    if let Some(req_id) = id {
        let err_frame = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message
            }
        });
        let out = format!("{}\n", err_frame);
        client_out.write_all(out.as_bytes()).await?;
        client_out.flush().await?;
    }
    Ok(())
}

fn summarize_drifts(drifts: &[LockDrift]) -> (String, String) {
    let mut parts = Vec::new();
    let mut diffs = String::new();

    for d in drifts {
        match d {
            LockDrift::UnpinnedServer { server } => {
                parts.push(format!("unpinned server '{}'", server));
            }
            LockDrift::ToolAdded { tool, .. } => {
                parts.push(format!("new unpinned tool '{}'", tool));
            }
            LockDrift::ToolRemoved { tool, .. } => {
                parts.push(format!("removed pinned tool '{}'", tool));
            }
            LockDrift::SchemaMutated { tool, diff, .. } => {
                parts.push(format!("mutated schema '{}'", tool));
                diffs.push_str(&format!("--- tool: {} ---\n{}\n", tool, strip_ansi(diff)));
            }
        }
    }

    let summary = parts.join(", ");
    let payload = if diffs.is_empty() { summary.clone() } else { diffs };
    (summary, payload)
}

/// Strips ANSI escapes before storing diffs in audit.jsonl so ratatui renders clean +/- colors.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for ch in chars.by_ref() {
                if ch == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
