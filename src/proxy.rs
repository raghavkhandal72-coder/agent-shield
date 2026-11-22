use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::lockfile::{LockDrift, ShieldLock};
use crate::policy::{Decision, PolicyEngine};
use crate::sandbox::SandboxConfig;
use crate::scanner::ResponseScanner;
use crate::taint::{TaintConfig, TaintEngine, TaintVerdict};

pub async fn run_proxy(
    cmd: &str,
    args: &[String],
    policy: PolicyEngine,
    scanner: ResponseScanner,
    server_name: Option<String>,
    lockfile: Option<ShieldLock>,
    sandbox_cfg: Option<SandboxConfig>,
) -> Result<()> {
    // 1. Spawn child process (inside sandbox if configured)
    let (mut child, _sandbox_guard) = if let Some(sb_cfg) = sandbox_cfg {
        let (c, g) = crate::sandbox::spawn_sandboxed(cmd, args, &sb_cfg)?;
        (c, Some(g))
    } else {
        let c = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        (c, None)
    };

    let mut child_stdin = child.stdin.take().expect("failed to open child stdin");
    let child_stdout = child.stdout.take().expect("failed to open child stdout");

    let mut client_in = BufReader::new(io::stdin()).lines();
    let mut server_out = BufReader::new(child_stdout).lines();
    let mut client_out = io::stdout();

    let server_name_str = server_name.clone().unwrap_or_else(|| "mcp".to_string());
    let taint = TaintEngine::new(TaintConfig::default())?;
    let mut pending_calls: HashMap<String, (String, Value)> = HashMap::new();

    loop {
        tokio::select! {
            // Direction A: MCP Client -> agent-shield -> MCP Server
            line = client_in.next_line() => {
                let Some(raw) = line? else { break; };
                if raw.trim().is_empty() { continue; }

                match serde_json::from_str::<Value>(&raw) {
                    Ok(msg) if msg.get("method").and_then(|m| m.as_str()) == Some("tools/call") => {
                        let tool_name = msg.get("params")
                            .and_then(|p| p.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let tool_args = msg.get("params")
                            .and_then(|p| p.get("arguments"))
                            .cloned()
                            .unwrap_or(json!({}));

                        // 1. Cross-Server Taint & Encoding-Aware DLP Check
                        match taint.check_outbound_call(&server_name_str, tool_name, &tool_args) {
                            TaintVerdict::BlockDlp { encoding, label, source_server, source_tool } => {
                                let reason = format!(
                                    "Cross-server DLP block: {} ({}) from {}::{} detected in {} outbound call",
                                    label, encoding, source_server, source_tool, tool_name
                                );
                                crate::write_rich_audit_event(&server_name_str, tool_name, "outbound", "DLP_BLOCK", &reason, &raw);
                                eprintln!("\x1b[1;31m[agent-shield] {}\x1b[0m", reason);
                                if let Some(id) = msg.get("id") {
                                    let err_frame = json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": { "code": -32003, "message": format!("Blocked by agent-shield: {}", reason) }
                                    });
                                    client_out.write_all(format!("{}\n", err_frame).as_bytes()).await?;
                                    client_out.flush().await?;
                                }
                                continue;
                            }
                            TaintVerdict::BlockTrifecta { private_servers, untrusted_servers } => {
                                let reason = format!(
                                    "Lethal Trifecta active (private: {:?}, untrusted: {:?}) — outbound '{}' blocked",
                                    private_servers, untrusted_servers, tool_name
                                );
                                crate::write_rich_audit_event(&server_name_str, tool_name, "outbound", "TRIFECTA_BLOCK", &reason, &raw);
                                eprintln!("\x1b[1;31m[agent-shield] {}\x1b[0m", reason);
                                if let Some(id) = msg.get("id") {
                                    let err_frame = json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": { "code": -32004, "message": format!("Blocked by agent-shield: {}", reason) }
                                    });
                                    client_out.write_all(format!("{}\n", err_frame).as_bytes()).await?;
                                    client_out.flush().await?;
                                }
                                continue;
                            }
                            TaintVerdict::WarnTrifecta { private_servers, untrusted_servers } => {
                                eprintln!(
                                    "\x1b[1;33m[agent-shield] TRIFECTA WARNING:\x1b[0m private={:?} + untrusted={:?} -> outbound '{}'",
                                    private_servers, untrusted_servers, tool_name
                                );
                            }
                            TaintVerdict::Allow => {}
                        }

                        // Track call ID so Direction B can map response back to tool
                        if let Some(id) = msg.get("id") {
                            pending_calls.insert(id.to_string(), (tool_name.to_string(), tool_args));
                        }

                        // 2. Outbound Policy Engine check
                        match policy.evaluate_tool_call(&msg) {
                            Decision::Block(reason) => {
                                crate::write_rich_audit_event(&server_name_str, tool_name, "outbound", "BLOCK", &reason, &raw);
                                eprintln!("[agent-shield] BLOCKED: {}", reason);
                                if let Some(id) = msg.get("id") {
                                    let err_frame = json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": -32001,
                                            "message": format!("Blocked by agent-shield: {}", reason)
                                        }
                                    });
                                    client_out.write_all(format!("{}\n", err_frame).as_bytes()).await?;
                                    client_out.flush().await?;
                                }
                                continue;
                            }
                            Decision::AuditAlert(reason) => {
                                crate::write_rich_audit_event(&server_name_str, tool_name, "outbound", "AUDIT_ALERT", &reason, &raw);
                                eprintln!("[agent-shield] AUDIT ALERT: {}", reason);
                            }
                            Decision::Allow => {
                                crate::write_rich_audit_event(&server_name_str, tool_name, "outbound", "ALLOW", "forwarded", &raw);
                            }
                        }
                    }
                    _ => {}
                }

                // Forward clean frame to real MCP Server
                child_stdin.write_all(raw.as_bytes()).await?;
                child_stdin.write_all(b"\n").await?;
                child_stdin.flush().await?;
            }

            // Direction B: MCP Server -> agent-shield -> MCP Client
            line = server_out.next_line() => {
                let Some(raw) = line? else { break; };
                if raw.trim().is_empty() { continue; }

                // Ingest response for secret fingerprinting & taint tracking
                if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                    if let Some(id) = parsed.get("id") {
                        if let Some((tool_name, tool_args)) = pending_calls.remove(&id.to_string()) {
                            let tainted = taint.ingest_response(&server_name_str, &tool_name, &tool_args, &raw);
                            if tainted > 0 {
                                eprintln!(
                                    "[agent-shield] Taint Engine fingerprinted {} secret anchor(s) from {}::{}",
                                    tainted, server_name_str, tool_name
                                );
                            }
                        }
                    }
                }

                // Live mid-session rug-pull freeze check
                if let (Some(lock), Some(srv_name)) = (&lockfile, &server_name) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                        if let Some(tools) = parsed
                            .get("result")
                            .and_then(|r| r.get("tools"))
                            .and_then(|t| t.as_array())
                        {
                            let drifts = lock.verify_server(srv_name, tools);
                            if !drifts.is_empty() {
                                for d in &drifts {
                                    if let LockDrift::SchemaMutated { tool, diff, .. } = d {
                                        eprintln!("\x1b[1;31m[agent-shield] RUG-PULL BLOCKED on '{}::{}':\x1b[0m\n{}", srv_name, tool, diff);
                                    }
                                }
                                crate::write_rich_audit_event(srv_name, "-", "inbound", "RUG_PULL_BLOCKED", "schema mutated", &raw);
                                if let Some(id) = parsed.get("id") {
                                    let err_frame = json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": -32002,
                                            "message": format!("Blocked by agent-shield: tool schema rug-pull detected on '{}'. Run `agent-shield scan` to inspect diff.", srv_name)
                                        }
                                    });
                                    client_out.write_all(format!("{}\n", err_frame).as_bytes()).await?;
                                    client_out.flush().await?;
                                }
                                continue;
                            }
                        }
                    }
                }

                let outcome = scanner.sanitize_response(&raw);
                if !outcome.findings.is_empty() {
                    let summary = outcome.findings.join("; ");
                    crate::write_rich_audit_event(&server_name_str, "-", "inbound", "SANITIZED", &summary, &raw);
                    eprintln!("[agent-shield] SANITIZED RESPONSE: {}", summary);
                } else {
                    crate::write_rich_audit_event(&server_name_str, "-", "inbound", "ALLOW", "clean response", &raw);
                }
                client_out.write_all(outcome.sanitized_json.as_bytes()).await?;
                client_out.write_all(b"\n").await?;
                client_out.flush().await?;
            }
        }
    }

    drop(child_stdin);
    let _ = child.wait().await;
    Ok(())
}
