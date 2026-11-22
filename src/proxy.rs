use anyhow::Result;
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::policy::{Decision, PolicyEngine};
use crate::scanner::ResponseScanner;

pub async fn run_proxy(
    cmd: &str,
    args: &[String],
    policy: PolicyEngine,
    scanner: ResponseScanner,
) -> Result<()> {
    // 1. Spawn the real MCP Server with piped stdio
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Let server errors pass to host stderr safely
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("failed to open child stdin");
    let child_stdout = child.stdout.take().expect("failed to open child stdout");

    let mut client_in = BufReader::new(io::stdin()).lines();
    let mut server_out = BufReader::new(child_stdout).lines();
    let mut client_out = io::stdout();

    loop {
        tokio::select! {
            // Direction A: MCP Client -> agent-shield -> MCP Server
            line = client_in.next_line() => {
                let Some(raw) = line? else { break; };
                if raw.trim().is_empty() { continue; }

                match serde_json::from_str::<Value>(&raw) {
                    Ok(msg) if msg.get("method").and_then(|m| m.as_str()) == Some("tools/call") => {
                        match policy.evaluate_tool_call(&msg) {
                            Decision::Block(reason) => {
                                crate::write_audit_event("outbound", "BLOCK", &reason);
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
                                crate::write_audit_event("outbound", "AUDIT_ALERT", &reason);
                                eprintln!("[agent-shield] AUDIT ALERT: {}", reason);
                            }
                            Decision::Allow => {}
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

                let outcome = scanner.sanitize_response(&raw);
                if !outcome.findings.is_empty() {
                    let summary = outcome.findings.join("; ");
                    crate::write_audit_event("inbound", "SANITIZED", &summary);
                    eprintln!("[agent-shield] SANITIZED RESPONSE: {}", summary);
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
