use anyhow::Result;
use serde_json::{json, Value};
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::lockfile::{LockDrift, ShieldLock};
use crate::policy::{Decision, PolicyEngine};
use crate::sandbox::SandboxConfig;
use crate::scanner::ResponseScanner;

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
                                crate::write_audit_event("inbound", "RUG_PULL_BLOCKED", srv_name);
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
