use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

use crate::rules::{RuleAction, RuleEngine};

pub fn run_rule_tests(rules_dir: &Path) -> Result<bool> {
    println!("\n\x1b[1;36m======================================================================\x1b[0m");
    println!("\x1b[1;36m  agent-shield fuzz  |  Community YAML Rule Verification\x1b[0m");
    println!("  Directory: {}", rules_dir.display());
    println!("\x1b[1;36m======================================================================\x1b[0m\n");

    let engine = RuleEngine::load_dir(rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;

    if engine.rules.is_empty() {
        println!("No YAML rules found in {}", rules_dir.display());
        return Ok(true);
    }

    let mut total_rules = 0;
    let mut total_tests = 0;
    let mut passed_tests = 0;
    let mut failed_tests = 0;

    for rule in &engine.rules {
        total_rules += 1;
        println!("Rule: \x1b[1m{}\x1b[0m ({}) [{}]", rule.id, rule.source_file, rule.severity);

        let Some(tests) = &rule.tests else {
            println!("  \x1b[33m[SKIP]\x1b[0m No tests defined in rule\n");
            continue;
        };

        let single_engine = RuleEngine {
            rules: vec![rule.clone()],
        };

        // 1. Test should_block cases
        for case in &tests.should_block {
            total_tests += 1;
            let verdict = single_engine.evaluate(&case.tool, &case.args);
            let ok = match (rule.action.clone(), verdict) {
                (RuleAction::Block, Some(crate::rules::RuleVerdict::Block { .. })) => true,
                (RuleAction::Warn, Some(crate::rules::RuleVerdict::Warn { .. })) => true,
                _ => false,
            };

            if ok {
                passed_tests += 1;
                println!("  \x1b[32m[PASS]\x1b[0m should_block: {} {:?}", case.tool, case.args);
            } else {
                failed_tests += 1;
                println!(
                    "  \x1b[1;31m[FAIL]\x1b[0m should_block FAILED to trigger rule: {} {:?}",
                    case.tool, case.args
                );
            }
        }

        // 2. Test should_allow cases
        for case in &tests.should_allow {
            total_tests += 1;
            let verdict = single_engine.evaluate(&case.tool, &case.args);
            if verdict.is_none() {
                passed_tests += 1;
                println!("  \x1b[32m[PASS]\x1b[0m should_allow: {} {:?}", case.tool, case.args);
            } else {
                failed_tests += 1;
                println!(
                    "  \x1b[1;31m[FAIL]\x1b[0m should_allow falsely triggered rule: {} {:?}",
                    case.tool, case.args
                );
            }
        }

        println!();
    }

    println!("----------------------------------------------------------------------");
    if failed_tests == 0 {
        println!(
            "\x1b[1;32mRESULT: ALL PASSED\x1b[0m ({} rules, {} test cases passed, 0 failures)",
            total_rules, passed_tests
        );
    } else {
        println!(
            "\x1b[1;31mRESULT: FAILED\x1b[0m ({} passed, {} failed out of {} test cases)",
            passed_tests, failed_tests, total_tests
        );
    }
    println!("----------------------------------------------------------------------\n");

    Ok(failed_tests == 0)
}

pub async fn run_server_qa(
    cmd: &str,
    args: &[String],
    workspace: Option<&Path>,
) -> Result<bool> {
    println!("\n\x1b[1;36m======================================================================\x1b[0m");
    println!("\x1b[1;36m  agent-shield fuzz  |  MCP Schema & Boundary QA Runner\x1b[0m");
    println!("  Target: {} {:?}", cmd, args);
    if let Some(ws) = workspace {
        println!("  Workspace: {}", ws.display());
    }
    println!("\x1b[1;36m======================================================================\x1b[0m\n");

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("Failed to spawn target server: {}", cmd))?;

    let mut child_in = child.stdin.take().expect("failed child stdin");
    let mut child_out = BufReader::new(child.stdout.take().expect("failed child stdout")).lines();

    let mut req_id = 0;

    let mut send_rpc = |method: &str, params: Value| {
        req_id += 1;
        let id = req_id;
        let frame = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        format!("{}\n", frame)
    };

    // 1. Handshake: initialize
    println!("[1/4] Probing server handshake (initialize) ...");
    let t0 = Instant::now();
    child_in
        .write_all(
            send_rpc(
                "initialize",
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": { "name": "agent-shield-fuzz", "version": "0.1.0" }
                }),
            )
            .as_bytes(),
        )
        .await?;
    child_in.flush().await?;

    let init_resp = match child_out.next_line().await? {
        Some(line) => line,
        None => bail!("Target MCP server exited prematurely during initialize"),
    };
    let init_val: Value = serde_json::from_str(&init_resp).unwrap_or(json!({}));
    let srv_name = init_val
        .get("result")
        .and_then(|r| r.get("serverInfo"))
        .and_then(|s| s.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");
    println!("  \x1b[32m[OK]\x1b[0m Connected to '{}' in {:.1}ms", srv_name, t0.elapsed().as_secs_f64() * 1000.0);

    // 2. Fetch tools
    println!("[2/4] Querying available tools (tools/list) ...");
    child_in.write_all(send_rpc("tools/list", json!({})).as_bytes()).await?;
    child_in.flush().await?;

    let tools_resp = match child_out.next_line().await? {
        Some(line) => line,
        None => bail!("Target MCP server closed stdout during tools/list"),
    };
    let tools_val: Value = serde_json::from_str(&tools_resp).unwrap_or(json!({}));
    let tools = tools_val
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();

    println!("  \x1b[32m[OK]\x1b[0m Discovered {} tool(s)", tools.len());

    // 3. Fuzz each tool with safe boundary cases
    println!("[3/4] Fuzzing tools with safe resilience & boundary cases ...");
    let mut total_fuzz_cases = 0;
    let mut survived_cases = 0;

    for tool in &tools {
        let name = tool.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
        print!("  Tool '{}': ", name);

        let test_cases = vec![
            ("empty_args", json!({})),
            ("null_args", json!({ "path": null, "query": null, "cmd": null })),
            ("wrong_types", json!({ "path": 12345, "query": true, "cmd": [1, 2] })),
            (
                "oversized_string",
                json!({ "input": "A".repeat(16384), "query": "B".repeat(16384) }),
            ),
            (
                "boundary_canary",
                json!({
                    "path": "../agent_shield_canary.txt",
                    "file": "../../agent_shield_canary.txt",
                    "file_path": "../../../agent_shield_canary.txt"
                }),
            ),
        ];

        let mut tool_ok = true;
        for (_label, test_args) in test_cases {
            total_fuzz_cases += 1;
            let call_frame = send_rpc("tools/call", json!({ "name": name, "arguments": test_args }));
            if child_in.write_all(call_frame.as_bytes()).await.is_err() {
                tool_ok = false;
                break;
            }
            if child_in.flush().await.is_err() {
                tool_ok = false;
                break;
            }

            match child_out.next_line().await {
                Ok(Some(line)) => {
                    if serde_json::from_str::<Value>(&line).is_ok() {
                        survived_cases += 1;
                    } else {
                        tool_ok = false;
                    }
                }
                _ => {
                    tool_ok = false;
                    break;
                }
            }
        }

        if tool_ok {
            println!("\x1b[32mPASS\x1b[0m (5/5 cases handled gracefully)");
        } else {
            println!("\x1b[31mCRASH/HANG\x1b[0m");
        }
    }

    println!("[4/4] Summary verdict ...");
    let all_passed = total_fuzz_cases > 0 && total_fuzz_cases == survived_cases;
    println!("----------------------------------------------------------------------");
    if all_passed {
        println!(
            "\x1b[1;32mSCHEMA RESILIENCE: 100%\x1b[0m ({} cases tested, 0 server crashes)",
            total_fuzz_cases
        );
    } else {
        println!(
            "\x1b[1;33mSCHEMA RESILIENCE: {}%\x1b[0m ({}/{} cases handled cleanly)",
            (survived_cases * 100) / total_fuzz_cases.max(1),
            survived_cases,
            total_fuzz_cases
        );
    }
    println!("----------------------------------------------------------------------\n");

    let _ = child.kill().await;
    Ok(all_passed)
}
