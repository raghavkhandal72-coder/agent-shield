---
name: 🛡️ Propose or Add a Rule Pack
about: Submit a new community YAML rule pack to guard MCP tools
title: "[RULE]: <Short rule pack description>"
labels: ["enhancement", "rules", "good first issue"]
assignees: ''

---

### Rule Pack Details
- **Rule ID**: `e.g. redis-no-flushall`
- **Rule Name**: `e.g. Block Redis FLUSHALL and FLUSHDB`
- **Target MCP Servers / Tools**: `e.g. *redis*, *cache*, *kv*`
- **Severity**: `critical` | `high` | `medium` | `low`
- **Action**: `block` | `warn`

### What Does This Rule Prevent?
<!-- Describe the dangerous command, SQL injection, destructive API call, or credential leak this rule guards against. -->

### Proposed YAML Content (`rules/<rule-id>.yaml`)
```yaml
id: my-safe-rule
name: My Safe Rule Description
severity: high
action: block
description: Explanation of what is blocked.

match:
  tools: ["*tool_pattern*"]
  arg_regex:
    - "(?i)\\bdangerous_command\\b"

tests:
  should_block:
    - tool: my_tool
      args: { command: "dangerous_command execute" }
  should_allow:
    - tool: my_tool
      args: { command: "safe_command execute" }
```

### Self-Test Verification
Run locally before opening PR:
```bash
agent-shield fuzz --rules ./rules
```
- [ ] `agent-shield fuzz --rules ./rules` passed with 0 failures
- [ ] At least 2 `should_block` and 2 `should_allow` test cases included
