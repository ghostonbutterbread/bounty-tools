# Ghost Orchestrator

Persistent bug bounty hunting coordination layer that orchestrates AI coding agents (Claude Code or Codex) for security testing.

## What It Is

Ghost coordinates multiple AI agents in parallel. Each agent gets:
- Its own Chrome container (via chrome-devtools-mcp)
- Relevant context from reconnaissance
- A specific hunting task

Findings flow back to Ghost → logged to central ledger → deduplicated → prioritized.

## Quick Start

```python
from orchestrator import hunt, AgentRuntime

# Full hunt on a program
result = hunt("acme", tasks=["xss", "bac"], runtime=AgentRuntime.CLAUDE)

# Spawn a single agent
from orchestrator import spawn_agent
config = spawn_agent(
    program_name="acme",
    task_type="xss",
    task_description="Test search parameters for XSS",
    context=context,
    runtime=AgentRuntime.CODEX
)
```

```bash
# CLI usage
cd ~/projects/bounty-tools/orchestrator
python3 cli.py status
python3 cli.py add-target acme --scope "*.example.com"
python3 cli.py hunt acme --tasks xss,sqli --runtime claude
```

## Architecture

```
Ryushe's Claude Code ──┬──→ Chrome MCP ──→ Chrome (Account 1)
                       │
Me (Ghost) ────────────┼──→ Chrome MCP ──→ Chrome (Account 2)
                       │
Codex Agent ──────────┴──→ Chrome MCP ──→ Chrome (Account 3)
```

## Components

| File | Purpose |
|------|---------|
| `cli.py` | CLI entry point (`python cli.py`) |
| `state_manager.py` | Thread-safe state with file locking |
| `findings_store.py` | Compatibility facade over bounty-core findings |
| `context_prep.py` | Prepares recon context for agents |
| `spawn.py` | Unified agent spawner (Claude Code + Codex) |
| `hunt.py` | High-level `hunt()` interface |
| `config.py` | Configuration and constants |
| `test_orchestrator.py` | Unit tests |

## Python API

```python
from orchestrator import (
    hunt,           # Main hunting workflow
    spawn_agent,    # Spawn and run a single agent
    run_agent,      # Execute an agent config
    state_mgr,      # State management
    AgentRuntime,   # Runtime enum (CLAUDE, CODEX)
    save_finding,   # Save a finding
    load_all_findings,
)

# Run a hunt session
result = hunt(
    program_name="acme",
    tasks=["xss", "sqli", "ssrf", "bac"],
    runtime=AgentRuntime.CLAUDE,
    parallel=False,
    timeout=600
)

# Agent spawn config (returns dict, doesn't run)
config = spawn_agent(
    program_name="acme",
    task_type="xss",
    task_description="Test search parameters for XSS",
    context=context,
    runtime=AgentRuntime.CLAUDE
)

# Run the spawned agent
result = run_agent(
    program_name="acme",
    task_type="xss",
    task_description="Test XSS",
    context=context,
    runtime=AgentRuntime.CLAUDE
)

# State management
state = state_mgr.read()
state_mgr.add_target("acme", ["*.example.com"])
state_mgr.add_finding(finding)
```

## CLI Commands

```bash
# Status overview
python3 cli.py status

# Add a target program
python3 cli.py add-target acme \
  --scope "*.example.com" \
  --accounts "test@example.com"

# Spawn and run a single agent
python3 cli.py spawn acme xss "Test search params for XSS" \
  --runtime claude \
  --model sonnet

# Run automated hunt workflow
python3 cli.py hunt acme \
  --tasks xss,sqli,bac \
  --runtime claude \
  --parallel

# Show findings
python3 cli.py findings \
  --target acme \
  --severity P1 \
  --format markdown

# Generate report
python3 cli.py report --format markdown
```

## State File

`~/Shared/web_bounty/orchestrator/web/working/orchestrator/state.json`

```json
{
  "version": "1.0",
  "targets": {
    "acme": {
      "name": "acme",
      "scope": ["*.example.com"],
      "accounts": ["test@example.com"],
      "test_history": [],
      "created_at": "2025-03-25T10:00:00"
    }
  },
  "findings": [],
  "active_agents": [],
  "last_updated": "2025-03-25T10:30:00"
}
```

## Findings Format

```json
{
  "id": 1,
  "target": "acme",
  "vuln_type": "XSS",
  "endpoint": "https://api.example.com/search?q=",
  "severity": "High - P2",
  "poc": "alert(1)",
  "description": "Reflected XSS in search parameter",
  "status": "new",
  "created_at": "2025-03-25T10:30:00"
}
```

## Severity Levels

| Constant | Meaning |
|----------|---------|
| `SEVERITY_P1` | Critical - Account takeover, payment flaws |
| `SEVERITY_P2` | High - Auth bypass, IDOR, injection |
| `SEVERITY_P3` | Medium - XSS, info disclosure |
| `SEVERITY_P4` | Low - CSRF, missing headers |
| `SEVERITY_P5` | Info - Informational only |

## Supported Agents

| Agent | Runtime | Models |
|-------|---------|--------|
| Claude Code | `AgentRuntime.CLAUDE` | Sonnet, Opus |
| Codex | `AgentRuntime.CODEX` | GPT-5.4, Claude-Sonnet, Opus |

## Task Types

| Task | Default Model | Focus |
|------|---------------|-------|
| `xss` | Sonnet | Reflected/stored XSS in params and forms |
| `sqli` | Sonnet | SQL injection in filters and APIs |
| `ssrf` | Sonnet | URL params, image fetch, webhooks |
| `bac` | Sonnet | IDOR, horizontal/vertical escalation |
| `recon` | Sonnet | Endpoint enumeration |
| `fuzz` | Sonnet | Hidden endpoints via ffuf |
| `js` | Sonnet | JavaScript secret extraction |
| `auth` | Sonnet | Authentication testing |
| `complex` | Opus | Complex exploit chains |
| `exploit_dev` | Opus | Exploit development |
| `architecture` | Opus | Deep design analysis |

## Chrome Container Strategy

- Ports 9222-9226 for up to 5 parallel agents
- Each agent gets its own port for isolation
- chrome-devtools-mcp connects to debug port

## Pentesting Module Integration

The orchestrator integrates with existing pentesting tools:

```python
from orchestrator import get_bac_tests
from bac_checks import BACChecks

# Get BAC test matrix
tests = get_bac_tests("https://api.acme.com")
# Returns 16 test cases: 4 P0, 6 P1, 6 P2

# Use credential store
from credential_store import CredentialStore
store = CredentialStore("acme")
creds = store.get()  # Returns dict with API keys, tokens
```

## Running Tests

```bash
cd ~/projects/bounty-tools/orchestrator
python3 -m pytest test_orchestrator.py -v
python3 test_orchestrator.py  # Direct run
```

## File Structure

```
orchestrator/
├── __init__.py          # Package exports
├── cli.py               # CLI entry point
├── config.py            # Configuration constants
├── state_manager.py     # Thread-safe state with file locking
├── findings_store.py    # bounty-core finding compatibility facade
├── context_prep.py      # Recon context preparation
├── spawn.py             # Unified agent spawner
├── hunt.py              # High-level hunt workflow
└── test_orchestrator.py # Unit tests
```
