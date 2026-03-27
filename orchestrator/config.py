# Orchestrator Configuration
# Shared state and config for the Ghost hunting orchestration layer

import os
import json

ORCHESTRATOR_DIR = os.path.expanduser("~/Shared/bounty_recon/orchestrator")
STATE_FILE = os.path.join(ORCHESTRATOR_DIR, "state.json")
FINDINGS_DIR = os.path.join(ORCHESTRATOR_DIR, "findings")

# Chrome container ports for parallel agents
CHROME_PORTS = [9222, 9223, 9224, 9225, 9226]

# MCP server command
MCP_SERVER = "npx -y chrome-devtools-mcp@latest"

# Model priorities by task type
MODEL_BY_TASK = {
    "recon": "sonnet",
    "xss": "sonnet",
    "sqli": "sonnet",
    "ssrf": "sonnet",
    "bac": "sonnet",
    "auth": "sonnet",
    "api": "sonnet",
    "fuzz": "sonnet",
    "js": "sonnet",
    "complex": "opus",
    "exploit_dev": "opus",
    "architecture": "opus",
}

# Severity triage
SEVERITY_P1 = "Critical - P1"  # Account takeover, payment flaws, mass data
SEVERITY_P2 = "High - P2"       # Auth bypass, IDOR, injection
SEVERITY_P3 = "Medium - P3"     # XSS, info disclosure
SEVERITY_P4 = "Low - P4"        # CSRF, missing headers
SEVERITY_P5 = "Info - P5"       # Informational only

# Priority levels
PRIORITY_P0 = "P0 - Critical"
PRIORITY_P1 = "P1 - High"
PRIORITY_P2 = "P2 - Medium"

# Available runtimes
RUNTIMES = ["subagent", "claude", "codex"]

# Runtime selection by task type
# subagent = lightweight Python agent via existing framework
# claude = Claude Code (requires Max plan)
# codex = Codex (OpenAI)
RUNTIME_BY_TASK = {
    "fuzz": "subagent",       # Fast, uses ffuf directly
    "recon": "subagent",      # Fast enumeration
    "js": "subagent",         # Fast JS analysis
    "subdomain": "subagent",   # Fast DNS enumeration
    "xss": "claude",          # Needs browser + reasoning
    "sqli": "claude",         # Needs browser + reasoning
    "ssrf": "claude",         # Needs browser + reasoning
    "bac": "claude",          # Complex auth logic
    "auth": "claude",         # Complex auth testing
    "all": "claude",          # Needs planning
    "complex": "claude",      # Deep analysis
    "exploit_dev": "claude",  # Complex exploit building
    "architecture": "claude",   # Deep design analysis
}

# Task type metadata
TASK_INFO = {
    "xss": {"emoji": "🕷️", "name": "XSS", "runtime": "claude"},
    "sqli": {"emoji": "💉", "name": "SQL Injection", "runtime": "claude"},
    "ssrf": {"emoji": "🌐", "name": "SSRF", "runtime": "claude"},
    "bac": {"emoji": "🔓", "name": "Broken Access Control", "runtime": "claude"},
    "fuzz": {"emoji": "💥", "name": "Web Fuzzing", "runtime": "subagent"},
    "recon": {"emoji": "🔍", "name": "Reconnaissance", "runtime": "subagent"},
    "js": {"emoji": "📜", "name": "JS Analysis", "runtime": "subagent"},
    "subdomain": {"emoji": "🌍", "name": "Subdomain Enum", "runtime": "subagent"},
    "all": {"emoji": "🎯", "name": "Full Hunt", "runtime": "claude"},
}


def ensure_dirs():
    """Create necessary directories."""
    os.makedirs(ORCHESTRATOR_DIR, exist_ok=True)
    os.makedirs(FINDINGS_DIR, exist_ok=True)


def load_state():
    """Load current state from JSON file."""
    ensure_dirs()
    if not os.path.exists(STATE_FILE):
        return {
            "version": "1.0",
            "targets": {},
            "findings": [],
            "active_agents": [],
            "last_updated": None
        }
    with open(STATE_FILE, 'r') as f:
        return json.load(f)


def save_state(state):
    """Save state to JSON file with locking."""
    ensure_dirs()
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)
