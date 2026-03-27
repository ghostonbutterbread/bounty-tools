"""
Ghost Orchestrator Package — Unified hunting orchestration for bug bounty.

Usage:
    # As module
    from orchestrator import hunt, spawn_agent, AgentRuntime
    
    result = hunt("acme", tasks=["xss", "bac"], runtime=AgentRuntime.CLAUDE)
    
    # CLI
    python -m orchestrator status
    python -m orchestrator hunt acme --tasks xss,bac
"""

import sys

sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

# Core exports
from .state_manager import StateManager, state_mgr
from .findings_store import (
    save_finding, load_all_findings, generate_report,
    create_finding, get_findings_summary
)
from .context_prep import (
    prep_recon_context, prep_test_context,
    format_context_for_agent, categorize_urls
)
from .config import (
    ensure_dirs, CHROME_PORTS, MODEL_BY_TASK,
    SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4, SEVERITY_P5,
    RUNTIMES
)

# Agent spawning (includes AgentRuntime)
from .spawn import (
    spawn_agent, run_agent, spawn_parallel_agents,
    AgentRuntime,
)

# Hunt workflow
from .hunt import hunt, parse_findings_from_output, get_bac_tests

# Telegram command interface
from .telegram_commands import handle_command

__version__ = "1.0.0"

__all__ = [
    # State
    "StateManager",
    "state_mgr",
    # Findings
    "save_finding",
    "load_all_findings",
    "generate_report",
    "create_finding",
    "get_findings_summary",
    # Context
    "prep_recon_context",
    "prep_test_context",
    "format_context_for_agent",
    "categorize_urls",
    # Config
    "ensure_dirs",
    "CHROME_PORTS",
    "MODEL_BY_TASK",
    "SEVERITY_P1",
    "SEVERITY_P2",
    "SEVERITY_P3",
    "SEVERITY_P4",
    "SEVERITY_P5",
    "AgentRuntime",
    "RUNTIMES",
    # Agents
    "spawn_agent",
    "run_agent",
    "spawn_parallel_agents",
    # Hunt
    "hunt",
    "parse_findings_from_output",
    "get_bac_tests",
    # Telegram
    "handle_command",
]