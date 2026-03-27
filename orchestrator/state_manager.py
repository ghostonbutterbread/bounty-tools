"""
State Manager — Thread-safe state management with file locking.
"""

import json
import os
import fcntl
from datetime import datetime
from pathlib import Path

# Import from config
try:
    from .config import STATE_FILE, ensure_dirs
except ImportError:
    # Fallback if config not yet loaded
    _ORCHESTRATOR_DIR = os.path.expanduser("~/Shared/bounty_recon/orchestrator")
    STATE_FILE = os.path.join(_ORCHESTRATOR_DIR, "state.json")
    def ensure_dirs():
        os.makedirs(_ORCHESTRATOR_DIR, exist_ok=True)


class StateManager:
    """Thread-safe state management with file locking."""

    def __init__(self, state_file: str = None):
        ensure_dirs()
        self.state_file = state_file or STATE_FILE
        self.lock_file = self.state_file + ".lock"

    def _acquire_lock(self, timeout: float = 10.0):
        """Acquire exclusive file lock with timeout (non-blocking with retry)."""
        import time
        self._lock_fd = open(self.lock_file, 'w')
        start = time.time()
        while True:
            try:
                fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return  # Got the lock
            except BlockingIOError:
                if time.time() - start >= timeout:
                    self._lock_fd.close()
                    raise TimeoutError(f"Could not acquire lock on {self.lock_file} within {timeout}s")
                time.sleep(0.1)

    def _release_lock(self):
        """Release file lock."""
        if hasattr(self, '_lock_fd') and self._lock_fd:
            fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
            self._lock_fd.close()
            self._lock_fd = None

    def read(self) -> dict:
        """Read current state (thread-safe)."""
        self._acquire_lock()
        try:
            if not os.path.exists(self.state_file):
                return self._empty_state()
            with open(self.state_file, 'r') as f:
                return json.load(f)
        finally:
            self._release_lock()

    def write(self, state: dict) -> None:
        """Write state with timestamp (thread-safe)."""
        state["last_updated"] = datetime.now().isoformat()
        self._acquire_lock()
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        finally:
            self._release_lock()

    def update(self, updater_func) -> None:
        """Atomically update state using a function.

        Usage:
            state_mgr.update(lambda s: s["findings"].append(new_finding))
        """
        self._acquire_lock()
        try:
            if not os.path.exists(self.state_file):
                state = self._empty_state()
            else:
                with open(self.state_file, 'r') as f:
                    state = json.load(f)

            updater_func(state)
            state["last_updated"] = datetime.now().isoformat()

            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        finally:
            self._release_lock()

    @staticmethod
    def _empty_state() -> dict:
        return {
            "version": "1.0",
            "targets": {},
            "findings": [],
            "active_agents": [],
            "last_updated": None
        }

    # ─── Target Management ───────────────────────────────────────────────────

    def add_target(self, program_name: str, scope: list = None, accounts: list = None) -> None:
        """Add a new target program."""
        self.update(lambda s: s["targets"].update({
            program_name: {
                "name": program_name,
                "scope": scope or [],
                "accounts": accounts or [],
                "test_history": [],
                "created_at": datetime.now().isoformat(),
                "last_tested": None
            }
        }))

    def get_target(self, program_name: str) -> dict:
        """Get target by name."""
        state = self.read()
        return state["targets"].get(program_name)

    def add_tested_endpoint(self, program_name: str, endpoint: str, vuln_type: str, result: str) -> None:
        """Log a tested endpoint."""
        def _update(s):
            if program_name not in s["targets"]:
                return
            s["targets"][program_name]["test_history"].append({
                "endpoint": endpoint,
                "vuln_type": vuln_type,
                "result": result,
                "tested_at": datetime.now().isoformat()
            })
            s["targets"][program_name]["last_tested"] = datetime.now().isoformat()
        self.update(_update)

    # ─── Finding Management ──────────────────────────────────────────────────

    def add_finding(self, finding: dict) -> None:
        """Add a new finding with deduplication check."""
        # Make a copy at call time so nested function can safely modify
        finding_copy = dict(finding)

        def _update(s):
            # Deduplicate by target + endpoint + vuln_type
            for existing in s["findings"]:
                if (existing.get("target") == finding_copy.get("target") and
                    existing.get("endpoint") == finding_copy.get("endpoint") and
                    existing.get("vuln_type") == finding_copy.get("vuln_type")):
                    return  # Already exists, skip

            finding_copy["id"] = len(s["findings"]) + 1
            finding_copy.setdefault("status", "new")
            finding_copy["added_at"] = datetime.now().isoformat()
            s["findings"].append(finding_copy)
        self.update(_update)

    def get_findings(self, target: str = None, vuln_type: str = None, status: str = None) -> list:
        """Query findings with filters."""
        state = self.read()
        findings = state["findings"]

        if target:
            findings = [f for f in findings if f.get("target") == target]
        if vuln_type:
            findings = [f for f in findings if f.get("vuln_type") == vuln_type]
        if status:
            findings = [f for f in findings if f.get("status") == status]

        return findings

    def update_finding_status(self, finding_id: int, new_status: str, notes: str = None) -> None:
        """Update finding status (new -> confirmed -> reported -> duplicate)."""
        def _update(s):
            for f in s["findings"]:
                if f.get("id") == finding_id:
                    f["status"] = new_status
                    if notes:
                        f["notes"] = notes
                    f["updated_at"] = datetime.now().isoformat()
        self.update(_update)

    # ─── Agent Management ────────────────────────────────────────────────────

    def register_agent(self, agent_id: str, task: str, target: str) -> None:
        """Register an active agent."""
        def _update(s):
            # Remove stale entry for this agent_id first
            s["active_agents"] = [a for a in s["active_agents"] if a.get("agent_id") != agent_id]
            s["active_agents"].append({
                "agent_id": agent_id,
                "task": task,
                "target": target,
                "started_at": datetime.now().isoformat()
            })
        self.update(_update)

    def unregister_agent(self, agent_id: str) -> None:
        """Remove an agent from active list."""
        def _update(s):
            s["active_agents"] = [a for a in s["active_agents"] if a.get("agent_id") != agent_id]
        self.update(_update)

    def get_active_agents(self) -> list:
        """Get all active agents."""
        state = self.read()
        return state["active_agents"]


# Singleton instance
state_mgr = StateManager()
