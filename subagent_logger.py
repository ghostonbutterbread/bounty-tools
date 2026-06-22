#!/usr/bin/env python3
"""
Sub-Agent Logger — Audit trail for all sub-agent runs.
Logs to ~/.openclaw/logs/{tool}/{date}.log

Usage:
    from subagent_logger import SubagentLogger
    log = SubagentLogger("fuzz", "acme")
    log.start(target="https://example.com", mode="dir")
    log.step("Running ffuf scan...")
    log.result("Found 15 interesting endpoints")
    log.finish(success=True)
"""

import json
import math
import os
import sys
import traceback
import uuid
from pathlib import Path
from datetime import date, datetime, timezone
from dataclasses import dataclass, asdict
from typing import Any, Optional

DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"
BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))


def _log_base() -> Path:
    return Path.home() / ".openclaw" / "logs"


def _trace_base(program: str, *, family: str = DEFAULT_CORE_FAMILY, lane: str = DEFAULT_CORE_LANE) -> Path:
    safe_program = str(program or "general").lower().replace(" ", "_")
    try:
        from bounty_core import resolve_storage
    except Exception:
        if BOUNTY_CORE_PATH.exists() and str(BOUNTY_CORE_PATH) not in sys.path:
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
        try:
            from bounty_core import resolve_storage
        except Exception:
            return Path.home() / "Shared" / family / safe_program / lane / "ledgers" / "traces"
    layout = resolve_storage(safe_program, family=family, lane=lane, create=False)
    return layout.ledgers_root / "traces"


def estimate_tokens(size_bytes: int | float | None) -> int:
    """Best-effort token estimate used when exact tokenizer data is unavailable."""
    if size_bytes is None:
        return 0
    try:
        numeric = int(size_bytes)
    except (TypeError, ValueError):
        return 0
    return max(0, math.ceil(numeric / 4))


def compute_pte_lite(
    *,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    tool_output_tokens: int | None = None,
    spawn_prefill_tokens: int | None = None,
    context_tokens_after: int | None = None,
    context_overhang_tokens: int | None = None,
    soft_context_limit_tokens: int = 32000,
) -> int:
    """Compute the PTE-lite approximation from the design doc."""
    prompt = max(0, int(prompt_tokens or 0))
    completion = max(0, int(completion_tokens or 0))
    tool_replay = max(0, int(tool_output_tokens or 0))
    spawn_prefill = max(0, int(spawn_prefill_tokens or 0))
    if context_overhang_tokens is None:
        context_after = max(0, int(context_tokens_after or 0))
        overhang = max(0, context_after - max(0, int(soft_context_limit_tokens or 0)))
    else:
        overhang = max(0, int(context_overhang_tokens or 0))
    return prompt + completion + tool_replay + spawn_prefill + overhang


@dataclass
class LogEntry:
    timestamp: str
    level: str          # START, STEP, RESULT, ERROR, FINISH
    tool: str
    agent_id: str       # session key or thread id
    run_id: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    parent_span_id: Optional[str] = None
    span_type: Optional[str] = None  # run, spawn_decision, model, tool, finding
    phase: Optional[str] = None      # preflight, agent_run, review, ledger
    agent_name: Optional[str] = None
    tool_name: Optional[str] = None
    tool_category: Optional[str] = None
    model_name: Optional[str] = None
    target: Optional[str] = None
    params: Optional[dict] = None
    message: Optional[str] = None
    duration_ms: Optional[int] = None
    success: Optional[bool] = None
    findings_count: Optional[int] = None
    error: Optional[str] = None
    parent_run_id: Optional[str] = None  # links child sub-agent logs to parent spawn event
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    cached_tokens_read: Optional[int] = None
    cached_tokens_written: Optional[int] = None
    context_tokens_before: Optional[int] = None
    context_tokens_after: Optional[int] = None
    tool_output_tokens: Optional[int] = None
    tool_output_reused: Optional[bool] = None
    spawn_prefill_tokens: Optional[int] = None
    context_overhang_tokens: Optional[int] = None
    pte_lite: Optional[int] = None
    latency_ms: Optional[int] = None
    input_bytes: Optional[int] = None
    output_bytes: Optional[int] = None
    output_tokens_est: Optional[int] = None
    fed_back_to_model: Optional[bool] = None
    pte_replay_cost: Optional[int] = None
    redundancy_penalty: Optional[float] = None
    historical_worth: Optional[float] = None
    expected_worth: Optional[float] = None
    finding_fid: Optional[str] = None
    review_tier: Optional[str] = None
    duplicate: Optional[bool] = None
    finding_reward: Optional[float] = None
    allocated_pte_lite: Optional[int] = None
    chain_enabler: Optional[bool] = None


class SubagentLogger:
    """
    Logs sub-agent runs to ~/.openclaw/logs/{tool}/{date}.log
    
    Each run gets a unique run_id, and all steps are grouped together.
    Logs are JSONL format (one JSON object per line).
    
    Also creates a human-readable summary file alongside the JSONL.
    """
    
    def __init__(
        self,
        tool: str,
        program: str = "general",
        agent_id: Optional[str] = None,
        *,
        family: str = DEFAULT_CORE_FAMILY,
        lane: str = DEFAULT_CORE_LANE,
    ):
        self.tool = tool.lower()
        self.program = program.lower().replace(" ", "_")
        self.family = family
        self.lane = lane
        self.agent_id = agent_id or f"agent_{datetime.now().strftime('%H%M%S')}"
        self.run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.trace_id = f"{self.tool}_{self.run_id}_{uuid.uuid4().hex[:8]}"
        self.start_time = datetime.now()
        self.log_dir = _log_base() / self.tool
        self.log_file = self.log_dir / f"{self.program}_{date.today().isoformat()}.logl"
        self.summary_file = self.log_dir / f"{self.program}_{date.today().isoformat()}.summary"
        self.trace_dir = _trace_base(self.program, family=family, lane=lane)
        self.trace_file = self.trace_dir / f"{self.run_id}.jsonl"
        self._steps = []
        self._findings_count = 0
        self._active = True
        
        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.trace_dir.mkdir(parents=True, exist_ok=True)

    def _coerce_int(self, value: Any) -> Optional[int]:
        if value in ("", None):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _normalize_fields(self, fields: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(fields)
        for key in (
            "prompt_tokens",
            "completion_tokens",
            "cached_tokens_read",
            "cached_tokens_written",
            "context_tokens_before",
            "context_tokens_after",
            "tool_output_tokens",
            "spawn_prefill_tokens",
            "context_overhang_tokens",
            "pte_lite",
            "latency_ms",
            "input_bytes",
            "output_bytes",
            "output_tokens_est",
            "pte_replay_cost",
            "allocated_pte_lite",
            "duration_ms",
        ):
            if key in normalized:
                normalized[key] = self._coerce_int(normalized.get(key))

        if normalized.get("output_tokens_est") is None and normalized.get("output_bytes") is not None:
            normalized["output_tokens_est"] = estimate_tokens(normalized["output_bytes"])

        if normalized.get("tool_output_tokens") is None and normalized.get("output_bytes") is not None:
            normalized["tool_output_tokens"] = estimate_tokens(normalized["output_bytes"])

        if normalized.get("pte_lite") is None and any(
            normalized.get(key) is not None
            for key in (
                "prompt_tokens",
                "completion_tokens",
                "tool_output_tokens",
                "spawn_prefill_tokens",
                "context_tokens_after",
                "context_overhang_tokens",
            )
        ):
            normalized["pte_lite"] = compute_pte_lite(
                prompt_tokens=normalized.get("prompt_tokens"),
                completion_tokens=normalized.get("completion_tokens"),
                tool_output_tokens=normalized.get("tool_output_tokens"),
                spawn_prefill_tokens=normalized.get("spawn_prefill_tokens"),
                context_tokens_after=normalized.get("context_tokens_after"),
                context_overhang_tokens=normalized.get("context_overhang_tokens"),
            )

        normalized.setdefault("run_id", self.run_id)
        normalized.setdefault("trace_id", self.trace_id)
        normalized.setdefault("agent_name", self.tool)
        return normalized

    def _make_entry(self, *, level: str, message: Optional[str] = None, **fields: Any) -> LogEntry:
        normalized = self._normalize_fields(fields)
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            level=level,
            tool=self.tool,
            agent_id=self.agent_id,
            message=message,
            **normalized,
        )

    def _write(self, entry: LogEntry) -> None:
        """Write a JSONL entry to the legacy log file and the program trace file."""
        if not self._active:
            return
        try:
            payload = asdict(entry)
            line = json.dumps(payload) + "\n"
            with open(self.log_file, "a", encoding="utf-8") as handle:
                handle.write(line)
            with open(self.trace_file, "a", encoding="utf-8") as handle:
                handle.write(line)
        except Exception as e:
            print(f"[subagent_logger] Failed to write log: {e}", file=sys.stderr)
    
    def _update_summary(self, status: str, message: str) -> None:
        """Update the human-readable summary file."""
        try:
            lines = []
            if self.summary_file.exists():
                lines = self.summary_file.read_text().strip().split("\n")
            
            # Replace or append the current run entry
            new_entry = (
                f"[{datetime.now().strftime('%H:%M:%S')}] [{status}] "
                f"{self.tool} | {self.program} | {self.agent_id} | {self.run_id} | {message}"
            )
            
            # Find existing entry for this run_id
            found = False
            new_lines = []
            for line in lines:
                if self.run_id in line:
                    new_lines.append(new_entry)
                    found = True
                else:
                    new_lines.append(line)
            
            if not found:
                new_lines.append(new_entry)
            
            # Keep last 100 entries
            new_lines = new_lines[-100:]
            
            self.summary_file.write_text("\n".join(new_lines) + "\n")
        except Exception as e:
            print(f"[subagent_logger] Failed to update summary: {e}", file=sys.stderr)
    
    # ─── Redaction ───────────────────────────────────────────────────────────────
    
    def _redact(self, text: str) -> str:
        """Redact sensitive values from text (tokens, passwords, API keys)."""
        import re
        if not text:
            return text
        # Redact common token patterns
        patterns = [
            (r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)', '***JWT***'),  # JWT tokens
            (r'(YA9h[A-Za-z0-9]+)', '***TOKEN***'),  # Similar auth tokens
            (r'(brfN[A-Za-z0-9]+)', '***TOKEN***'),  # Similar auth tokens
            (r'(Bearer |bearer )([A-Za-z0-9_-]+)', r'\1***TOKEN***'),
            (r'(password|pwd|passwd|secret)=([^\s&]+)', r'\1=***REDACTED***'),
            (r'(api[_-]?key|apikey|key)=([^\s&]+)', r'\1=***REDACTED***'),
        ]
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        return text
    
    # ─── Logging Methods ───────────────────────────────────────────────────────
    
    def start(self, target: str, parent_run_id: Optional[str] = None, **params) -> None:
        """Log the start of a sub-agent run. Pass parent_run_id if this was spawned by a parent agent."""
        params = dict(params)
        span_type = params.pop("span_type", "run")
        phase = params.get("phase", "agent_run")
        self._params = params
        self._target = target
        self.parent_run_id = parent_run_id
        entry = self._make_entry(
            level="START",
            target=target,
            params=params,
            parent_run_id=parent_run_id,
            span_type=span_type,
            phase=phase,
            message=f"Started {self.tool} on {target}",
            success=True,
        )
        self._write(entry)
        self._update_summary("START", f"target={target}")
        redacted_target = self._redact(target)
        print(f"[{self.run_id}] START: {self.tool} | {self.program} | {redacted_target}", flush=True)

    def step(self, message: str, **fields: Any) -> None:
        """Log a step in the agent's work."""
        entry = self._make_entry(level="STEP", message=message, **fields)
        self._write(entry)
        self._steps.append(message)
        print(f"[{self.run_id}] STEP: {message}", flush=True)

    def result(self, message: str, findings_count: Optional[int] = None, **fields: Any) -> None:
        """Log a result or finding."""
        if findings_count is not None:
            self._findings_count = findings_count
        entry = self._make_entry(
            level="RESULT",
            message=message,
            findings_count=findings_count,
            **fields,
        )
        self._write(entry)
        self._update_summary("RESULT", message)
        print(f"[{self.run_id}] RESULT: {self._redact(message)}", flush=True)

    def error(self, message: str, exc: Optional[Exception] = None, **fields: Any) -> None:
        """Log an error."""
        error_msg = message
        if exc:
            error_msg = f"{message}: {exc}\n{traceback.format_exc()}"
        entry = self._make_entry(level="ERROR", message=message, error=error_msg, success=False, **fields)
        self._write(entry)
        self._update_summary("ERROR", message)
        print(f"[{self.run_id}] ERROR: {self._redact(message)}", file=sys.stderr, flush=True)

    def finish(self, success: bool = True, summary: Optional[str] = None, **fields: Any) -> None:
        """Log the completion of a sub-agent run."""
        duration_ms = int((datetime.now() - self.start_time).total_seconds() * 1000)
        phase = fields.pop("phase", "agent_run")
        entry = self._make_entry(
            level="FINISH",
            target=getattr(self, "_target", None),
            duration_ms=duration_ms,
            success=success,
            findings_count=self._findings_count,
            parent_run_id=getattr(self, "parent_run_id", None),
            span_type=fields.pop("span_type", "run"),
            phase=phase,
            message=summary or f"{'Completed successfully' if success else 'Failed'} — {len(self._steps)} steps, {self._findings_count} findings",
            **fields,
        )
        self._write(entry)
        status = "OK" if success else "FAIL"
        self._update_summary(status, f"duration={duration_ms}ms findings={self._findings_count}")
        print(f"[{self.run_id}] FINISH: {status} | {duration_ms}ms | {self._findings_count} findings", flush=True)
        self._active = False

    def log_span(self, span_type: str, level: str = "STEP", message: Optional[str] = None, **fields: Any) -> None:
        """Emit an arbitrary structured span while keeping legacy logs intact."""
        entry = self._make_entry(level=level, message=message, span_type=span_type, **fields)
        self._write(entry)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.error(str(exc_val), exc_val)
            self.finish(success=False)
        return False


# ─── CLI: View Logs ─────────────────────────────────────────────────────────

def view_logs(tool: Optional[str] = None, program: Optional[str] = None, limit: int = 20):
    """Print recent log entries, optionally filtered by tool/program."""
    base = _log_base() if not tool else _log_base() / tool.lower()
    
    if not base.exists():
        print(f"No logs found at {base}")
        return
    
    log_files = []
    if program:
        today = date.today().isoformat()
        f = base / f"{program}_{today}.logl"
        if f.exists():
            log_files = [f]
        else:
            log_files = list(base.glob(f"{program}_*.logl"))
    else:
        log_files = sorted(base.rglob("*.logl"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]
    
    count = 0
    for lf in log_files:
        print(f"\n{'='*60}")
        print(f"📄 {lf}")
        print('='*60)
        lines = lf.read_text().strip().split("\n")
        for line in lines[-limit:]:
            try:
                obj = json.loads(line)
                ts = obj.get("timestamp", "")[11:19]
                level = obj.get("level", "")
                msg = obj.get("message", "")
                target = obj.get("target", "")
                dur = obj.get("duration_ms", "")
                
                icons = {"START": "▶", "STEP": "  ├", "RESULT": "  └", "ERROR": "❌", "FINISH": "🏁"}
                icon = icons.get(level, "  ")
                
                if level == "START":
                    print(f"{icon} [{ts}] {msg}")
                elif level == "FINISH":
                    status = "✅" if obj.get("success") else "❌"
                    print(f"{icon} [{ts}] {status} {msg} ({dur}ms)")
                elif level == "STEP":
                    print(f"{icon} {msg}")
                elif level == "RESULT":
                    print(f"{icon} {msg}")
                elif level == "ERROR":
                    print(f"{icon} [{ts}] ❌ {msg}")
                
                count += 1
            except:
                pass
    
    print(f"\nTotal entries shown: {count}")

def cleanup_logs(days: int = 30, dry_run: bool = False):
    """
    Remove log files older than `days` days.
    Default: 30 days (one month).
    
    Args:
        days: Remove logs older than this many days (default: 30)
        dry_run: If True, only print what would be deleted
    """
    base = _log_base()
    if not base.exists():
        print("No logs directory found.")
        return
    
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    total_size = 0
    
    for log_file in base.rglob("*.logl"):
        mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
        if mtime < cutoff:
            size = log_file.stat().st_size
            if dry_run:
                print(f"  Would remove: {log_file} ({size:,} bytes, {mtime.date()})")
            else:
                log_file.unlink()
                # Also remove matching summary
                summary = log_file.with_suffix(".summary")
                if summary.exists():
                    summary.unlink()
                print(f"  Removed: {log_file.name} ({size:,} bytes)")
            removed += 1
            total_size += size
    
    # Clean empty directories
    for d in sorted(base.rglob("*"), key=lambda p: str(p), reverse=True):
        if d.is_dir() and not any(d.iterdir()):
            if dry_run:
                print(f"  Would remove empty dir: {d}")
            else:
                d.rmdir()
    
    if dry_run:
        print(f"\n[dry run] Would remove {removed} files ({total_size:,} bytes)")
    else:
        print(f"\nCleaned {removed} files ({total_size:,} bytes), kept logs from last {days} days")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Sub-Agent Logger CLI")
    sub = parser.add_subparsers(dest="cmd")
    
    p_view = sub.add_parser("view", help="View recent logs")
    p_view.add_argument("--tool", help="Filter by tool (e.g. fuzz, bac, recon)")
    p_view.add_argument("--program", help="Filter by program (e.g. acme)")
    p_view.add_argument("--limit", type=int, default=20, help="Lines per file (default: 20)")
    
    p_tail = sub.add_parser("tail", help="Tail a log file in real-time")
    p_tail.add_argument("tool", help="Tool name")
    p_tail.add_argument("program", nargs="?", help="Program name")
    
    p_clean = sub.add_parser("cleanup", help="Clean old log files")
    p_clean.add_argument("--days", type=int, default=30, help="Remove logs older than N days (default: 30)")
    p_clean.add_argument("--dry-run", action="store_true", help="Show what would be deleted without deleting")
    
    args = parser.parse_args()
    
    if args.cmd == "view":
        view_logs(args.tool, args.program, args.limit)
    elif args.cmd == "tail":
        import time
        log_dir = _log_base() / args.tool.lower()
        today = date.today().isoformat()
        if args.program:
            log_file = log_dir / f"{args.program}_{today}.logl"
        else:
            files = sorted(log_dir.glob("*.logl"), key=lambda p: p.stat().st_mtime, reverse=True)
            log_file = files[0] if files else None
        
        if not log_file or not log_file.exists():
            print(f"No log file found: {log_file}")
        else:
            print(f"Tailing {log_file}... (Ctrl+C to stop)")
            with open(log_file) as f:
                f.seek(0, 2)  # seek to end
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    try:
                        obj = json.loads(line)
                        print(f"[{obj.get('timestamp','')[11:19]}] {obj.get('level',''):6} | {obj.get('message','')}")
                    except:
                        print(line.strip())
    elif args.cmd == "cleanup":
        cleanup_logs(days=args.days, dry_run=args.dry_run)
    else:
        parser.print_help()
