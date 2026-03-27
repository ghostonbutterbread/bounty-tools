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

import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime, date
from dataclasses import dataclass, asdict
from typing import Optional

LOG_BASE = Path.home() / ".openclaw" / "logs"


@dataclass
class LogEntry:
    timestamp: str
    level: str          # START, STEP, RESULT, ERROR, FINISH
    tool: str
    agent_id: str       # session key or thread id
    target: Optional[str] = None
    params: Optional[dict] = None
    message: Optional[str] = None
    duration_ms: Optional[int] = None
    success: Optional[bool] = None
    findings_count: Optional[int] = None
    error: Optional[str] = None
    parent_run_id: Optional[str] = None  # links child sub-agent logs to parent spawn event


class SubagentLogger:
    """
    Logs sub-agent runs to ~/.openclaw/logs/{tool}/{date}.log
    
    Each run gets a unique run_id, and all steps are grouped together.
    Logs are JSONL format (one JSON object per line).
    
    Also creates a human-readable summary file alongside the JSONL.
    """
    
    def __init__(self, tool: str, program: str = "general", agent_id: Optional[str] = None):
        self.tool = tool.lower()
        self.program = program.lower().replace(" ", "_")
        self.agent_id = agent_id or f"agent_{datetime.now().strftime('%H%M%S')}"
        self.run_id = f"{self.tool}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.start_time = datetime.now()
        self.log_dir = LOG_BASE / self.tool
        self.log_file = self.log_dir / f"{self.program}_{date.today().isoformat()}.logl"
        self.summary_file = self.log_dir / f"{self.program}_{date.today().isoformat()}.summary"
        self._steps = []
        self._findings_count = 0
        self._active = True
        
        # Create log directory
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def _write(self, entry: LogEntry) -> None:
        """Write a JSONL entry to the log file."""
        if not self._active:
            return
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(asdict(entry)) + "\n")
        except Exception as e:
            print(f"[subagent_logger] Failed to write log: {e}", file=sys.stderr)
    
    def _update_summary(self, status: str, message: str) -> None:
        """Update the human-readable summary file."""
        try:
            lines = []
            if self.summary_file.exists():
                lines = self.summary_file.read_text().strip().split("\n")
            
            # Replace or append the current run entry
            new_entry = f"[{datetime.now().strftime('%H:%M:%S')}] [{status}] {self.tool} | {self.program} | {self.agent_id} | {message}"
            
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
        self._params = params
        self._target = target
        self.parent_run_id = parent_run_id
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="START",
            tool=self.tool,
            agent_id=self.agent_id,
            target=target,
            params=params,
            message=f"Started {self.tool} on {target}",
            parent_run_id=parent_run_id
        )
        self._write(entry)
        self._update_summary("START", f"target={target}")
        redacted_target = self._redact(target)
        print(f"[{self.run_id}] START: {self.tool} | {self.program} | {redacted_target}", flush=True)
    
    def step(self, message: str) -> None:
        """Log a step in the agent's work."""
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="STEP",
            tool=self.tool,
            agent_id=self.agent_id,
            message=message
        )
        self._write(entry)
        self._steps.append(message)
        print(f"[{self.run_id}] STEP: {message}", flush=True)
    
    def result(self, message: str, findings_count: Optional[int] = None) -> None:
        """Log a result or finding."""
        if findings_count is not None:
            self._findings_count = findings_count
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="RESULT",
            tool=self.tool,
            agent_id=self.agent_id,
            message=message,
            findings_count=findings_count
        )
        self._write(entry)
        self._update_summary("RESULT", message)
        print(f"[{self.run_id}] RESULT: {self._redact(message)}", flush=True)
    
    def error(self, message: str, exc: Optional[Exception] = None) -> None:
        """Log an error."""
        error_msg = message
        if exc:
            error_msg = f"{message}: {exc}\n{traceback.format_exc()}"
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="ERROR",
            tool=self.tool,
            agent_id=self.agent_id,
            message=message,
            error=error_msg
        )
        self._write(entry)
        self._update_summary("ERROR", message)
        print(f"[{self.run_id}] ERROR: {self._redact(message)}", file=sys.stderr, flush=True)
    
    def finish(self, success: bool = True, summary: Optional[str] = None) -> None:
        """Log the completion of a sub-agent run."""
        duration_ms = int((datetime.now() - self.start_time).total_seconds() * 1000)
        entry = LogEntry(
            timestamp=datetime.now().isoformat(),
            level="FINISH",
            tool=self.tool,
            agent_id=self.agent_id,
            target=self._target,
            duration_ms=duration_ms,
            success=success,
            findings_count=self._findings_count,
            parent_run_id=getattr(self, 'parent_run_id', None),
            message=summary or f"{'Completed successfully' if success else 'Failed'} — {len(self._steps)} steps, {self._findings_count} findings"
        )
        self._write(entry)
        status = "OK" if success else "FAIL"
        self._update_summary(status, f"duration={duration_ms}ms findings={self._findings_count}")
        print(f"[{self.run_id}] FINISH: {status} | {duration_ms}ms | {self._findings_count} findings", flush=True)
        self._active = False
    
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
    base = LOG_BASE if not tool else LOG_BASE / tool.lower()
    
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


# ─── Log Cleanup ───────────────────────────────────────────────────────────

def cleanup_logs(days: int = 30, dry_run: bool = False):
    """
    Remove log files older than `days` days.
    Default: 30 days (one month).
    
    Args:
        days: Remove logs older than this many days (default: 30)
        dry_run: If True, only print what would be deleted
    """
    if not LOG_BASE.exists():
        print("No logs directory found.")
        return
    
    from datetime import timedelta
    cutoff = datetime.now() - timedelta(days=days)
    removed = 0
    total_size = 0
    
    for log_file in LOG_BASE.rglob("*.logl"):
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
    for d in sorted(LOG_BASE.rglob("*"), key=lambda p: str(p), reverse=True):
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
        log_dir = LOG_BASE / args.tool.lower()
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
