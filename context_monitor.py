#!/usr/bin/env python3
"""
Context Budget Monitor

Checks OpenClaw session history, identifies high-message sessions, and writes a
focused markdown snapshot before context compaction discards useful details.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SNAPSHOT_VERSION = 2
CLEANUP_DAYS_LOW = 7
CLEANUP_DAYS_MEDIUM = 30
CLEANUP_DAYS_HIGH = 90
ARCHIVE_DIR = os.path.expanduser("~/memory/snapshots/archive/")

MESSAGE_THRESHOLD = 80
MAX_TRANSCRIPT_MESSAGES = 1000
SNAPSHOT_DIR = os.path.expanduser("~/memory/snapshots/")
ARCHIVE_DIR = "~/memory/snapshots/archive/"
CLEANUP_DAYS_LOW = 7
CLEANUP_DAYS_MEDIUM = 30
CLEANUP_DAYS_HIGH = 90

PRIORITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
LOW_PRIORITY_HINTS = ("resolved", "closed", "fixed", "done", "completed")
MEDIUM_PRIORITY_HINTS = ("paused", "deferred", "later", "backlog")

PHASES = ("recon", "testing", "analysis", "reporting", "stuck")
VULNERABILITY_KEYWORDS = (
    "xss",
    "csrf",
    "ssrf",
    "sqli",
    "idor",
    "rce",
    "lfi",
    "ssti",
    "html injection",
    "prototype pollution",
    "auth bypass",
    "account takeover",
    "race condition",
    "open redirect",
    "xxe",
)
CODE_PATH_RE = re.compile(r"(~|/)[^\s`\"']+\.(?:py|js|ts|tsx|jsx|md|json|sh|rb|go|php|java|kt|swift|yml|yaml)")
FILE_NAME_RE = re.compile(r"\b[\w./-]+\.(?:py|js|ts|tsx|jsx|md|json|sh|rb|go|php|java|kt|swift|yml|yaml)\b")
LINE_REF_RE = re.compile(r"\b(?:line|lines|module)\s+\d[\d,-]*\b", re.IGNORECASE)
F_CODE_RE = re.compile(r"\bF\d{2,}\b")


@dataclass
class SessionRecord:
    key: str
    session_id: str
    updated_at: int
    kind: str
    agent_id: str
    session_file: Path | None
    message_count: int
    total_tokens: int
    context_tokens: int
    messages: list[dict]


@dataclass
class PrioritizedEntry:
    text: str
    priority: str
    reason: str
    label: str | None = None


def expand_path(path: str) -> Path:
    return Path(os.path.expanduser(path)).resolve()


def extract_json_blob(raw_output: str) -> dict:
    decoder = json.JSONDecoder()
    for idx, char in enumerate(raw_output):
        if char not in "[{":
            continue
        try:
            obj, _ = decoder.raw_decode(raw_output[idx:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
    raise ValueError("Could not find JSON payload in command output")


def run_sessions_list() -> dict:
    commands = (
        ["sessions_list", "--json"],
        ["openclaw", "sessions", "--json"],
    )
    last_error: Exception | None = None
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            last_error = exc
            continue
        except subprocess.CalledProcessError as exc:
            last_error = RuntimeError(exc.stderr.strip() or exc.stdout.strip() or str(exc))
            continue
        return extract_json_blob(completed.stdout)
    raise RuntimeError(f"Unable to run sessions listing: {last_error}")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def open_text_file(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def load_session_messages(session_file: Path | None) -> list[dict]:
    if not session_file or not session_file.exists():
        return []

    messages: list[dict] = []
    with open_text_file(session_file) as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("type") == "message" and isinstance(entry.get("message"), dict):
                messages.append(entry)
    return messages


def build_session_records() -> list[SessionRecord]:
    sessions_payload = run_sessions_list()
    store_path = Path(sessions_payload["path"])
    store = load_json(store_path)
    records: list[SessionRecord] = []

    for item in sessions_payload.get("sessions", []):
        store_entry = store.get(item["key"], {})
        session_file_raw = store_entry.get("sessionFile")
        session_file = Path(session_file_raw).expanduser() if session_file_raw else None
        messages = load_session_messages(session_file)
        records.append(
            SessionRecord(
                key=item.get("key", ""),
                session_id=item.get("sessionId", ""),
                updated_at=int(item.get("updatedAt") or 0),
                kind=item.get("kind", "unknown"),
                agent_id=item.get("agentId", ""),
                session_file=session_file,
                message_count=len(messages),
                total_tokens=int(item.get("totalTokens") or 0),
                context_tokens=int(item.get("contextTokens") or 0),
                messages=messages,
            )
        )

    records.sort(key=lambda record: record.updated_at, reverse=True)
    return records


def select_target_session(records: Iterable[SessionRecord]) -> SessionRecord | None:
    candidates = [record for record in records if record.message_count > 0 and ":run:" not in record.key]
    if not candidates:
        return None

    over_threshold = [record for record in candidates if record.message_count >= MESSAGE_THRESHOLD]
    if over_threshold:
        return max(over_threshold, key=lambda record: record.updated_at)
    return max(candidates, key=lambda record: record.updated_at)


def flatten_content_item(item: dict) -> str:
    item_type = item.get("type")
    if item_type == "text":
        return item.get("text", "")
    if item_type == "thinking":
        return ""
    if item_type == "toolCall":
        name = item.get("name", "tool")
        arguments = item.get("arguments", {})
        if isinstance(arguments, dict):
            preview = json.dumps(arguments, ensure_ascii=True, sort_keys=True)
        else:
            preview = str(arguments)
        return f"[tool call] {name} {preview}"
    if item_type == "toolResult":
        name = item.get("toolName", "tool")
        text_parts = []
        for part in item.get("content", []):
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(part.get("text", ""))
        joined = "\n".join(part for part in text_parts if part).strip()
        return f"[tool result] {name}\n{joined}".strip()
    return ""


def extract_message_text(entry: dict) -> str:
    message = entry.get("message", {})
    content = message.get("content", [])
    parts = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                text = flatten_content_item(item).strip()
                if text:
                    parts.append(text)
    elif isinstance(content, str):
        parts.append(content.strip())

    if not parts and message.get("role") == "toolResult":
        for part in message.get("content", []):
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text", "").strip()
                if text:
                    parts.append(text)

    return "\n".join(parts).strip()


def normalize_for_summary(text: str) -> str:
    cleaned = text
    cleaned = re.sub(r"Conversation info \(untrusted metadata\):\s*```.*?```", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"Sender \(untrusted metadata\):\s*```.*?```", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"^System: \[.*?\].*$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        normalized = " ".join(item.split())
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def infer_program(text_blob: str, code_context: list[str]) -> str:
    lowered = text_blob.lower()
    explicit = re.search(r"\b([A-Z][A-Za-z0-9]+)\s+AI Search\b", text_blob)
    if explicit:
        return explicit.group(1)

    path_blob = "\n".join(code_context)
    if "evernote" in lowered or "evernote" in path_blob.lower():
        return "Evernote"
    if "superdrug" in lowered or "superdrug" in path_blob.lower():
        return "Superdrug"

    path_match = re.search(r"/Shared/[^/\s]+/([^/\s]+)/[^/\s]+/(?:recon|reports|ledgers|context|working)/", path_blob)
    if path_match:
        return path_match.group(1).replace("_", " ").title()

    note_link = re.search(r"\[\[([a-z0-9_-]+)/", text_blob, re.IGNORECASE)
    if note_link:
        return note_link.group(1).replace("_", " ").title()

    title_match = re.search(r"##\s+([A-Za-z0-9 _-]+?)\s+[—-]\s+", text_blob)
    if title_match:
        return title_match.group(1).strip()

    return "Unknown"


def infer_vulnerability(text_blob: str) -> str:
    f_code = F_CODE_RE.search(text_blob)
    if f_code:
        label_match = re.search(rf"{re.escape(f_code.group(0))}\s+[—-]\s+([^\n]+)", text_blob)
        if label_match:
            return f"{f_code.group(0)} — {label_match.group(1).strip()}"
        return f_code.group(0)

    lowered = text_blob.lower()
    for keyword in VULNERABILITY_KEYWORDS:
        if keyword in lowered:
            return keyword.upper() if len(keyword) <= 4 else keyword.title()
    return "Unknown"


def infer_phase(text_blob: str) -> str:
    lowered = text_blob.lower()
    scores = {phase: 0 for phase in PHASES}
    for token in ("scan", "enumerate", "recon", "search results", "dork"):
        if token in lowered:
            scores["recon"] += 1
    for token in ("test", "payload", "fired", "try", "re-running audit"):
        if token in lowered:
            scores["testing"] += 1
    for token in ("analy", "audit", "review", "confirmed", "sink", "source"):
        if token in lowered:
            scores["analysis"] += 1
    for token in ("report", "writeup", "summary"):
        if token in lowered:
            scores["reporting"] += 1
    for token in ("stuck", "blocked", "unable", "portinuseerror", "didn't fire"):
        if token in lowered:
            scores["stuck"] += 1

    phase = max(scores, key=scores.get)
    return phase if scores[phase] > 0 else "analysis"


def collect_open_questions(lines: list[str]) -> list[str]:
    questions: list[str] = []
    capture_testing = False
    for line in lines:
        stripped = line.strip(" -*")
        if not stripped:
            capture_testing = False
            continue
        if stripped.lower().startswith("worth testing"):
            capture_testing = True
            continue
        if capture_testing and stripped:
            questions.append(stripped)
            continue
        if "?" in stripped:
            questions.append(stripped)
        elif stripped.lower().startswith(("need to find", "determine whether", "verify whether")):
            questions.append(stripped)
    return dedupe_keep_order(questions)[:8]


def collect_recent_findings(lines: list[str]) -> list[str]:
    findings: list[str] = []
    keywords = ("confirmed", "found", "sink", "source", "vulnerability", "alert didn't fire", "no client-side sanitization")
    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            continue
        if any(token in lowered for token in keywords):
            status = "confirmed" if any(token in lowered for token in ("confirmed", "found", "sink", "source")) else "noted"
            findings.append(f"{stripped}: {status}")
    return dedupe_keep_order(findings)[:8]


def collect_code_context(lines: list[str]) -> list[str]:
    entries: list[str] = []
    for line in lines:
        path_match = CODE_PATH_RE.search(line) or FILE_NAME_RE.search(line)
        if not path_match:
            continue
        path = path_match.group(0)
        line_ref = LINE_REF_RE.search(line)
        description = line.strip()
        if len(description) > 200:
            description = description[:197].rstrip() + "..."
        if line_ref:
            entries.append(f"File: {path} — {line_ref.group(0)} — {description}")
        else:
            entries.append(f"File: {path} — {description}")
    return dedupe_keep_order(entries)[:10]


def collect_pending_actions(lines: list[str]) -> list[str]:
    pending: list[str] = []
    for line in lines:
        stripped = line.strip(" -*")
        lowered = stripped.lower()
        if not stripped:
            continue
        if "not yet tried" in lowered or "needs to" in lowered or "need to" in lowered:
            owner = "Ryushe" if "ryushe" in lowered or "not yet tried" in lowered else "Agent"
            pending.append(f"[ ] {owner} action: {stripped}")
        elif any(token in lowered for token in ("next steps", "follow up", "build it", "re-running audit", "what to test")):
            owner = "Agent" if "audit" in lowered or "follow up" in lowered else "Ryushe"
            pending.append(f"[ ] {owner} action: {stripped}")
    return dedupe_keep_order(pending)[:8]


def summarize_status(findings: list[str], pending: list[str], lines: list[str]) -> str:
    status_bits: list[str] = []
    if findings:
        status_bits.append(findings[0].split(": ", 1)[0])
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in ("confirmed behavior", "status", "active", "current phase")):
            status_bits.append(line.strip())
            break
    if pending:
        status_bits.append(pending[0].replace("[ ] ", ""))
    status_bits = dedupe_keep_order(status_bits)
    if status_bits:
        return " | ".join(status_bits[:3])
    return "No active state identified from the latest session transcript."


def render_transcript(messages: list[dict], limit: int = MAX_TRANSCRIPT_MESSAGES) -> str:
    transcript_lines: list[str] = []
    for entry in messages[-limit:]:
        role = entry.get("message", {}).get("role", "unknown")
        timestamp = entry.get("timestamp", "")
        text = extract_message_text(entry).strip()
        if not text:
            continue
        transcript_lines.append(f"### {timestamp} [{role}]\n{text}")
    return "\n\n".join(transcript_lines).strip()


def timestamp_to_datetime(raw_timestamp: int) -> datetime:
    if raw_timestamp <= 0:
        return datetime.now(timezone.utc)
    if raw_timestamp > 10_000_000_000:
        raw_timestamp = raw_timestamp / 1000
    return datetime.fromtimestamp(raw_timestamp, tz=timezone.utc)


def base_priority_for_record(record: SessionRecord, now: datetime) -> tuple[str, str]:
    session_dt = timestamp_to_datetime(record.updated_at)
    age = now - session_dt.astimezone(now.tzinfo or timezone.utc)
    age_days = age.total_seconds() / 86400
    if age_days <= 1:
        return "HIGH", "last 24h"
    if age_days <= 7:
        return "MEDIUM", "last 7 days"
    return "LOW", "older context"


def max_priority(*levels: str) -> str:
    return max(levels, key=lambda level: PRIORITY_RANK[level])


def infer_entry_priority(text: str, section: str, base_level: str, base_reason: str, snapshot: dict) -> tuple[str, str]:
    lowered = text.lower()
    if any(token in lowered for token in LOW_PRIORITY_HINTS):
        return "LOW", "resolved or closed"

    if section == "pending_actions":
        if "ryushe" in lowered:
            return "HIGH", "pending Ryushe action"
        if any(token in lowered for token in MEDIUM_PRIORITY_HINTS):
            return "MEDIUM", "deferred action"
        return "HIGH", "pending action"

    if section == "open_questions":
        if any(token in lowered for token in ("blocking", "blocked", "unresolved")):
            return "HIGH", "blocking"
        if any(token in lowered for token in MEDIUM_PRIORITY_HINTS):
            return "MEDIUM", "deferred decision"
        return max_priority(base_level, "MEDIUM"), "open question"

    if section == "recent_findings":
        if any(token in lowered for token in ("confirmed", "found", "sink", "source", "vulnerability")):
            return "HIGH", "active finding"
        return base_level, base_reason

    if section == "code_context":
        if any(token in lowered for token in ("need to", "follow up", "todo")):
            return max_priority(base_level, "MEDIUM"), "relevant code path"
        return base_level, base_reason

    if section == "active_state_program":
        if snapshot["program"] != "Unknown" and (snapshot["pending_actions"] or snapshot["recent_findings"]):
            return "HIGH", "active investigation"
        return base_level, base_reason

    if section == "active_state_vulnerability":
        if snapshot["vulnerability"] != "Unknown":
            return "HIGH", "unresolved vulnerability"
        return base_level, base_reason

    if section == "active_state_phase":
        if snapshot["phase"] == "stuck":
            return "HIGH", "blocking"
        if snapshot["phase"] in ("recon", "testing", "analysis"):
            return max_priority(base_level, "MEDIUM"), "active phase"
        return base_level, base_reason

    if section == "active_state_status":
        status_lower = snapshot["status"].lower()
        if any(token in status_lower for token in ("blocked", "active", "confirmed")):
            return "HIGH", "active investigation"
        if snapshot["pending_actions"]:
            return "HIGH", "pending Ryushe action"
        return base_level, base_reason

    return base_level, base_reason


def prioritize_entries(
    items: list[str],
    section: str,
    base_level: str,
    base_reason: str,
    snapshot: dict,
    *,
    empty_value: str | None = None,
) -> list[PrioritizedEntry]:
    if not items and empty_value is not None:
        return [PrioritizedEntry(text=empty_value, priority="LOW", reason="no active item")]

    entries: list[PrioritizedEntry] = []
    for item in items:
        level, reason = infer_entry_priority(item, section, base_level, base_reason, snapshot)
        entries.append(PrioritizedEntry(text=item, priority=level, reason=reason))
    return entries


def build_active_state_entries(snapshot: dict, base_level: str, base_reason: str) -> list[PrioritizedEntry]:
    entries = [
        ("Program", snapshot["program"], "active_state_program"),
        ("Vulnerability", snapshot["vulnerability"], "active_state_vulnerability"),
        ("Current phase", snapshot["phase"], "active_state_phase"),
        ("Status", snapshot["status"], "active_state_status"),
    ]
    output: list[PrioritizedEntry] = []
    for label, text, section in entries:
        level, reason = infer_entry_priority(text, section, base_level, base_reason, snapshot)
        output.append(PrioritizedEntry(label=label, text=text, priority=level, reason=reason))
    return output
    output: list[PrioritizedEntry] = []
    for label, text, section in entries:
        level, reason = infer_entry_priority(text, section, base_level, base_reason, snapshot)
        output.append(PrioritizedEntry(label=label, text=text, priority=level, reason=reason))
    return "\n".join(lines())


def extract_snapshot_data(record: SessionRecord, now: datetime) -> dict:
    recent_messages = record.messages[-MAX_TRANSCRIPT_MESSAGES:]
    recent_texts = [
        normalize_for_summary(extract_message_text(message))
        for message in recent_messages
    ]
    lines = []
    for text in recent_texts:
        if not text:
            continue
        lines.extend(text.splitlines())

    code_context = collect_code_context(lines)
    findings = collect_recent_findings(lines)
    pending = collect_pending_actions(lines)
    text_blob = "\n".join(lines)
    base_level, base_reason = base_priority_for_record(record, now)

    if record.total_tokens > 0 and record.context_tokens > 0:
        context_pct = f"{round((record.total_tokens / record.context_tokens) * 100)}%"
    else:
        context_pct = f"{min(100, round((record.message_count / MESSAGE_THRESHOLD) * 100))}%"

    snapshot = {
        "program": infer_program(text_blob, code_context),
        "vulnerability": infer_vulnerability(text_blob),
        "phase": infer_phase(text_blob),
        "status": summarize_status(findings, pending, lines),
        "open_questions": collect_open_questions(lines),
        "recent_findings": findings,
        "code_context": code_context,
        "pending_actions": pending,
        "transcript": render_transcript(record.messages, MAX_TRANSCRIPT_MESSAGES),
        "generated": now.strftime("%Y-%m-%d_%H%M"),
        "context_pct": context_pct,
        "snapshot_version": SNAPSHOT_VERSION,
        "priority_threshold": base_level,
    }

    snapshot["active_state_entries"] = build_active_state_entries(snapshot, base_level, base_reason)
    snapshot["open_question_entries"] = prioritize_entries(
        snapshot["open_questions"],
        "open_questions",
        base_level,
        base_reason,
        snapshot,
        empty_value="None captured",
    )
    snapshot["recent_finding_entries"] = prioritize_entries(
        snapshot["recent_findings"],
        "recent_findings",
        base_level,
        base_reason,
        snapshot,
        empty_value="No explicit findings captured",
    )
    snapshot["code_context_entries"] = prioritize_entries(
        snapshot["code_context"],
        "code_context",
        base_level,
        base_reason,
        snapshot,
        empty_value="No code references captured",
    )
    snapshot["pending_action_entries"] = prioritize_entries(
        snapshot["pending_actions"],
        "pending_actions",
        base_level,
        base_reason,
        snapshot,
        empty_value="No pending actions captured",
    )

    all_priorities = [
        entry.priority
        for key in (
            "active_state_entries",
            "open_question_entries",
            "recent_finding_entries",
            "code_context_entries",
            "pending_action_entries",
        )
        for entry in snapshot[key]
    ]
    snapshot["priority_threshold"] = max(all_priorities, key=lambda level: PRIORITY_RANK[level])
    return snapshot


def has_active_state(snapshot: dict) -> bool:
    meaningful_lists = (
        snapshot["open_questions"],
        snapshot["recent_findings"],
        snapshot["code_context"],
        snapshot["pending_actions"],
    )
    if any(meaningful_lists):
        return True
    return snapshot["status"] != "No active state identified from the latest session transcript."


def load_latest_snapshot() -> str | None:
    snapshot_dir = expand_path(SNAPSHOT_DIR)
    if not snapshot_dir.exists():
        return None

    snapshots = sorted(snapshot_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not snapshots:
        return None
    return snapshots[0].read_text(encoding="utf-8")


def format_prioritized_entries(entries: list[PrioritizedEntry]) -> str:
    lines: list[str] = []
    for entry in entries:
        if entry.label:
            prefix = f"- **{entry.label}:** {entry.text}"
        else:
            prefix = f"- {entry.text}"
        lines.append(f"{prefix} [PRIORITY: {entry.priority} — {entry.reason}]")
    return "\n".join(lines)






def build_snapshot_markdown(snapshot: dict, now: datetime, *, include_transcript: bool = True) -> str:
    timestamp = now.strftime("%Y-%m-%d %H:%M")
    sections = [
        "---",
        f"snapshot_version: {snapshot['snapshot_version']}",
        f"generated: {snapshot['generated']}",
        f"context_pct: {snapshot['context_pct']}",
        f"priority_threshold: {snapshot['priority_threshold']}",
        "---",
        "",
        f"# Context Snapshot — {timestamp}",
        "",
        "## Active State",
        format_prioritized_entries(snapshot["active_state_entries"]),
        "",
        "## Open Questions",
        format_prioritized_entries(snapshot["open_question_entries"]),
        "",
        "## Recent Findings",
        format_prioritized_entries(snapshot["recent_finding_entries"]),
        "",
        "## Code Context",
        format_prioritized_entries(snapshot["code_context_entries"]),
        "",
        "## Pending Actions",
        format_prioritized_entries(snapshot["pending_action_entries"]),
    ]

    if include_transcript:
        sections.extend(
            [
                "",
                "## Session Transcript (last N messages)",
                snapshot["transcript"] or "_No recent transcript content available._",
                "",
            ]
        )
    else:
        sections.append("")
    return "\n".join(sections)


def write_snapshot(snapshot_markdown: str, now: datetime) -> Path:
    snapshot_dir = expand_path(SNAPSHOT_DIR)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    path = snapshot_dir / f"{now.strftime('%Y-%m-%d_%H%M')}.md"
    path.write_text(snapshot_markdown, encoding="utf-8")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor OpenClaw session context budget and snapshot active state.")
    parser.add_argument("--check-only", action="store_true", help="Dry run; report state without writing a snapshot.")
    args = parser.parse_args()

    try:
        records = build_session_records()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    target = select_target_session(records)
    latest_snapshot = load_latest_snapshot()

    if not target:
        print("Context Budget Monitor")
        print("No session transcripts were available to inspect.")
        if latest_snapshot:
            print("Latest snapshot: available")
        else:
            print("Latest snapshot: none")
        return 0

    now = datetime.now().astimezone()
    snapshot = extract_snapshot_data(target, now)
    snapshot_needed = target.message_count >= MESSAGE_THRESHOLD and has_active_state(snapshot)

    print("Context Budget Monitor")
    print(f"Sessions scanned: {len(records)}")
    print(f"Target session: {target.key}")
    print(f"Session file: {target.session_file or 'missing'}")
    print(f"Message count: {target.message_count}")
    print(f"Threshold: {MESSAGE_THRESHOLD}")
    print(f"Snapshot needed: {'yes' if snapshot_needed else 'no'}")
    print(f"Latest snapshot present: {'yes' if latest_snapshot else 'no'}")
    print(f"Program: {snapshot['program']}")
    print(f"Vulnerability: {snapshot['vulnerability']}")
    print(f"Phase: {snapshot['phase']}")
    print(f"Status: {snapshot['status']}")
    print(f"Priority threshold: {snapshot['priority_threshold']}")
    print(f"Snapshot version: {snapshot['snapshot_version']}")

    if args.check_only:
        print("Mode: check-only")
        if snapshot_needed:
            print("Action: would write snapshot")
        else:
            print("Action: no snapshot")
        print("")
        print(build_snapshot_markdown(snapshot, now, include_transcript=False).rstrip())
        return 0

    if not snapshot_needed:
        print("Action: no snapshot")
        return 0

    snapshot_markdown = build_snapshot_markdown(snapshot, now)
    output_path = write_snapshot(snapshot_markdown, now)
    print(f"Action: snapshot written to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
