"""
Compatibility facade for orchestrator finding access.

The orchestrator historically wrote one JSON file per finding. New writes go to
bounty-core only; the functions below keep older imports working while reading
and reporting from canonical bounty-core ledgers.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import os

BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))
DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"

# Kept for older tests/imports that patch this symbol. It is no longer used for
# writes.
FINDINGS_DIR = str(Path.home() / "Shared" / DEFAULT_CORE_FAMILY / "orchestrator" / DEFAULT_CORE_LANE / "ledgers")

SEVERITY_P1 = "Critical - P1"
SEVERITY_P2 = "High - P2"
SEVERITY_P3 = "Medium - P3"
SEVERITY_P4 = "Low - P4"
SEVERITY_P5 = "Info - P5"


def _sanitize_core_program(program: str | None, default: str = "ghost") -> str:
    safe_program = re.sub(r"[^a-z0-9_\-]+", "-", (program or default).lower()).strip("-")
    return safe_program or default


def infer_core_program(value: str | None, default: str = "ghost") -> str:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    host = (parsed.hostname or parsed.netloc or "").lower().strip()
    if host:
        if host.startswith("www."):
            host = host[4:]
        return _sanitize_core_program(host, default=default)
    return _sanitize_core_program(raw, default=default)


def _load_bounty_core():
    try:
        from bounty_core import add_finding, resolve_storage
        return add_finding, resolve_storage, None
    except Exception as first_error:
        if BOUNTY_CORE_PATH.exists() and str(BOUNTY_CORE_PATH) not in sys.path:
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
        try:
            from bounty_core import add_finding, resolve_storage
            return add_finding, resolve_storage, None
        except Exception as second_error:
            return None, None, second_error or first_error


def _severity_to_core(severity: str | None) -> str:
    value = str(severity or "").upper()
    if "P1" in value or "CRITICAL" in value:
        return "CRITICAL"
    if "P2" in value or "HIGH" in value:
        return "HIGH"
    if "P3" in value or "MEDIUM" in value:
        return "MEDIUM"
    if "P4" in value or "LOW" in value:
        return "LOW"
    if "P5" in value or "INFO" in value:
        return "INFO"
    return value or "UNKNOWN"


def _severity_from_core(severity: str | None) -> str:
    value = str(severity or "").upper()
    if value == "CRITICAL":
        return SEVERITY_P1
    if value == "HIGH":
        return SEVERITY_P2
    if value == "MEDIUM":
        return SEVERITY_P3
    if value == "LOW":
        return SEVERITY_P4
    return SEVERITY_P5


def _finding_to_core_payload(finding: dict[str, Any], *, program: str, family: str, lane: str) -> dict[str, Any]:
    endpoint = str(finding.get("endpoint") or finding.get("url") or "")
    parsed = urlparse(endpoint)
    asset = (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.scheme and parsed.netloc
        else endpoint or finding.get("target", "unknown")
    )
    vuln_type = str(finding.get("vuln_type") or finding.get("type") or "unknown")
    status = str(finding.get("status") or "raw").lower()
    core_status = status if status in {"raw", "confirmed", "dormant", "novel", "complete", "archive"} else "raw"

    evidence = []
    if endpoint:
        evidence.append(f"endpoint={endpoint}")
    if finding.get("poc"):
        evidence.append(str(finding["poc"]))

    return {
        "program": program,
        "family": family,
        "lane": lane,
        "type": vuln_type,
        "status": core_status,
        "severity": _severity_to_core(finding.get("severity")),
        "title": finding.get("title") or f"{vuln_type.upper()} candidate on {asset}",
        "asset": asset,
        "url": endpoint,
        "endpoint": endpoint,
        "target": finding.get("target"),
        "summary": finding.get("summary") or finding.get("description") or "Orchestrator finding imported from Bounty Tools.",
        "description": finding.get("description", ""),
        "poc": finding.get("poc", ""),
        "evidence": evidence,
        "tags": ["orchestrator", vuln_type],
        "source_tool": "orchestrator.findings_store",
        "source_repo": "bounty-tools",
        "agent": "bounty-tools.orchestrator",
        "legacy_created_at": finding.get("created_at"),
    }


def _core_to_legacy(finding: dict[str, Any]) -> dict[str, Any]:
    payload = dict(finding)
    payload.setdefault("target", finding.get("target") or finding.get("program") or finding.get("asset"))
    payload.setdefault("vuln_type", finding.get("type", "unknown"))
    payload.setdefault("endpoint", finding.get("endpoint") or finding.get("url") or finding.get("asset", ""))
    payload["severity"] = _severity_from_core(finding.get("severity"))
    payload.setdefault("poc", finding.get("poc", ""))
    payload.setdefault("description", finding.get("description") or finding.get("summary", ""))
    return payload


def write_core_finding(
    finding: dict[str, Any],
    *,
    program: str,
    family: str = DEFAULT_CORE_FAMILY,
    lane: str = DEFAULT_CORE_LANE,
) -> dict[str, Any]:
    add_finding, _, error = _load_bounty_core()
    if add_finding is None:
        return {"ok": False, "error": f"bounty-core unavailable: {error}", "written": 0, "new": 0}

    payload = _finding_to_core_payload(finding, program=program, family=family, lane=lane)
    result = add_finding(payload, program=program, family=family, lane=lane)
    stored = result.get("finding") or {}
    return {
        "ok": True,
        "written": 1,
        "new": 1 if result.get("is_new") else 0,
        "layout": result.get("layout"),
        "finding": stored,
        "report_path": stored.get("report_path"),
    }


def ensure_findings_dir():
    """Compatibility no-op; bounty-core creates canonical directories."""
    return None


def create_finding(
    target: str,
    vuln_type: str,
    endpoint: str,
    severity: str,
    poc: str,
    description: str = "",
    status: str = "new",
) -> dict[str, Any]:
    return {
        "target": target,
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "severity": severity,
        "poc": poc,
        "description": description,
        "status": status,
        "created_at": datetime.now().isoformat(),
    }


def save_finding(
    finding: dict[str, Any],
    filename: str | None = None,
    *,
    core_program: str | None = None,
    family: str = DEFAULT_CORE_FAMILY,
    lane: str = DEFAULT_CORE_LANE,
    no_core: bool = False,
    record_core_result: bool = False,
) -> str:
    """Write a finding through bounty-core and return its report path when available.

    ``filename`` is accepted for legacy callers but ignored; per-finding JSON
    files are intentionally no longer created.
    """
    if no_core:
        core_result = {"ok": False, "error": "bounty-core write disabled", "written": 0, "new": 0}
    else:
        core_identity = _sanitize_core_program(core_program) if core_program else infer_core_program(
            finding.get("endpoint") or finding.get("target") or "ghost"
        )
        try:
            core_result = write_core_finding(finding, program=core_identity, family=family, lane=lane)
        except Exception as exc:
            core_result = {"ok": False, "error": str(exc), "written": 0, "new": 0}

    if record_core_result:
        finding["core_result"] = core_result
    return str(core_result.get("report_path") or "")


def _ledger_paths() -> list[Path]:
    base = Path.home() / "Shared"
    if not base.exists():
        return []
    return sorted(base.glob("*/*/*/ledgers/ledger.json"))


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    findings = payload.get("findings", [])
    return findings if isinstance(findings, list) else []


def load_finding(filepath: str) -> dict[str, Any]:
    path = Path(filepath)
    if path.suffix == ".json" and path.exists():
        return json.loads(path.read_text(encoding="utf-8"))

    target = str(path)
    for ledger_path in _ledger_paths():
        for finding in _read_ledger(ledger_path):
            if str(finding.get("report_path") or "") == target:
                return _core_to_legacy(finding)
    raise FileNotFoundError(filepath)


def load_all_findings() -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for ledger_path in _ledger_paths():
        findings.extend(_core_to_legacy(item) for item in _read_ledger(ledger_path))
    return findings


def get_findings_summary() -> dict[str, Any]:
    findings = load_all_findings()
    summary = {
        "total": len(findings),
        "by_target": {},
        "by_severity": {SEVERITY_P1: [], SEVERITY_P2: [], SEVERITY_P3: [], SEVERITY_P4: [], SEVERITY_P5: []},
        "by_status": {},
    }

    for finding in findings:
        target = finding.get("target", "unknown")
        severity = finding.get("severity", SEVERITY_P5)
        status = finding.get("status", "unknown")
        summary["by_target"].setdefault(target, []).append(finding)
        summary["by_severity"].setdefault(severity, []).append(finding)
        summary["by_status"].setdefault(status, []).append(finding)
    return summary


def generate_report(findings: list[dict[str, Any]] | None = None, format: str = "markdown") -> str:
    findings = load_all_findings() if findings is None else findings
    if format == "json":
        return json.dumps(findings, indent=2)
    if format != "markdown":
        return str(findings)

    lines = [
        "# Bug Bounty Findings Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Findings: {len(findings)}",
        "",
    ]
    by_sev: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_sev.setdefault(finding.get("severity", SEVERITY_P5), []).append(finding)

    for severity in [SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4, SEVERITY_P5]:
        items = by_sev.get(severity, [])
        if not items:
            continue
        lines.append(f"## {severity} ({len(items)})")
        for finding in items:
            lines.extend([
                "",
                f"### {finding.get('target', '?')} - {finding.get('vuln_type', finding.get('type', '?'))}",
                f"**Endpoint:** {finding.get('endpoint', finding.get('url', 'N/A'))}",
                f"**Status:** {finding.get('status', 'raw')}",
                "",
                f"**Description:** {finding.get('description') or finding.get('summary') or 'N/A'}",
                "",
                "**PoC:**",
                "```",
                str(finding.get("poc") or "N/A"),
                "```",
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def format_finding_for_intigriti(finding: dict[str, Any]) -> str:
    lines = [
        f"# {finding['target']} - {finding['vuln_type']}",
        "",
        "## Severity",
        finding["severity"],
        "",
        "## Endpoint",
        finding["endpoint"],
        "",
        "## Description",
        finding.get("description", "N/A"),
        "",
        "## Proof of Concept",
        "```",
        finding["poc"],
        "```",
        "",
        "## Timeline",
        f"- Discovered: {finding.get('created_at', 'N/A')}",
        f"- Status: {finding['status']}",
    ]
    return "\n".join(lines)


def generate_professional_report(finding: dict[str, Any], output_path: str | Path) -> Path:
    """Render a standalone markdown report without the removed legacy renderer."""
    try:
        if BOUNTY_CORE_PATH.exists() and str(BOUNTY_CORE_PATH) not in sys.path:
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
        from bounty_core.reports import render_finding_report

        text = render_finding_report(_finding_to_core_payload(
            finding,
            program=infer_core_program(finding.get("target") or finding.get("endpoint")),
            family=finding.get("family", DEFAULT_CORE_FAMILY),
            lane=finding.get("lane", DEFAULT_CORE_LANE),
        ))
    except Exception:
        text = generate_report([_core_to_legacy(finding)], "markdown")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    return output


def finding_to_report(finding: dict[str, Any], program: str, vuln_type: str) -> Path:
    """Add the finding to bounty-core and return the generated report path."""
    payload = dict(finding)
    payload.setdefault("vuln_type", vuln_type)
    result_path = save_finding(payload, core_program=program, record_core_result=True)
    if result_path:
        return Path(result_path)
    raise RuntimeError((payload.get("core_result") or {}).get("error") or "bounty-core report write failed")
