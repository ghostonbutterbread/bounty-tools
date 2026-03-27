"""
Findings Store — Store, query, and manage vulnerability findings.
"""

import json
import os
from datetime import datetime
from pathlib import Path

try:
    from .config import FINDINGS_DIR, SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4, SEVERITY_P5
except ImportError:
    # Fallback if config not yet loaded
    FINDINGS_DIR = os.path.join(os.path.expanduser("~/Shared/bounty_recon/orchestrator"), "findings")
    SEVERITY_P1 = "Critical - P1"
    SEVERITY_P2 = "High - P2"
    SEVERITY_P3 = "Medium - P3"
    SEVERITY_P4 = "Low - P4"
    SEVERITY_P5 = "Info - P5"


def ensure_findings_dir():
    os.makedirs(FINDINGS_DIR, exist_ok=True)


def create_finding(
    target: str,
    vuln_type: str,
    endpoint: str,
    severity: str,
    poc: str,
    description: str = "",
    status: str = "new"
) -> dict:
    """Create a structured finding dict."""
    return {
        "target": target,
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "severity": severity,
        "poc": poc,
        "description": description,
        "status": status,
        "created_at": datetime.now().isoformat()
    }


def save_finding(finding: dict, filename: str = None) -> str:
    """Save a finding to its own JSON file."""
    ensure_findings_dir()

    target = finding.get("target", "unknown").replace("/", "_").replace(".", "_")
    vuln = finding.get("vuln_type", "unknown").replace("/", "_").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if filename is None:
        filename = f"{target}_{vuln}_{timestamp}.json"

    filepath = os.path.join(FINDINGS_DIR, filename)
    with open(filepath, 'w') as f:
        json.dump(finding, f, indent=2)
    return filepath


def load_finding(filepath: str) -> dict:
    """Load a finding from file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def load_all_findings() -> list:
    """Load all findings from the findings directory."""
    ensure_findings_dir()
    findings = []
    for filename in os.listdir(FINDINGS_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(FINDINGS_DIR, filename)
            try:
                findings.append(load_finding(filepath))
            except (json.JSONDecodeError, OSError):
                # Skip corrupted/unreadable files
                pass
    return findings


def get_findings_summary() -> dict:
    """Get a summary of all findings by target and severity."""
    findings = load_all_findings()
    summary = {
        "total": len(findings),
        "by_target": {},
        "by_severity": {SEVERITY_P1: [], SEVERITY_P2: [], SEVERITY_P3: [], SEVERITY_P4: [], SEVERITY_P5: []},
        "by_status": {"new": [], "confirmed": [], "reported": [], "duplicate": []}
    }

    for f in findings:
        target = f.get("target", "unknown")
        severity = f.get("severity", SEVERITY_P5)
        status = f.get("status", "new")

        if target not in summary["by_target"]:
            summary["by_target"][target] = []
        summary["by_target"][target].append(f)

        if severity in summary["by_severity"]:
            summary["by_severity"][severity].append(f)

        if status in summary["by_status"]:
            summary["by_status"][status].append(f)

    return summary


def generate_report(findings: list = None, format: str = "markdown") -> str:
    """Generate a formatted report of findings."""
    if findings is None:
        findings = load_all_findings()

    if format == "markdown":
        lines = [
            "# Bug Bounty Findings Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total Findings: {len(findings)}",
            ""
        ]

        # Group by severity
        by_sev = {}
        for f in findings:
            sev = f.get("severity", SEVERITY_P5)
            if sev not in by_sev:
                by_sev[sev] = []
            by_sev[sev].append(f)

        for sev in [SEVERITY_P1, SEVERITY_P2, SEVERITY_P3, SEVERITY_P4, SEVERITY_P5]:
            if sev in by_sev:
                lines.append(f"\n## {sev} ({len(by_sev[sev])})")
                for f in by_sev[sev]:
                    lines.append(f"\n### {f.get('target', '?')} - {f.get('vuln_type', '?')}")
                    lines.append(f"**Endpoint:** {f.get('endpoint', 'N/A')}")
                    lines.append(f"**Status:** {f.get('status', 'new')}")
                    lines.append(f"\n**Description:**\n{f.get('description', 'N/A')}")
                    lines.append(f"\n**PoC:**\n```\n{f.get('poc', 'N/A')}\n```")

        return "\n".join(lines)

    elif format == "json":
        return json.dumps(findings, indent=2)

    return str(findings)


def format_finding_for_intigriti(finding: dict) -> str:
    """Format a finding for Intigriti submission."""
    lines = [
        f"# {finding['target']} - {finding['vuln_type']}",
        "",
        f"## Severity",
        finding['severity'],
        "",
        f"## Endpoint",
        finding['endpoint'],
        "",
        f"## Description",
        finding.get('description', 'N/A'),
        "",
        f"## Proof of Concept",
        "```",
        finding['poc'],
        "```",
        "",
        f"## Timeline",
        f"- Discovered: {finding.get('created_at', 'N/A')}",
        f"- Status: {finding['status']}",
    ]
    return "\n".join(lines)
