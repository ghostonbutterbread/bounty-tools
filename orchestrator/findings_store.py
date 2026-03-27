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


# ── Professional Report Generator ──────────────────────────────────────────────

def generate_professional_report(
    finding: dict,
    output_path: str | Path,
) -> Path:
    """Generate a professional markdown report from a finding dict.

    Args:
        finding: A finding dict with keys:
            - title: Report title
            - vuln_type: e.g. "information-disclosure", "auth-bypass"
            - target: Target asset or domain
            - severity: Low / Medium / High / Critical
            - summary: 1-2 sentence executive summary
            - impact: Impact description
            - technical_details: (optional) technical explanation
            - steps: (optional) list of repro steps
            - request_response: (optional) raw request/response block
            - remediation: (optional) fix guidance
            - references: (optional) list of reference URLs
            - cve: (optional) CVE ID
            - reporter: (optional) your name/handle
        output_path: Where to write the .md file

    Returns:
        Path to the written report
    """
    try:
        from report_generator.report_generator import Finding, ReportWriter
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "report_generator",
            Path(__file__).parent.parent / "report_generator" / "report_generator.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        Finding = mod.Finding
        ReportWriter = mod.ReportWriter

    f = Finding(
        title=finding.get("title", "Unnamed Finding"),
        vuln_type=finding.get("vuln_type", "unknown"),
        target=finding.get("target", "unknown"),
        severity=finding.get("severity", "Medium"),
        summary=finding.get("summary", finding.get("description", "No summary provided.")),
        impact=finding.get("impact", "Impact not specified."),
        technical_details=finding.get("technical_details", ""),
        steps=finding.get("steps", []),
        request_response=finding.get("request_response", ""),
        remediation=finding.get("remediation", ""),
        references=finding.get("references", []),
        cve=finding.get("cve", ""),
        reporter=finding.get("reporter", ""),
        extra_rows=finding.get("extra_rows", {}),
        off_flow_diagram=finding.get("off_flow_diagram", ""),
    )

    output_path = Path(output_path)
    writer = ReportWriter(f)
    writer.write(output_path)
    return output_path


def finding_to_report(finding: dict, program: str, vuln_type: str) -> Path:
    """Convenience: generate a report from a finding dict.

    Writes to: ~/Shared/bounty_recon/{program}/ghost/reports/{vuln_type}_{target}.md
    """
    target = finding.get("target", "unknown").replace("/", "_")
    program_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "reports"
    program_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{vuln_type}_{target}_{datetime.now().strftime('%Y%m%d')}.md"
    output_path = program_dir / filename

    return generate_professional_report(finding, output_path)
