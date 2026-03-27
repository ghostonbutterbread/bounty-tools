#!/usr/bin/env python3
"""
Professional bug bounty report generator.

Report style:
- No emojis
- Concise, professional prose
- Tables when appropriate
- Code blocks for requests/responses
- Off-flow attack diagrams (ASCII art)
- Markdown-compatible output for all bug bounty platforms
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


# ── Report Template ────────────────────────────────────────────────────────────

REPORT_TEMPLATE = """# {title}

## Overview

{overview_table}

## Summary

{summary}

## Technical Details

{technical_details}

{off_flow_diagram}

## Impact

{impact}

## Steps to Reproduce

{steps}

{request_response}

## Remediation

{remediation}

{references}
"""


# ── Off-Flow Diagram Builder ──────────────────────────────────────────────────

@dataclass
class OffFlowNode:
    label: str
    detail: str = ""
    decision: bool = False
    outcome: bool = False  # True = success path, False = fail/next


class OffFlowDiagram:
    """Builds an ASCII attack-flow diagram for off-flow vulnerabilities.

    Usage:
        d = OffFlowDiagram("Password Reset Oracle")
        d.step("Attacker obtains reset token", "Via XSS, MitM, or referrer leak")
        d.step("POST /resetpassword {\"token\": T, \"password\": \"guess1\"}", "Oracle check")
        d.decision("ValidationError fires?",
                   yes=("Password CONFIRMED", "Attacker stops - oracle confirmed"),
                   no=("Try next guess", "Continue brute force"))
        d.step("Token TTL expires", "No action needed - oracle still works")
        d.decision("Submit expired token + correct password",
                   yes=("ValidationError fires", "Expiry bypassed - oracle permanent"))
        print(d.render())
    """

    def __init__(self, title: str):
        self.title = title
        self.rows: list[str] = []

    def step(self, action: str, detail: str = "") -> "OffFlowDiagram":
        prefix = "  -->"
        self.rows.append(prefix)
        self.rows.append(f"  |  {action}")
        if detail:
            self.rows.append(f"  |  ({detail})")
        return self

    def decision(
        self,
        condition: str,
        yes: tuple[str, str] = ("", ""),
        no: tuple[str, str] = ("", ""),
    ) -> "OffFlowDiagram":
        """Add a decision diamond.

        Args:
            condition: The yes/no question
            yes: (action, result) when condition is YES / true path
            no:  (action, result) when condition is NO / false path
        """
        self.rows.append(f"  +--[ {condition} ]--+")
        if yes[0]:
            self.rows.append(f"  |  YES: {yes[0]}")
            if yes[1]:
                self.rows.append(f"  |  => {yes[1]}")
        if no[0]:
            self.rows.append(f"  |  NO:  {no[0]}")
            if no[1]:
                self.rows.append(f"  |  => {no[1]}")
        return self

    def outcome(self, label: str, detail: str = "") -> "OffFlowDiagram":
        self.rows.append(f"  \\-> {label}")
        if detail:
            self.rows.append(f"     ({detail})")
        return self

    def render(self) -> str:
        lines = [f"### Attack Flow ({self.title})", ""]
        if not self.rows:
            lines.append("```")
            lines.append("  (no steps defined)")
            lines.append("```")
            return "\n".join(lines)
        lines.append("```")
        lines.append("                    ATTACKER")
        lines.append("                         |")
        for row in self.rows:
            lines.append(row)
        lines.append("                         |")
        lines.append("                    VICTIM / SERVER")
        lines.append("```")
        return "\n".join(lines)


# ── Report Builder ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    # Required
    title: str
    vuln_type: str          # e.g. "authentication-bypass", "idor", "information-disclosure"
    target: str             # e.g. "api.superdrug.com"
    summary: str           # 1-2 sentence executive summary

    # Severity
    severity: str = "Medium"   # Low / Medium / High / Critical

    # Technical
    technical_details: str = ""
    impact: str = ""
    steps: list[str] = field(default_factory=list)
    request_response: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Metadata
    reporter: str = ""
    date_reported: str = ""
    cve: str = ""
    status: str = "Open"

    # Off-flow diagram
    off_flow_diagram: str = ""

    # Extra overview rows (key-value pairs added to table)
    extra_rows: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**d)


def build_off_flow_diagram(diagram: OffFlowDiagram) -> str:
    return diagram.render()


class ReportWriter:
    """Writes a Finding to a clean, professional markdown report."""

    def __init__(self, finding: Finding):
        self.f = finding

    def _wrap(self, text: str, width: int = 80) -> str:
        """Wrap text to width, preserving paragraphs."""
        paragraphs = []
        for para in text.split("\n"):
            para = para.strip()
            if not para:
                paragraphs.append("")
                continue
            if len(para) <= width:
                paragraphs.append(para)
            else:
                wrapped = textwrap.fill(para, width=width, break_long_words=False)
                paragraphs.append(wrapped)
        return "\n".join(paragraphs)

    def _md_table(self, rows: list[list[str]]) -> str:
        """Render a list of [key, value] rows as a markdown table."""
        lines = ["| Field | Value |", "|-------|-------|"]
        for k, v in rows:
            lines.append(f"| {k} | {v} |")
        return "\n".join(lines)

    def _md_list(self, items: list[str], ordered: bool = False) -> str:
        if ordered:
            return "\n".join(f"{i+1}. {item}" for i, item in enumerate(items))
        return "\n".join(f"- {item}" for item in items)

    def _md_code(self, text: str, lang: str = "") -> str:
        return f"```{lang}\n{text}\n```"

    def _md_heading(self, text: str, level: int = 2) -> str:
        return f"{'#' * level} {text}"

    def render(self) -> str:
        f = self.f
        date = f.date_reported or datetime.utcnow().strftime("%Y-%m-%d")

        # Build overview table
        overview_rows = [
            ["Target", f"`{f.target}`"],
            ["Severity", f"**{f.severity}**"],
            ["Type", f"`{f.vuln_type}`"],
            ["Status", f.status],
            ["Date Reported", date],
            ["Reporter", f.reporter or "Anonymous"],
        ]
        if f.cve:
            overview_rows.insert(3, ["CVE", f"`{f.cve}`"])
        overview_rows += [[k, v] for k, v in f.extra_rows.items()]

        # Build steps section
        if f.steps:
            steps_text = self._md_list(f.steps, ordered=True)
        else:
            steps_text = "_No steps provided._"

        # Build references
        refs_text = ""
        if f.references:
            refs_text = "\n".join(
                f"- [{ref}]({ref})" if ref.startswith("http") else f"- {ref}"
                for ref in f.references
            )

        # Build off-flow diagram section
        off_flow = f.off_flow_diagram or ""
        if not off_flow and isinstance(f.off_flow_diagram, str):
            # If it's an empty string, don't show section
            off_flow = ""

        return REPORT_TEMPLATE.format(
            title=f.title,
            target=f.target,
            severity=f"**{f.severity}**" if f.severity else f.severity,
            vuln_type=f.vuln_type,
            date_reported=date,
            reporter=f.reporter or "Anonymous",
            summary=self._wrap(f.summary),
            overview_table=self._md_table(overview_rows),
            technical_details=self._wrap(f.technical_details) if f.technical_details else "_No technical details provided._",
            off_flow_diagram=f"\n\n{off_flow}\n" if off_flow else "",
            impact=self._wrap(f.impact),
            steps=steps_text,
            request_response=f"\n{f.request_response}\n" if f.request_response else "",
            remediation=self._wrap(f.remediation) if f.remediation else "_No remediation provided._",
            references=(
                f"\n{self._md_heading('References', 2)}\n{refs_text}\n"
                if refs_text
                else ""
            ),
        )

    def write(self, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render(), encoding="utf-8")


# ── CLI ────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate professional bug bounty reports.")
    p.add_argument("--title", required=True, help="Report title")
    p.add_argument("--target", required=True, help="Target asset")
    p.add_argument("--type", dest="vuln_type", required=True,
                   help="Vulnerability type (e.g. auth-bypass, idor, information-disclosure)")
    p.add_argument("--severity", default="Medium", help="Severity (Low/Medium/High/Critical)")
    p.add_argument("--summary", required=True, help="Executive summary (1-2 sentences)")
    p.add_argument("--impact", required=True, help="Impact description")
    p.add_argument("--technical", default="", help="Technical details")
    p.add_argument("--steps", nargs="+", default=[], help="Steps to reproduce")
    p.add_argument("--request", default="", help="Request/response block (raw text)")
    p.add_argument("--remediation", default="", help="Remediation guidance")
    p.add_argument("--reference", dest="references", action="append", default=[], help="Reference URLs (repeat for multiple)")
    p.add_argument("--cve", default="", help="CVE ID if applicable")
    p.add_argument("--reporter", default="", help="Your name/handle")
    p.add_argument("--output", required=True, help="Output .md file path")
    p.add_argument("--json", dest="json_mode", action="store_true",
                   help="Read finding from JSON file instead of args")
    p.add_argument("--list-types", action="store_true", help="List supported vuln types")
    return p.parse_args()


SUPPORTED_TYPES = [
    "api-key-exposure",
    "authentication-bypass",
    "broken-access-control",
    "idor",
    "information-disclosure",
    "idor",
    "ssrf",
    "sqli",
    "xss",
    "open-redirect",
    "auth-bypass",
    "idor",
    "session-hijacking",
    "csrf",
    "command-injection",
    "ssrf",
    "ssti",
    "lfi",
    "generic",
]


def main() -> None:
    args = parse_args()

    if args.list_types:
        for t in SUPPORTED_TYPES:
            print(t)
        return

    if args.json_mode:
        with open(args.output, "r") as fh:
            data = json.load(fh)
        finding = Finding.from_dict(data)
    else:
        finding = Finding(
            title=args.title,
            vuln_type=args.vuln_type,
            target=args.target,
            severity=args.severity,
            summary=args.summary,
            technical_details=args.technical,
            impact=args.impact,
            steps=args.steps,
            request_response=args.request,
            remediation=args.remediation,
            references=args.references,
            cve=args.cve,
            reporter=args.reporter,
            date_reported=datetime.utcnow().strftime("%Y-%m-%d"),
        )

    writer = ReportWriter(finding)
    output = Path(args.output)
    writer.write(output)
    print(f"Report written: {output}")


if __name__ == "__main__":
    main()
