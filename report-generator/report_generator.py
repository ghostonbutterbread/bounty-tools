#!/usr/bin/env python3
"""Bug bounty report template generator for HackerOne and Bugcrowd."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from string import Template
from typing import Dict, List

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
PLATFORM_DIR = TEMPLATES_DIR / "platforms"
VULN_DIR = TEMPLATES_DIR / "vuln_types"


def sanitize_slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_") or "report"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def load_platform_template(platform: str) -> str:
    path = PLATFORM_DIR / f"{platform}.md"
    if not path.exists():
        raise FileNotFoundError(f"Missing platform template: {path}")
    return read_text(path)


def load_vuln_template(vuln_type: str) -> str:
    vtype = sanitize_slug(vuln_type)
    path = VULN_DIR / f"{vtype}.md"
    if path.exists():
        return read_text(path)

    generic = VULN_DIR / "generic.md"
    if generic.exists():
        return read_text(generic)

    return ""


def available_vuln_types() -> List[str]:
    if not VULN_DIR.exists():
        return []
    return sorted(p.stem for p in VULN_DIR.glob("*.md"))


def render(template: str, values: Dict[str, str]) -> str:
    return Template(template).safe_substitute(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate markdown bug bounty reports for HackerOne and Bugcrowd."
    )
    parser.add_argument("--interactive", action="store_true", help="Enable interactive prompts")
    parser.add_argument("--platform", choices=["hackerone", "bugcrowd", "both"], default="both")
    parser.add_argument("--vuln-type", default="", help="Vulnerability type (xss, idor, sqli, auth_bypass, etc.)")
    parser.add_argument("--cve", default="N/A", help="CVE ID")
    parser.add_argument("--title", default="", help="Report title")
    parser.add_argument("--target", default="", help="Target asset/domain")
    parser.add_argument("--severity", default="Medium", help="Severity")
    parser.add_argument("--description", default="", help="Description")
    parser.add_argument("--impact", default="", help="Impact")
    parser.add_argument("--steps", default="", help="Steps to reproduce")
    parser.add_argument("--poc", default="", help="Proof of concept details")
    parser.add_argument("--remediation", default="", help="Remediation guidance")
    parser.add_argument("--reporter", default="", help="Reporter handle/name")
    parser.add_argument("--output-dir", default="output", help="Output directory")
    parser.add_argument("--preview", action="store_true", help="Print generated markdown")
    parser.add_argument("--list-vuln-types", action="store_true", help="List available vulnerability templates")
    return parser.parse_args()


def collect_interactive(vuln_types: List[str]) -> Dict[str, str]:
    print("=== Interactive Mode ===")
    print(f"Available vuln templates: {', '.join(vuln_types) if vuln_types else '(none)'}")
    vuln_type = input("Vulnerability type: ").strip() or "generic"
    cve = input("CVE (or N/A): ").strip() or "N/A"
    title = input("Title: ").strip() or f"{vuln_type.upper()} vulnerability in target"
    target = input("Target: ").strip() or "unknown-target"
    severity = input("Severity [Low/Medium/High/Critical]: ").strip() or "Medium"
    description = input("Description: ").strip() or "Describe the issue."
    impact = input("Impact: ").strip() or "Explain impact."
    print("Steps to reproduce (single line or '\\n' separated):")
    steps = input("> ").strip() or "1. Step one\\n2. Step two"
    poc = input("PoC details (optional): ").strip()
    remediation = input("Remediation (optional): ").strip()
    reporter = input("Reporter (optional): ").strip()

    return {
        "vulnerability_type": vuln_type,
        "cve": cve,
        "title": title,
        "target": target,
        "severity": severity,
        "description": description,
        "impact": impact,
        "steps_to_reproduce": steps.replace("\\n", "\n"),
        "proof_of_concept": poc,
        "remediation": remediation,
        "reporter": reporter,
    }


def collect_non_interactive(args: argparse.Namespace) -> Dict[str, str]:
    vuln_type = args.vuln_type or "generic"
    title = args.title or f"{vuln_type.upper()} vulnerability in target"
    return {
        "vulnerability_type": vuln_type,
        "cve": args.cve or "N/A",
        "title": title,
        "target": args.target or "unknown-target",
        "severity": args.severity or "Medium",
        "description": args.description or "Describe the issue.",
        "impact": args.impact or "Explain impact.",
        "steps_to_reproduce": (args.steps or "1. Step one\n2. Step two").replace("\\n", "\n"),
        "proof_of_concept": args.poc or "",
        "remediation": args.remediation or "",
        "reporter": args.reporter or "",
    }


def generate_report(platform: str, values: Dict[str, str], out_dir: Path) -> Path:
    platform_template = load_platform_template(platform)
    vuln_template = load_vuln_template(values["vulnerability_type"])
    values = dict(values)
    values["vuln_type_template"] = render(vuln_template, values).strip()

    content = render(platform_template, values).strip() + "\n"
    filename = f"{platform}_{sanitize_slug(values['target'])}_{sanitize_slug(values['title'])}.md"
    path = out_dir / filename
    write_text(path, content)
    return path


def main() -> None:
    args = parse_args()
    vuln_types = available_vuln_types()

    if args.list_vuln_types:
        for vt in vuln_types:
            print(vt)
        return

    values = collect_interactive(vuln_types) if args.interactive else collect_non_interactive(args)
    platforms = ["hackerone", "bugcrowd"] if args.platform == "both" else [args.platform]
    out_dir = Path(args.output_dir)

    generated = []
    for platform in platforms:
        path = generate_report(platform, values, out_dir)
        generated.append(path)

    for path in generated:
        print(f"Generated: {path}")
        if args.preview:
            print("\n=== Preview:", path.name, "===\n")
            print(read_text(path))


if __name__ == "__main__":
    main()
