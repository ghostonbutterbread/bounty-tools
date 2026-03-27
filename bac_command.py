#!/usr/bin/env python3
"""
/bac command — Broken Access Control testing.

Spider-web composable module: references bac_checks.py as the shared test catalog.
Can be run standalone with focus, or called by an orchestrator.

Usage:
    python3 bac_command.py <target> [focus] [options]

Focus modes:
    all           Full test matrix (16 tests, P0+P1+P2)
    horizontal    Horizontal privilege escalation (IDOR, token state, sequential IDs)
    vertical      Vertical privilege escalation (admin functions, forceful browsing)
    auth_bypass   Auth bypass only (token reuse, plus-addressing, JWT, OAuth, verb tampering)
    idor          IDOR-only tests (token state bypass, email enum, sequential IDs)
    p0            P0 critical only (account takeover, token misuse)
    p1            P1 high only (missing auth, horizontal/vertical escalation)
    p2            P2 medium only (config issues, info disclosure)

Examples:
    python3 bac_command.py https://api.example.com all
    python3 bac_command.py https://api.example.com horizontal
    python3 bac_command.py https://api.example.com vertical --program=acme
    python3 bac_command.py https://api.example.com p0 --output=detailed
    python3 bac_command.py https://api.example.com auth_bypass --dry-run
"""

import argparse
import sys
import json
import re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bac_checks import BACChecks, Severity, BACFinding

BASE_DIR = Path.home() / "Shared" / "bounty_recon"


def get_priority_filter(focus: str) -> str | None:
    """Return priority filter string or None."""
    focus_lower = focus.lower()
    if focus_lower == "p0":
        return "P0"
    elif focus_lower == "p1":
        return "P1"
    elif focus_lower == "p2":
        return "P2"
    return None


def get_subfocus_filter(focus: str):
    """Return keyword filter based on focus, or None for all."""
    focus_lower = focus.lower()
    if focus_lower == "horizontal":
        # Only tests specifically about horizontal escalation / IDOR / sequential IDs
        return {
            "include": ["horizontal", "idor", "sequential", "token state bypass"],
            "exclude": ["vertical", "admin functions", "forceful browsing"]
        }
    elif focus_lower == "vertical":
        # Only tests about vertical escalation, admin, forceful browsing
        return {
            "include": ["vertical", "admin functions", "forceful browsing"],
            "exclude": ["horizontal", "token state", "sequential"]
        }
    elif focus_lower == "idor":
        return {
            "include": ["idor", "sequential", "token state bypass"],
            "exclude": ["horizontal", "vertical", "admin", "forceful"]
        }
    elif focus_lower == "auth_bypass":
        return {
            "include": ["token", "password", "email", "oauth", "jwt", "rate", "case", "weak", "plus-address", "algorithm", "verb tampering", "state bypass", "enumeration via timing"],
            "exclude": []
        }
    elif focus_lower in ("all", "hv", "p0", "p1", "p2"):
        return None
    return None


def get_filtered_tests(target: str, focus: str) -> list[BACFinding]:
    """Build test matrix for target, filtered by focus."""
    checks = BACChecks()
    focus_lower = focus.lower()

    priority_filter = get_priority_filter(focus_lower)
    subfocus_kws = get_subfocus_filter(focus_lower)

    # If focus matches a bac_checks category name, filter by that category
    category_filter = focus_lower if focus_lower in ("auth_bypass", "escalation", "idor") else None

    # Get all tests in order
    all_tests = checks.all_tests

    # Build test matrix with target URLs populated
    findings = []
    for i, test in enumerate(all_tests):
        # Priority
        if i < 4:
            priority = "P0"
            severity = Severity.CRITICAL
        elif i < 10:
            priority = "P1"
            severity = Severity.HIGH
        else:
            priority = "P2"
            severity = Severity.MEDIUM

        # Apply priority filter
        if priority_filter and priority != priority_filter:
            continue

        # Apply category filter (when focus is a category name like "auth_bypass")
        if category_filter and test["category"] != category_filter:
            continue

        # Apply subfocus keyword filter (for horizontal/vertical/idor)
        if subfocus_kws is not None:
            name_lower = test["test_name"].lower()
            include = any(kw.lower() in name_lower for kw in subfocus_kws.get("include", []))
            exclude = any(kw.lower() in name_lower for kw in subfocus_kws.get("exclude", []))
            if not include or exclude:
                continue

        # Populate endpoint with target
        endpoint = test["endpoint"].replace("v*", "v2")
        if endpoint.startswith("/"):
            full_url = f"{target.rstrip('/')}{endpoint}"
        else:
            full_url = f"{target.rstrip('/')}/{endpoint}"

        finding = BACFinding(
            category=test["category"],
            test_name=test["test_name"],
            endpoint=full_url,
            method=test["method"],
            severity=severity,
            description=test["description"],
            expected=test["expected"],
            poc="\n".join(test["poc_steps"]),
            references=test["refs"]
        )
        findings.append(finding)

    return findings


def get_test_count(focus: str) -> str:
    """Get human-readable test count description."""
    focus_lower = focus.lower()
    if focus_lower == "all":
        return "16 tests (P0+P1+P2)"
    elif focus_lower == "horizontal":
        return "~5 tests (horizontal escalation, IDOR, sequential IDs)"
    elif focus_lower == "vertical":
        return "~3 tests (vertical escalation, forceful browsing)"
    elif focus_lower == "hv":
        return "~8 tests (horizontal + vertical escalation)"
    elif focus_lower == "auth_bypass":
        return "~10 tests (auth bypass, token reuse, plus-addressing, JWT, OAuth)"
    elif focus_lower == "idor":
        return "~3 tests (token state bypass, sequential ID enumeration)"
    elif focus_lower == "p0":
        return "4 P0 tests (account takeover, token misuse)"
    elif focus_lower == "p1":
        return "6 P1 tests (missing auth, horizontal/vertical escalation)"
    elif focus_lower == "p2":
        return "6 P2 tests (config issues, info disclosure)"
    return "all tests"


def validate_target(target: str) -> tuple[bool, str]:
    """Validate target URL."""
    if not target.startswith(("http://", "https://")):
        return False, "Target must start with http:// or https://"
    if len(target) > 500:
        return False, "Target URL too long"
    return True, ""


def sanitize_program(program: str) -> Path:
    """Return safe output directory."""
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "", program or "ghost") or "ghost"
    base = BASE_DIR / safe / "ghost" / "bac"
    try:
        resolved = base.resolve()
        resolved.relative_to(BASE_DIR.resolve())
        return base
    except ValueError:
        return BASE_DIR / "ghost" / "bac"


def save_output(program: str, focus: str, target: str,
                test_matrix: list[BACFinding],
                detailed: bool = False) -> tuple[Path, Path]:
    """Save test matrix and findings report."""
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base = sanitize_program(program)
    base.mkdir(parents=True, exist_ok=True)

    # Matrix file
    matrix_file = base / f"matrix_{focus}_{date_str}.md"
    with open(matrix_file, "w") as f:
        f.write(f"# BAC Test Matrix — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Target:** `{target}`\n")
        f.write(f"**Focus:** {focus}\n")
        f.write(f"**Tests:** {len(test_matrix)}\n\n")
        f.write("| Priority | Category | Method | Test | Endpoint | Status |\n")
        f.write("|----------|----------|--------|------|---------|--------|\n")
        for t in test_matrix:
            prio = "P0" if t.severity == Severity.CRITICAL else \
                   "P1" if t.severity == Severity.HIGH else "P2"
            f.write(f"| {prio} | {t.category} | {t.method} | "
                    f"{t.test_name} | `{t.endpoint}` | ❌ Pending |\n")

    # Findings report
    findings_file = base / f"findings_{focus}_{date_str}.md"
    with open(findings_file, "w") as f:
        f.write(f"# BAC Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Target:** `{target}`\n")
        f.write(f"**Focus:** {focus}\n\n")

        for severity_level, prio_label in [
            (Severity.CRITICAL, "P0"),
            (Severity.HIGH, "P1"),
            (Severity.MEDIUM, "P2"),
        ]:
            relevant = [x for x in test_matrix if x.severity == severity_level]
            if not relevant:
                continue
            f.write(f"\n## {prio_label} — {severity_level.value.upper()} ({len(relevant)} tests)\n\n")
            for t in relevant:
                status = "✅ Resolved" if t.resolved else "❌ OPEN"
                f.write(f"### {t.test_name} — {status}\n")
                f.write(f"**Endpoint:** {t.method} `{t.endpoint}`\n")
                f.write(f"**Category:** {t.category}\n")
                f.write(f"**Expected:** {t.expected}\n")
                if t.actual:
                    f.write(f"**Actual:** {t.actual}\n")
                if t.notes:
                    f.write(f"**Notes:** {t.notes}\n")
                if detailed and t.poc:
                    f.write(f"**PoC:**\n```\n{t.poc}\n```\n")
                f.write(f"**References:** {', '.join(t.references)}\n\n")

        open_c = sum(1 for x in test_matrix if not x.resolved)
        res_c = sum(1 for x in test_matrix if x.resolved)
        f.write(f"\n---\n**Total:** {len(test_matrix)} | "
                f"✅ Resolved: {res_c} | ❌ Open: {open_c}\n")

    return matrix_file, findings_file


def main():
    parser = argparse.ArgumentParser(
        description="Broken Access Control (BAC) testing — spider-web module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("target", help="Target base URL")
    parser.add_argument("focus", nargs="?", default="all",
                        choices=["all", "horizontal", "vertical", "hv",
                                 "auth_bypass", "idor", "p0", "p1", "p2"],
                        help="Test focus (default: all)")
    parser.add_argument("--program", "-p", default=None,
                        help="Bug bounty program name (output directory)")
    parser.add_argument("--output", "-o", choices=["summary", "detailed"],
                        default="summary", help="Output detail level")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show test matrix without saving")
    parser.add_argument("--json", action="store_true",
                        help="Output test matrix as JSON")

    args = parser.parse_args()

    valid, err = validate_target(args.target)
    if not valid:
        print(f"❌ {err}")
        sys.exit(1)

    test_matrix = get_filtered_tests(args.target, args.focus)

    if args.json:
        output = [{
            "test_name": t.test_name,
            "category": t.category,
            "method": t.method,
            "endpoint": t.endpoint,
            "severity": t.severity.value,
            "description": t.description,
            "expected": t.expected,
            "poc": t.poc,
            "references": t.references,
        } for t in test_matrix]
        print(json.dumps(output, indent=2))
        sys.exit(0)

    if args.dry_run:
        print(f"🎯 BAC: {args.target}")
        print(f"   Focus: {args.focus} — {len(test_matrix)} tests\n")
        print(f"{'Priority':<8} {'Method':<6} {'Category':<15} {'Test':<50}")
        print("-" * 100)
        for t in test_matrix:
            prio = "P0" if t.severity == Severity.CRITICAL else \
                   "P1" if t.severity == Severity.HIGH else "P2"
            print(f"{prio:<8} {t.method:<6} {t.category:<15} {t.test_name:<50}")
        print(f"\n{len(test_matrix)} tests total")
        sys.exit(0)

    matrix_file, findings_file = save_output(
        args.program or "ghost", args.focus, args.target,
        test_matrix, detailed=(args.output == "detailed")
    )

    p0 = sum(1 for t in test_matrix if t.severity == Severity.CRITICAL)
    p1 = sum(1 for t in test_matrix if t.severity == Severity.HIGH)
    p2 = sum(1 for t in test_matrix if t.severity == Severity.MEDIUM)

    print(f"🎯 BAC Test Matrix — {args.target}")
    print(f"   Focus: {args.focus} — {len(test_matrix)} tests ({p0}P0, {p1}P1, {p2}P2)")
    print(f"   📋 Matrix:  {matrix_file}")
    print(f"   📝 Findings: {findings_file}")
    print()
    print("Run tests manually and update findings, or integrate into orchestrator.")


if __name__ == "__main__":
    main()
