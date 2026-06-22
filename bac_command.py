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
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))
from bac_checks import BACChecks, Severity, BACFinding
from recon_storage import atomic_write_text, recon_bucket, safe_slug

BOUNTY_CORE_PATH = Path.home() / "projects" / "bounty-core"
DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"


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


def _sanitize_core_program(program: str, default: str = "ghost") -> str:
    """Normalize bounty-core program/target identity strings."""
    safe_program = re.sub(r"[^a-z0-9_\-]+", "-", (program or default).lower()).strip("-")
    return safe_program or default


def _infer_core_program(target: str) -> str:
    """Infer a bounty-core program/target identity from the target hostname."""
    parsed = urlparse(target)
    host = (parsed.hostname or parsed.netloc or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return _sanitize_core_program(host)


def _load_bounty_core():
    """Import bounty-core, falling back to ~/projects/bounty-core for dev installs."""
    try:
        from bounty_core import add_finding
        return add_finding, None
    except Exception as first_error:
        if BOUNTY_CORE_PATH.exists():
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
            try:
                from bounty_core import add_finding
                return add_finding, None
            except Exception as second_error:
                return None, second_error
        return None, first_error


def _finding_to_core_payload(finding: BACFinding, *, program: str, family: str,
                             lane: str, focus: str, target: str) -> dict:
    """Convert one BAC checklist item into bounty-core's normalized finding shape."""
    vuln_type = "auth" if finding.category == "auth_bypass" else "bac"
    parsed = urlparse(finding.endpoint)
    asset = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
             if parsed.scheme and parsed.netloc else finding.endpoint)
    tags = ["bac", finding.category, focus]
    if vuln_type == "auth":
        tags.append("auth")

    return {
        "program": program,
        "family": family,
        "lane": lane,
        "type": vuln_type,
        "status": "raw",
        "severity": finding.severity.value.upper(),
        "title": f"BAC checklist: {finding.test_name}",
        "asset": asset,
        "url": finding.endpoint,
        "endpoint": finding.endpoint,
        "method": finding.method,
        "parameter": re.sub(r"[^a-z0-9_\-]+", "-", finding.test_name.lower()).strip("-"),
        "target": target,
        "category": finding.category,
        "focus": focus,
        "summary": finding.description,
        "expected": finding.expected,
        "poc": finding.poc,
        "references": finding.references,
        "evidence": [
            f"method={finding.method}",
            f"endpoint={finding.endpoint}",
            f"expected={finding.expected}",
        ],
        "tags": tags,
        "source_tool": "bac_command.py",
        "source_repo": "bounty-tools",
        "agent": "bounty-tools.bac",
    }


def write_core_findings(program: str, family: str, lane: str, focus: str,
                        target: str, test_matrix: list[BACFinding]) -> dict:
    """Write BAC checklist candidates to bounty-core ledger/report/indexes."""
    add_finding, error = _load_bounty_core()
    if add_finding is None:
        return {"ok": False, "error": f"bounty-core unavailable: {error}", "written": 0, "new": 0}

    written = 0
    new = 0
    last_layout = None
    errors = []
    for finding in test_matrix:
        payload = _finding_to_core_payload(
            finding,
            program=program,
            family=family,
            lane=lane,
            focus=focus,
            target=target,
        )
        try:
            result = add_finding(payload, program=program, family=family, lane=lane)
            written += 1
            if result.get("is_new"):
                new += 1
            last_layout = result.get("layout") or last_layout
        except Exception as exc:
            errors.append(str(exc))

    return {"ok": not errors, "written": written, "new": new, "layout": last_layout, "errors": errors}


def save_output(program: str, focus: str, target: str,
                test_matrix: list[BACFinding],
                *,
                family: str = DEFAULT_CORE_FAMILY,
                lane: str = DEFAULT_CORE_LANE,
                detailed: bool = False) -> tuple[Path, Path]:
    """Save BAC checklist artifacts under the canonical recon bucket."""
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    parsed = urlparse(target)
    host = parsed.hostname or parsed.netloc or target
    bucket = recon_bucket(
        program,
        family=family,
        lane=lane,
        parts=("bac", safe_slug(host.lower(), default="target"), safe_slug(focus, default="all")),
    )
    base = bucket.bucket

    # Matrix file
    matrix_file = base / f"matrix_{focus}_{date_str}.md"
    matrix_lines = [
        f"# BAC Test Matrix — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Target:** `{target}`",
        f"**Focus:** {focus}",
        f"**Program:** {bucket.program}",
        f"**Family/Lane:** {bucket.family}/{bucket.lane}",
        f"**Tests:** {len(test_matrix)}",
        "",
        "| Priority | Category | Method | Test | Endpoint | Status |",
        "|----------|----------|--------|------|---------|--------|",
    ]
    for t in test_matrix:
        prio = "P0" if t.severity == Severity.CRITICAL else \
               "P1" if t.severity == Severity.HIGH else "P2"
        matrix_lines.append(
            f"| {prio} | {t.category} | {t.method} | "
            f"{t.test_name} | `{t.endpoint}` | Pending |"
        )
    atomic_write_text(matrix_file, "\n".join(matrix_lines) + "\n")

    # Findings report
    findings_file = base / f"findings_{focus}_{date_str}.md"
    findings_lines = [
        f"# BAC Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Target:** `{target}`",
        f"**Focus:** {focus}",
        f"**Program:** {bucket.program}",
        f"**Family/Lane:** {bucket.family}/{bucket.lane}",
        "",
    ]
    for severity_level, prio_label in [
        (Severity.CRITICAL, "P0"),
        (Severity.HIGH, "P1"),
        (Severity.MEDIUM, "P2"),
    ]:
        relevant = [x for x in test_matrix if x.severity == severity_level]
        if not relevant:
            continue
        findings_lines.extend(["", f"## {prio_label} — {severity_level.value.upper()} ({len(relevant)} tests)", ""])
        for t in relevant:
            status = "Resolved" if t.resolved else "OPEN"
            findings_lines.append(f"### {t.test_name} — {status}")
            findings_lines.append(f"**Endpoint:** {t.method} `{t.endpoint}`")
            findings_lines.append(f"**Category:** {t.category}")
            findings_lines.append(f"**Expected:** {t.expected}")
            if t.actual:
                findings_lines.append(f"**Actual:** {t.actual}")
            if t.notes:
                findings_lines.append(f"**Notes:** {t.notes}")
            if detailed and t.poc:
                findings_lines.append(f"**PoC:**\n```\n{t.poc}\n```")
            findings_lines.append(f"**References:** {', '.join(t.references)}")
            findings_lines.append("")

    open_c = sum(1 for x in test_matrix if not x.resolved)
    res_c = sum(1 for x in test_matrix if x.resolved)
    findings_lines.extend(["", "---", f"**Total:** {len(test_matrix)} | Resolved: {res_c} | Open: {open_c}"])
    atomic_write_text(findings_file, "\n".join(findings_lines) + "\n")

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
                        help="Deprecated compatibility program name; used as canonical identity only when --core-program/--name is omitted")
    parser.add_argument("--output", "-o", choices=["summary", "detailed"],
                        default="summary", help="Output detail level")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show test matrix without saving")
    parser.add_argument("--json", action="store_true",
                        help="Output test matrix as JSON")
    parser.add_argument("--core-program", "--name", dest="core_program", default=None,
                        help="bounty-core program/target identity/name (default: --program when set, otherwise infer from target hostname)")
    parser.add_argument("--family", default=DEFAULT_CORE_FAMILY,
                        help=f"bounty-core storage family for ledger writes (default: {DEFAULT_CORE_FAMILY})")
    parser.add_argument("--lane", default=DEFAULT_CORE_LANE,
                        help=f"bounty-core storage lane for ledger writes (default: {DEFAULT_CORE_LANE})")
    parser.add_argument("--write-core", action="store_true",
                        help="Opt in to bounty-core writes for manually validated BAC findings/checklist items")
    parser.add_argument("--no-core", action="store_true",
                        help="Deprecated alias for the default behavior: do not write BAC checklist items to bounty-core")

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

    core_program = _sanitize_core_program(args.core_program or args.program) if (args.core_program or args.program) else _infer_core_program(args.target)

    matrix_file, findings_file = save_output(
        core_program, args.focus, args.target,
        test_matrix,
        family=args.family,
        lane=args.lane,
        detailed=(args.output == "detailed"),
    )

    core_result = None
    if args.write_core and not args.no_core:
        core_result = write_core_findings(
            core_program,
            args.family,
            args.lane,
            args.focus,
            args.target,
            test_matrix,
        )

    p0 = sum(1 for t in test_matrix if t.severity == Severity.CRITICAL)
    p1 = sum(1 for t in test_matrix if t.severity == Severity.HIGH)
    p2 = sum(1 for t in test_matrix if t.severity == Severity.MEDIUM)

    print(f"🎯 BAC Test Matrix — {args.target}")
    print(f"   Focus: {args.focus} — {len(test_matrix)} tests ({p0}P0, {p1}P1, {p2}P2)")
    print(f"   Recon bucket: {matrix_file.parent}")
    if args.write_core and not args.no_core:
        print(f"   bounty-core identity: program={core_program} family={args.family} lane={args.lane}")
    else:
        print("   bounty-core: checklist promotion disabled by default (use --write-core only after validation)")
    print(f"   📋 Matrix:  {matrix_file}")
    print(f"   📝 Findings: {findings_file}")
    if core_result:
        if core_result.get("ok"):
            layout = core_result.get("layout") or {}
            print(f"   bounty-core: wrote {core_result.get('written', 0)} findings ({core_result.get('new', 0)} new)")
            if layout.get("canonical_root"):
                print(f"   bounty-core root: {layout['canonical_root']}")
        else:
            print(f"   bounty-core: skipped/partial — {core_result.get('error') or core_result.get('errors')}")
    print()
    print("Run tests manually and update findings, or integrate into orchestrator.")


if __name__ == "__main__":
    main()
