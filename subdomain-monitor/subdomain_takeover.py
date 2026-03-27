#!/usr/bin/env python3
"""Subdomain takeover monitoring tool.

Features:
- Accept domains/subdomains from CLI args or file
- Resolve DNS records (CNAME, A, AAAA, NS)
- Match DNS/HTTP fingerprints for known vulnerable services
- Detect dangling CNAME and potentially expired NS targets
- Export findings to JSON and Markdown
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

try:
    import requests
except Exception:
    requests = None


DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 20


@dataclass
class ServiceMatch:
    name: str
    confidence: str
    reasons: List[str]
    references: List[str]


@dataclass
class Finding:
    target: str
    status: str
    potential_takeover: bool
    dns: Dict[str, Any]
    http: Dict[str, Any]
    matched_services: List[Dict[str, Any]]
    notes: List[str]


def normalize_targets(cli_targets: List[str], file_path: Optional[str]) -> List[str]:
    targets = set(t.strip().lower().rstrip(".") for t in cli_targets if t.strip())

    if file_path:
        path = Path(file_path)
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.add(line.lower().rstrip("."))

    return sorted(targets)


def load_patterns(path: str) -> Dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _resolve(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> List[str]:
    try:
        answers = resolver.resolve(name, rdtype, raise_on_no_answer=False)
        if answers.rrset is None:
            return []
        return [str(r).strip().rstrip(".") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []


def fetch_http(hostname: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    if requests is None:
        return {"enabled": False, "error": "requests module not installed"}

    out = {
        "enabled": True,
        "https": {"ok": False, "status": None, "headers": {}, "body_snippet": "", "error": None},
        "http": {"ok": False, "status": None, "headers": {}, "body_snippet": "", "error": None},
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            out[scheme] = {
                "ok": True,
                "status": resp.status_code,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body_snippet": resp.text[:4000],
                "error": None,
            }
        except Exception as exc:
            out[scheme]["error"] = str(exc)

    return out


def maybe_dangling_cname(cname: Optional[str], resolver: dns.resolver.Resolver) -> Tuple[bool, str]:
    if not cname:
        return False, ""

    a_records = _resolve(resolver, cname, "A")
    aaaa_records = _resolve(resolver, cname, "AAAA")

    if not a_records and not aaaa_records:
        return True, f"CNAME target {cname} has no A/AAAA records"

    return False, ""


def maybe_expired_ns(ns_records: List[str]) -> List[str]:
    notes: List[str] = []
    for ns in ns_records:
        labels = ns.split(".")
        if len(labels) < 2:
            continue
        parent = ".".join(labels[-2:])
        try:
            socket.getaddrinfo(parent, None)
        except socket.gaierror:
            notes.append(f"NS parent domain may be unresolvable/expired: {parent}")
    return notes


def _regex_match(patterns: List[str], haystack: str) -> bool:
    for pat in patterns:
        if re.search(pat, haystack, flags=re.IGNORECASE | re.MULTILINE):
            return True
    return False


def match_services(host: str, cname: Optional[str], http_data: Dict[str, Any], patterns: Dict[str, Any]) -> List[ServiceMatch]:
    matches: List[ServiceMatch] = []

    body_parts: List[str] = []
    header_parts: List[str] = []
    for scheme in ("https", "http"):
        if scheme in http_data and isinstance(http_data[scheme], dict):
            body_parts.append(http_data[scheme].get("body_snippet", "") or "")
            header_parts.append("\n".join(f"{k}: {v}" for k, v in (http_data[scheme].get("headers", {}) or {}).items()))

    body_blob = "\n".join(body_parts)
    header_blob = "\n".join(header_parts)

    for service in patterns.get("services", []):
        reasons: List[str] = []

        cname_suffixes = service.get("cname_suffixes", [])
        if cname and any(cname.endswith(sfx.lower().strip(".")) for sfx in [s.lower().strip(".") for s in cname_suffixes]):
            reasons.append("CNAME suffix match")

        if service.get("http_body_regex") and _regex_match(service["http_body_regex"], body_blob):
            reasons.append("HTTP body fingerprint match")

        if service.get("http_header_regex") and _regex_match(service["http_header_regex"], header_blob):
            reasons.append("HTTP header fingerprint match")

        if reasons:
            confidence = "high" if len(reasons) >= 2 else "medium"
            matches.append(
                ServiceMatch(
                    name=service.get("name", "unknown"),
                    confidence=confidence,
                    reasons=reasons,
                    references=service.get("references", []),
                )
            )

    return matches


def scan_target(target: str, resolver: dns.resolver.Resolver, patterns: Dict[str, Any], do_http: bool) -> Finding:
    cnames = _resolve(resolver, target, "CNAME")
    cname = cnames[0] if cnames else None

    a_records = _resolve(resolver, target, "A")
    aaaa_records = _resolve(resolver, target, "AAAA")
    ns_records = _resolve(resolver, target, "NS")

    http_data = fetch_http(target) if do_http else {"enabled": False}

    notes: List[str] = []
    potential_takeover = False

    dangling, dangling_reason = maybe_dangling_cname(cname, resolver)
    if dangling:
        potential_takeover = True
        notes.append(dangling_reason)

    ns_notes = maybe_expired_ns(ns_records)
    if ns_notes:
        notes.extend(ns_notes)

    service_matches = match_services(target, cname, http_data, patterns)
    if service_matches:
        potential_takeover = True

    status = "ok"
    if potential_takeover:
        status = "potential_takeover"
    elif not (cname or a_records or aaaa_records):
        status = "unresolved"

    return Finding(
        target=target,
        status=status,
        potential_takeover=potential_takeover,
        dns={
            "cname": cname,
            "cnames": cnames,
            "a": a_records,
            "aaaa": aaaa_records,
            "ns": ns_records,
        },
        http=http_data,
        matched_services=[asdict(m) for m in service_matches],
        notes=notes,
    )


def write_json(path: str, findings: List[Finding]) -> None:
    payload = {
        "summary": {
            "total": len(findings),
            "potential_takeovers": sum(1 for f in findings if f.potential_takeover),
            "unresolved": sum(1 for f in findings if f.status == "unresolved"),
        },
        "findings": [asdict(f) for f in findings],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_markdown(path: str, findings: List[Finding]) -> None:
    lines: List[str] = []
    lines.append("# Subdomain Takeover Scan Report")
    lines.append("")
    lines.append(f"- Total targets: {len(findings)}")
    lines.append(f"- Potential takeovers: {sum(1 for f in findings if f.potential_takeover)}")
    lines.append(f"- Unresolved: {sum(1 for f in findings if f.status == 'unresolved')}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for f in findings:
        lines.append(f"### `{f.target}`")
        lines.append(f"- Status: `{f.status}`")
        lines.append(f"- Potential takeover: `{f.potential_takeover}`")
        lines.append(f"- CNAME: `{f.dns.get('cname')}`")
        lines.append(f"- A records: `{', '.join(f.dns.get('a', [])) or '-'}`")
        lines.append(f"- AAAA records: `{', '.join(f.dns.get('aaaa', [])) or '-'}`")
        lines.append(f"- NS records: `{', '.join(f.dns.get('ns', [])) or '-'}`")

        if f.matched_services:
            lines.append("- Matched services:")
            for m in f.matched_services:
                lines.append(
                    f"  - `{m['name']}` (confidence: `{m['confidence']}`) - reasons: {', '.join(m['reasons'])}"
                )

        if f.notes:
            lines.append("- Notes:")
            for note in f.notes:
                lines.append(f"  - {note}")

        lines.append("")

    Path(path).write_text("\n".join(lines), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Subdomain takeover monitoring tool")
    parser.add_argument("targets", nargs="*", help="Domains/subdomains to scan")
    parser.add_argument("-f", "--file", help="File containing domains/subdomains (one per line)")
    parser.add_argument("-p", "--patterns", default="patterns.json", help="Path to vulnerable service patterns JSON")
    parser.add_argument("--json-out", default="scan_results.json", help="JSON output path")
    parser.add_argument("--md-out", default="scan_results.md", help="Markdown output path")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="DNS/HTTP timeout seconds")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Concurrent worker count")
    parser.add_argument("--no-http", action="store_true", help="Disable HTTP fingerprint checks")
    parser.add_argument("--resolver", action="append", help="Custom DNS resolver IP (can specify multiple)")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        targets = normalize_targets(args.targets, args.file)
    except FileNotFoundError as exc:
        print(f"error: input file not found: {exc}", file=sys.stderr)
        return 2

    if not targets:
        parser.print_help(sys.stderr)
        print("\nerror: provide targets via CLI args or --file", file=sys.stderr)
        return 2

    try:
        patterns = load_patterns(args.patterns)
    except FileNotFoundError:
        print(f"error: patterns file not found: {args.patterns}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid patterns JSON: {exc}", file=sys.stderr)
        return 2

    resolver = dns.resolver.Resolver()
    resolver.lifetime = args.timeout
    resolver.timeout = args.timeout
    if args.resolver:
        resolver.nameservers = args.resolver

    findings: List[Finding] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(scan_target, t, resolver, patterns, not args.no_http): t
            for t in targets
        }
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                findings.append(fut.result())
            except Exception as exc:
                findings.append(
                    Finding(
                        target=t,
                        status="error",
                        potential_takeover=False,
                        dns={},
                        http={},
                        matched_services=[],
                        notes=[f"scan error: {exc}"],
                    )
                )

    findings.sort(key=lambda x: x.target)

    write_json(args.json_out, findings)
    write_markdown(args.md_out, findings)

    print(f"Scanned {len(findings)} target(s)")
    print(f"Potential takeovers: {sum(1 for f in findings if f.potential_takeover)}")
    print(f"JSON report: {args.json_out}")
    print(f"Markdown report: {args.md_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
