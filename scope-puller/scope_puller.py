#!/usr/bin/env python3
"""
Pull bug bounty program scope from HackerOne and Bugcrowd.

- Parses program URLs:
  - https://hackerone.com/programs/<handle>
  - https://bugcrowd.com/<handle>/program
- Fetches scope targets (best effort from public endpoints/pages)
- Checks bounty eligibility
- Extracts recent report statistics (best effort)
- Outputs JSON and Markdown
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

import requests

TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))
from recon_storage import atomic_write_json, atomic_write_text, recon_bucket, safe_slug


USER_AGENT = "scope-puller/1.0"
DEFAULT_TIMEOUT = 20
DEFAULT_RETRIES = 5
DEFAULT_BACKOFF = 1.5
BOUNTY_CORE_PATH = Path.home() / "projects" / "bounty-core"
DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"


class ScopePullerError(Exception):
    pass



def _sanitize_core_program(program: str, default: str = "scope-puller") -> str:
    safe_program = re.sub(r"[^a-z0-9_\-]+", "-", (program or default).lower()).strip("-")
    return safe_program or default


def _load_bounty_core():
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


@dataclass
class ProgramRef:
    platform: str
    handle: str
    url: str


def parse_program_url(url: str) -> ProgramRef:
    p = urlparse(url.strip())
    if p.scheme not in {"http", "https"}:
        raise ScopePullerError(f"Unsupported URL scheme: {url}")

    host = p.netloc.lower()
    parts = [x for x in p.path.split("/") if x]

    if host.endswith("hackerone.com"):
        if len(parts) >= 2 and parts[0] == "programs":
            return ProgramRef(platform="hackerone", handle=parts[1], url=url)
        raise ScopePullerError(f"Invalid HackerOne URL format: {url}")

    if host.endswith("bugcrowd.com"):
        if len(parts) >= 2 and parts[1] == "program":
            return ProgramRef(platform="bugcrowd", handle=parts[0], url=url)
        raise ScopePullerError(f"Invalid Bugcrowd URL format: {url}")

    raise ScopePullerError(f"Unsupported host: {url}")


class HttpClient:
    def __init__(self, timeout: int, max_retries: int, backoff: float) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            }
        )

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        sleep_s = self.backoff
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
            except requests.RequestException as exc:
                if attempt == self.max_retries:
                    raise ScopePullerError(f"Request failed: {url}: {exc}") from exc
                time.sleep(sleep_s)
                sleep_s = min(sleep_s * 2, 60)
                continue

            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait_s = sleep_s
                if retry_after and retry_after.isdigit():
                    wait_s = max(float(retry_after), 1.0)

                if attempt == self.max_retries:
                    raise ScopePullerError(f"Rate limited (429): {url}")
                time.sleep(wait_s)
                sleep_s = min(sleep_s * 2, 60)
                continue

            if 500 <= resp.status_code < 600:
                if attempt == self.max_retries:
                    raise ScopePullerError(f"Server error {resp.status_code}: {url}")
                time.sleep(sleep_s)
                sleep_s = min(sleep_s * 2, 60)
                continue

            return resp

        raise ScopePullerError(f"Exhausted retries: {url}")


def normalize_target(raw: Dict[str, Any]) -> Dict[str, Any]:
    asset = (
        raw.get("asset_identifier")
        or raw.get("target")
        or raw.get("name")
        or raw.get("endpoint")
        or raw.get("url")
        or ""
    )
    return {
        "asset": str(asset),
        "type": raw.get("asset_type") or raw.get("type") or "unknown",
        "instruction": raw.get("instruction") or raw.get("description") or "",
        "eligible_for_bounty": bool(
            raw["eligible_for_bounty"] if raw.get("eligible_for_bounty") is not None else raw.get("offers_bounty", False)
        ),
    }


def fetch_hackerone(client: HttpClient, handle: str) -> Dict[str, Any]:
    query = """
    query ProgramBrief($handle: String!) {
      team(handle: $handle) {
        handle
        name
        state
        offers_bounties
        number_of_reports_for_user
        structured_scopes {
          eligible_for_submission
          eligible_for_bounty
          instruction
          asset_type
          asset_identifier
        }
      }
    }
    """
    payload = {"query": query, "variables": {"handle": handle}}
    resp = client.request("POST", "https://hackerone.com/graphql", json=payload)
    if resp.status_code != 200:
        raise ScopePullerError(f"HackerOne returned HTTP {resp.status_code} for {handle}")

    data = resp.json()
    team = (data.get("data") or {}).get("team")
    if not team:
        raise ScopePullerError(f"HackerOne program not available: {handle}")

    scopes = team.get("structured_scopes") or []
    in_scope = [
        normalize_target(x)
        for x in scopes
        if x.get("eligible_for_submission", True)
    ]

    return {
        "platform": "hackerone",
        "program_handle": team.get("handle") or handle,
        "program_name": team.get("name") or handle,
        "bounty_eligible": bool(team.get("offers_bounties")),
        "scope_targets": in_scope,
        "recent_report_stats": {
            "reports_total_visible": team.get("number_of_reports_for_user"),
            "note": "Public field visibility depends on viewer/program.",
        },
        "raw_program_state": team.get("state"),
    }


def try_json_from_html(html: str) -> Optional[Dict[str, Any]]:
    patterns = [
        r'<script[^>]+id="__NEXT_DATA__"[^>]*>(\{.*?\})</script>',
        r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\});",
    ]
    for pat in patterns:
        m = re.search(pat, html, re.DOTALL)
        if not m:
            continue
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
    return None


def collect_targets(node: Any, out: List[Dict[str, Any]]) -> None:
    if isinstance(node, dict):
        keys = {k.lower() for k in node.keys()}
        if {"target", "name", "asset_identifier", "endpoint", "url"} & keys:
            nt = normalize_target(node)
            if nt["asset"]:
                out.append(nt)
        for v in node.values():
            collect_targets(v, out)
    elif isinstance(node, list):
        for item in node:
            collect_targets(item, out)


def collect_numeric_stats(node: Any, out: Dict[str, int]) -> None:
    if isinstance(node, dict):
        wanted = {
            "reports_count",
            "total_reports",
            "submitted_reports",
            "triaged_reports",
            "resolved_reports",
            "accepted_reports",
        }
        for k, v in node.items():
            if k in wanted and isinstance(v, int):
                out[k] = v
            collect_numeric_stats(v, out)
    elif isinstance(node, list):
        for item in node:
            collect_numeric_stats(item, out)


def dedupe_targets(targets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []
    for t in targets:
        key = (t.get("asset", "").strip().lower(), t.get("type", "").strip().lower())
        if not key[0] or key in seen:
            continue
        seen.add(key)
        result.append(t)
    return result


def fetch_bugcrowd(client: HttpClient, handle: str) -> Dict[str, Any]:
    url = f"https://bugcrowd.com/{handle}/program"
    resp = client.request("GET", url)
    if resp.status_code != 200:
        raise ScopePullerError(f"Bugcrowd returned HTTP {resp.status_code} for {handle}")

    html = resp.text
    state = try_json_from_html(html)

    targets: List[Dict[str, Any]] = []
    stats: Dict[str, Any] = {"note": "Public stats availability varies by program/page."}
    bounty_eligible = False
    program_name = handle

    if state is not None:
        collect_targets(state, targets)
        targets = dedupe_targets(targets)

        collect_numeric_stats(state, stats)

        dump = json.dumps(state)
        bounty_eligible = bool(
            re.search(
                r'"(bounty|cash_reward|is_bounty_enabled|offers_bounty)"\s*:\s*(true|1|"yes")',
                dump,
                re.IGNORECASE,
            )
        )
        m_name = re.search(r'"name"\s*:\s*"([^"]{2,120})"', dump)
        if m_name:
            program_name = m_name.group(1)
    else:
        hits = re.findall(r"(https?://[^\s\"'<>]+|\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", html)
        seen = set()
        for h in hits:
            if h in seen:
                continue
            seen.add(h)
            targets.append(
                {
                    "asset": h,
                    "type": "url_or_domain",
                    "instruction": "Heuristic extraction from public HTML",
                    "eligible_for_bounty": False,
                }
            )
        targets = dedupe_targets(targets)

    return {
        "platform": "bugcrowd",
        "program_handle": handle,
        "program_name": program_name,
        "bounty_eligible": bounty_eligible,
        "scope_targets": targets,
        "recent_report_stats": stats,
        "source_url": url,
    }


def render_markdown(programs: List[Dict[str, Any]]) -> str:
    lines: List[str] = ["# Bug Bounty Scope Pull Results", ""]
    for p in programs:
        lines.append(f"## {p.get('program_name', 'Unknown')} ({p.get('platform')})")
        lines.append("")
        lines.append(f"- Program handle: `{p.get('program_handle', '')}`")
        lines.append(f"- Bounty eligible: `{'yes' if p.get('bounty_eligible') else 'no'}`")
        stats = p.get("recent_report_stats") or {}
        if stats:
            pairs = ", ".join(f"{k}={v}" for k, v in stats.items())
            lines.append(f"- Recent report stats: `{pairs}`")
        lines.append("")
        targets = p.get("scope_targets") or []
        lines.append(f"### Scope Targets ({len(targets)})")
        lines.append("")
        if targets:
            lines.append("| Asset | Type | Bounty Eligible | Notes |")
            lines.append("|---|---|---:|---|")
            for t in targets:
                asset = str(t.get("asset", "")).replace("|", "\\|")
                ttype = str(t.get("type", "")).replace("|", "\\|")
                eligible = "yes" if t.get("eligible_for_bounty") else "no"
                note = str(t.get("instruction", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {asset} | {ttype} | {eligible} | {note} |")
        else:
            lines.append("No public scope targets found.")
        lines.append("")
    return "\n".join(lines)


def _target_asset(target: Dict[str, Any]) -> str:
    return str(target.get("asset") or "").strip()


def _asset_domain(asset: str) -> Optional[str]:
    asset = asset.strip()
    if not asset:
        return None
    parsed = urlparse(asset if "://" in asset else f"//{asset}")
    host = parsed.hostname
    if host:
        return host.lower().lstrip("*.").rstrip(".")
    candidate = asset.lstrip("*.").rstrip(".")
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", candidate):
        return candidate.lower()
    return None


def _scope_text_artifacts(program_data: Dict[str, Any]) -> Dict[str, str]:
    targets = program_data.get("scope_targets") or []
    assets = sorted({asset for target in targets for asset in [_target_asset(target)] if asset})
    eligible_assets = sorted({
        asset
        for target in targets
        for asset in [_target_asset(target)]
        if asset and target.get("eligible_for_bounty", False)
    })
    domains = sorted({domain for asset in assets for domain in [_asset_domain(asset)] if domain})
    return {
        "in-scope.txt": "\n".join(eligible_assets or assets) + ("\n" if assets or eligible_assets else ""),
        "domains.txt": "\n".join(domains) + ("\n" if domains else ""),
    }


def _combined_scope_text_artifacts(programs: List[Dict[str, Any]]) -> Dict[str, str]:
    targets = [target for program in programs for target in (program.get("scope_targets") or [])]
    return _scope_text_artifacts({"scope_targets": targets})


def save_scope_recon_outputs(
    programs: List[Dict[str, Any]],
    failures: List[Dict[str, str]],
    *,
    output_dir: Optional[str],
    json_out: Optional[str],
    md_out: Optional[str],
    core_program: Optional[str],
    family: str,
    lane: str,
    filters: Dict[str, Any],
) -> List[Dict[str, str]]:
    """Persist full scope inventory under canonical recon storage unless paths are explicit."""
    written: List[Dict[str, str]] = []

    if output_dir or json_out or md_out:
        base = Path(output_dir) if output_dir else Path(".")
        json_path = Path(json_out) if json_out else base / "scope_results.json"
        md_path = Path(md_out) if md_out else base / "scope_results.md"
        payload = {
            "generated_at_epoch": int(time.time()),
            "programs": programs,
            "failures": failures,
            "filters": filters,
        }
        atomic_write_json(json_path, payload)
        atomic_write_text(md_path, render_markdown(programs))
        files = {"json": str(json_path), "markdown": str(md_path)}
        text_base = Path(output_dir) if output_dir else json_path.parent
        for name, content in _combined_scope_text_artifacts(programs).items():
            path = text_base / name
            atomic_write_text(path, content)
            files[name] = str(path)
        written.append(files)
        return written

    for program_data in programs:
        program = _sanitize_core_program(core_program) if core_program else _infer_core_program(program_data)
        scope_part = safe_slug(str(program_data.get("program_handle") or program_data.get("platform") or program), default="scope")
        bucket = recon_bucket(program, family=family, lane=lane, parts=("scope", scope_part))
        payload = {
            "generated_at_epoch": int(time.time()),
            "programs": [program_data],
            "failures": [f for f in failures if f.get("url") in {program_data.get("input_url"), program_data.get("source_url")}],
            "filters": filters,
        }
        json_path = bucket.bucket / "scope_results.json"
        md_path = bucket.bucket / "scope_results.md"
        atomic_write_json(json_path, payload)
        atomic_write_text(md_path, render_markdown([program_data]))
        files = {"json": str(json_path), "markdown": str(md_path)}
        for name, content in _scope_text_artifacts(program_data).items():
            path = bucket.bucket / name
            atomic_write_text(path, content)
            files[name] = str(path)
        written.append(files)

    if failures and not programs:
        bucket = recon_bucket(core_program or "scope-puller", family=family, lane=lane, parts=("scope", "failures"))
        json_path = bucket.bucket / "scope_results.json"
        payload = {
            "generated_at_epoch": int(time.time()),
            "programs": [],
            "failures": failures,
            "filters": filters,
        }
        atomic_write_json(json_path, payload)
        atomic_write_text(bucket.bucket / "scope_results.md", render_markdown([]))
        written.append({"json": str(json_path), "markdown": str(bucket.bucket / "scope_results.md")})

    return written


def _infer_core_program(program: Dict[str, Any]) -> str:
    return _sanitize_core_program(
        str(program.get("program_handle") or program.get("program_name") or program.get("platform") or "scope-puller")
    )


def _program_summary_to_core_payload(program_data: Dict[str, Any], *, program: str, family: str, lane: str) -> Dict[str, Any]:
    platform = program_data.get("platform") or "unknown"
    handle = program_data.get("program_handle") or "unknown"
    targets = program_data.get("scope_targets") or []
    return {
        "program": program,
        "family": family,
        "lane": lane,
        "type": "scope",
        "status": "raw",
        "severity": "INFO",
        "title": f"Scope pull: {program_data.get('program_name') or handle}",
        "asset": str(program_data.get("input_url") or program_data.get("source_url") or handle),
        "url": str(program_data.get("input_url") or program_data.get("source_url") or ""),
        "platform": platform,
        "program_handle": handle,
        "program_name": program_data.get("program_name"),
        "bounty_eligible": bool(program_data.get("bounty_eligible")),
        "scope_target_count": len(targets),
        "recent_report_stats": program_data.get("recent_report_stats") or {},
        "summary": "Scope puller fetched public program metadata and scope targets.",
        "evidence": [
            f"platform={platform}",
            f"program={handle}",
            f"scope_targets={len(targets)}",
            f"bounty_eligible={bool(program_data.get('bounty_eligible'))}",
        ],
        "tags": ["scope", platform, "program-summary"],
        "source_tool": "scope_puller.py",
        "source_repo": "bounty-tools",
        "agent": "bounty-tools.scope-puller",
    }


def write_core_findings(core_program: Optional[str], family: str, lane: str, programs: List[Dict[str, Any]]) -> Dict[str, Any]:
    add_finding, error = _load_bounty_core()
    if add_finding is None:
        return {"ok": False, "error": f"bounty-core unavailable: {error}", "written": 0, "new": 0}

    written = 0
    new = 0
    last_layout = None
    errors: List[str] = []
    program_names: List[str] = []
    for program_data in programs:
        program = _sanitize_core_program(core_program) if core_program else _infer_core_program(program_data)
        program_names.append(program)
        payloads = [_program_summary_to_core_payload(program_data, program=program, family=family, lane=lane)]
        for payload in payloads:
            try:
                result = add_finding(payload, program=program, family=family, lane=lane)
                written += 1
                if result.get("is_new"):
                    new += 1
                last_layout = result.get("layout") or last_layout
            except Exception as exc:
                errors.append(str(exc))

    return {
        "ok": not errors,
        "written": written,
        "new": new,
        "layout": last_layout,
        "errors": errors,
        "programs": sorted(set(program_names)),
    }


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pull program scope from HackerOne and Bugcrowd.")
    parser.add_argument(
        "urls",
        nargs="+",
        help="Program URLs (hackerone.com/programs/* or bugcrowd.com/*/program)",
    )
    parser.add_argument("--output", default=None, help="Output directory (default: canonical recon/scope/<program-or-platform>/)")
    parser.add_argument("--json-out", default=None, help="Explicit JSON output path (overrides canonical default)")
    parser.add_argument("--md-out", default=None, help="Explicit Markdown output path (overrides canonical default)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    parser.add_argument("--max-retries", type=int, default=DEFAULT_RETRIES, help="Max retries")
    parser.add_argument("--backoff", type=float, default=DEFAULT_BACKOFF, help="Initial backoff seconds")
    parser.add_argument("--bounty-only", action="store_true", help="Only include targets eligible for bounty")
    parser.add_argument("--core-program", "--name", dest="core_program", default=None, help="bounty-core program/target identity/name (default: infer per pulled program handle)")
    parser.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    parser.add_argument("--lane", default=DEFAULT_CORE_LANE, help=f"bounty-core storage lane (default: {DEFAULT_CORE_LANE})")
    parser.add_argument("--write-core", action="store_true", help="Opt in to bounty-core summary ledger/report/index writes")
    parser.add_argument("--no-core", action="store_true", help="Disable bounty-core ledger/report/index writes; recon artifacts are still written")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    client = HttpClient(timeout=args.timeout, max_retries=args.max_retries, backoff=args.backoff)

    refs: List[ProgramRef] = []
    failures: List[Dict[str, str]] = []
    for raw_url in args.urls:
        try:
            refs.append(parse_program_url(raw_url))
        except Exception as exc:
            failures.append({"url": raw_url, "error": str(exc)})

    programs: List[Dict[str, Any]] = []
    for ref in refs:
        try:
            if ref.platform == "hackerone":
                result = fetch_hackerone(client, ref.handle)
            elif ref.platform == "bugcrowd":
                result = fetch_bugcrowd(client, ref.handle)
            else:
                raise ScopePullerError(f"Unsupported platform: {ref.platform}")
            result["input_url"] = ref.url
            programs.append(result)
        except Exception as exc:
            failures.append({"url": ref.url, "error": str(exc)})

    # Filter for bounty-eligible targets only if requested
    if args.bounty_only:
        for p in programs:
            original_count = len(p.get("scope_targets", []))
            p["scope_targets"] = [
                t for t in p["scope_targets"]
                if t.get("eligible_for_bounty", False)
            ]
            filtered_count = len(p["scope_targets"])
            print(f"Filtered {p.get('program_name', 'Unknown')}: {original_count} -> {filtered_count} bounty targets")

    output_files = save_scope_recon_outputs(
        programs,
        failures,
        output_dir=args.output,
        json_out=args.json_out,
        md_out=args.md_out,
        core_program=args.core_program,
        family=args.family,
        lane=args.lane,
        filters={"bounty_only": args.bounty_only},
    )

    if args.write_core and not args.no_core and programs:
        core_result = write_core_findings(args.core_program, args.family, args.lane, programs)
        if core_result.get("ok"):
            programs_label = ",".join(core_result.get("programs") or [])
            print(f"bounty-core: wrote={core_result['written']} new={core_result['new']} program={programs_label} family={args.family} lane={args.lane}")
        else:
            print(f"bounty-core: skipped/failed: {core_result.get('error') or core_result.get('errors')}", file=sys.stderr)

    if not args.write_core:
        print("bounty-core: summary promotion disabled by default (use --write-core to opt in)")

    for files in output_files:
        if "json" in files:
            print(f"Wrote JSON: {files['json']}")
        if "markdown" in files:
            print(f"Wrote Markdown: {files['markdown']}")

    if failures:
        print(f"Completed with {len(failures)} failure(s).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
