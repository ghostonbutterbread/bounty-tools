#!/usr/bin/env python3
"""
GitHub dorking tool for searching potential secrets in public repositories.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


GITHUB_API_BASE = "https://api.github.com"
DEFAULT_DORKS_FILE = "dorks.json"
DEFAULT_OUTPUT_JSON = "results.json"
DEFAULT_OUTPUT_MD = "results.md"


def load_dorks(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dorks file not found: {path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        dorks = data.get("dorks", [])
    elif isinstance(data, list):
        dorks = data
    else:
        raise ValueError("dorks.json must be a list or an object with a 'dorks' list")

    if not isinstance(dorks, list) or not all(isinstance(x, str) for x in dorks):
        raise ValueError("Invalid dorks format; expected list[str]")

    return [d.strip() for d in dorks if d.strip()]


def build_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "github-dorks-tool",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_next_link(link_header: str) -> Optional[str]:
    if not link_header:
        return None
    for part in link_header.split(","):
        if 'rel="next"' in part:
            m = re.search(r"<([^>]+)>", part)
            if m:
                return m.group(1)
    return None


def wait_for_rate_limit(response: requests.Response, verbose: bool = False) -> None:
    if response.status_code not in (403, 429):
        return

    remaining = response.headers.get("X-RateLimit-Remaining")
    reset = response.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset:
        reset_ts = int(reset)
        sleep_for = max(reset_ts - int(time.time()) + 1, 1)
        if verbose:
            print(f"[rate-limit] Sleeping {sleep_for}s until reset...", file=sys.stderr)
        time.sleep(sleep_for)
        return

    retry_after = response.headers.get("Retry-After")
    if retry_after:
        sleep_for = max(int(retry_after), 1)
        if verbose:
            print(f"[retry] Sleeping {sleep_for}s (Retry-After)...", file=sys.stderr)
        time.sleep(sleep_for)
        return

    # Secondary rate limit fallback
    if verbose:
        print("[rate-limit] Secondary limit hit, sleeping 60s...", file=sys.stderr)
    time.sleep(60)


def github_get(
    session: requests.Session,
    url: str,
    params: Optional[Dict[str, Any]] = None,
    verbose: bool = False,
    max_retries: int = 4,
) -> requests.Response:
    for attempt in range(max_retries):
        resp = session.get(url, params=params, timeout=30)
        if resp.status_code in (403, 429):
            wait_for_rate_limit(resp, verbose=verbose)
            continue
        if resp.status_code >= 500:
            sleep_for = 2 ** attempt
            if verbose:
                print(f"[server-error] {resp.status_code}, retrying in {sleep_for}s...", file=sys.stderr)
            time.sleep(sleep_for)
            continue
        return resp
    return resp


def is_bounty_eligible(
    repo: Dict[str, Any],
    allowed_orgs: Optional[List[str]],
    bounty_topics: Optional[List[str]],
) -> Dict[str, Any]:
    """
    Heuristic eligibility check:
    - If allowed_orgs is set, repo owner login must match one of them.
    - If bounty_topics is set, repo topics must contain at least one of them.
    """
    reasons: List[str] = []
    eligible = True

    owner_login = (repo.get("owner") or {}).get("login", "").lower()
    topics = [t.lower() for t in (repo.get("topics") or [])]

    if allowed_orgs:
        allowed = {o.lower() for o in allowed_orgs}
        if owner_login not in allowed:
            eligible = False
            reasons.append("owner_not_in_allowed_orgs")
        else:
            reasons.append("owner_in_allowed_orgs")

    if bounty_topics:
        wanted = {t.lower() for t in bounty_topics}
        if wanted.intersection(topics):
            reasons.append("has_bounty_topic")
        else:
            eligible = False
            reasons.append("missing_bounty_topic")

    if not allowed_orgs and not bounty_topics:
        reasons.append("no_eligibility_filters_configured")

    return {
        "eligible": eligible,
        "reasons": reasons,
    }


def search_code_for_dork(
    session: requests.Session,
    dork: str,
    per_page: int,
    max_pages: int,
    verbose: bool = False,
) -> List[Dict[str, Any]]:
    url = f"{GITHUB_API_BASE}/search/code"
    params = {"q": dork, "per_page": per_page, "page": 1}
    results: List[Dict[str, Any]] = []

    current_page = 0
    while current_page < max_pages:
        current_page += 1
        resp = github_get(session, url, params=params, verbose=verbose)

        if resp.status_code == 422:
            if verbose:
                print(f"[skip] Invalid/overbroad query: {dork}", file=sys.stderr)
            break
        if resp.status_code != 200:
            if verbose:
                print(
                    f"[error] Search failed for dork '{dork}' with status {resp.status_code}: {resp.text[:200]}",
                    file=sys.stderr,
                )
            break

        data = resp.json()
        items = data.get("items", [])
        results.extend(items)

        next_url = parse_next_link(resp.headers.get("Link", ""))
        if not next_url:
            break
        url = next_url
        params = None

    return results


def collect_repo_metadata(
    session: requests.Session,
    full_name: str,
    verbose: bool = False,
) -> Dict[str, Any]:
    repo_url = f"{GITHUB_API_BASE}/repos/{full_name}"
    resp = github_get(session, repo_url, verbose=verbose)
    if resp.status_code != 200:
        if verbose:
            print(f"[warn] Failed to fetch repo metadata for {full_name}", file=sys.stderr)
        return {}
    return resp.json()


def normalize_item(item: Dict[str, Any], dork: str) -> Dict[str, Any]:
    repo = item.get("repository") or {}
    return {
        "dork": dork,
        "name": item.get("name"),
        "path": item.get("path"),
        "html_url": item.get("html_url"),
        "sha": item.get("sha"),
        "score": item.get("score"),
        "repository": {
            "id": repo.get("id"),
            "full_name": repo.get("full_name"),
            "html_url": repo.get("html_url"),
            "private": repo.get("private"),
            "owner": (repo.get("owner") or {}).get("login"),
        },
    }


def write_json(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_markdown(path: str, payload: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append("# GitHub Dork Scan Report")
    lines.append("")
    lines.append(f"- Generated: `{payload['generated_at']}`")
    lines.append(f"- Total results: `{payload['summary']['total_results']}`")
    lines.append(f"- Eligible results: `{payload['summary']['eligible_results']}`")
    lines.append("")

    lines.append("## Dorks Used")
    lines.append("")
    for d in payload["dorks"]:
        lines.append(f"- `{d}`")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    if not payload["results"]:
        lines.append("No results found.")
    else:
        for idx, r in enumerate(payload["results"], start=1):
            repo_name = r["repository"]["full_name"]
            lines.append(f"### {idx}. `{repo_name}` - `{r['path']}`")
            lines.append("")
            lines.append(f"- Dork: `{r['dork']}`")
            lines.append(f"- File: [{r['name']}]({r['html_url']})")
            lines.append(f"- Repository: [{repo_name}]({r['repository']['html_url']})")
            lines.append(f"- Eligible: `{r['bounty_eligibility']['eligible']}`")
            lines.append(
                f"- Eligibility reasons: `{', '.join(r['bounty_eligibility']['reasons'])}`"
            )
            lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def dedupe_results(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for row in rows:
        key = (row.get("sha"), row.get("html_url"))
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def parse_csv_arg(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    entries = [x.strip() for x in value.split(",")]
    entries = [x for x in entries if x]
    return entries or None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Search GitHub code for common dorks and mark bounty eligibility."
    )
    parser.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token")
    parser.add_argument("--dorks-file", default=DEFAULT_DORKS_FILE, help="Path to dorks.json")
    parser.add_argument(
        "--dork",
        action="append",
        default=[],
        help="Custom dork query (can be repeated)",
    )
    parser.add_argument(
        "--allowed-orgs",
        default=None,
        help="Comma-separated repo owners/orgs considered bounty-eligible",
    )
    parser.add_argument(
        "--bounty-topics",
        default=None,
        help="Comma-separated repo topics required for eligibility (heuristic)",
    )
    parser.add_argument("--per-page", type=int, default=50, help="GitHub search per_page (max 100)")
    parser.add_argument("--max-pages", type=int, default=2, help="Max pages per dork")
    parser.add_argument("--out-json", default=DEFAULT_OUTPUT_JSON, help="JSON output path")
    parser.add_argument("--out-md", default=DEFAULT_OUTPUT_MD, help="Markdown output path")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    if not args.token:
        print("Error: GitHub token is required. Use --token or set GITHUB_TOKEN.", file=sys.stderr)
        return 1

    try:
        dorks = load_dorks(args.dorks_file)
    except Exception as e:
        print(f"Error loading dorks: {e}", file=sys.stderr)
        return 1

    dorks.extend(args.dork)
    dorks = [d.strip() for d in dorks if d.strip()]
    dorks = list(dict.fromkeys(dorks))

    if not dorks:
        print("Error: No dorks to run.", file=sys.stderr)
        return 1

    allowed_orgs = parse_csv_arg(args.allowed_orgs)
    bounty_topics = parse_csv_arg(args.bounty_topics)

    session = requests.Session()
    session.headers.update(build_headers(args.token))

    all_results: List[Dict[str, Any]] = []
    repo_cache: Dict[str, Dict[str, Any]] = {}

    for dork in dorks:
        if args.verbose:
            print(f"[search] {dork}", file=sys.stderr)
        items = search_code_for_dork(
            session=session,
            dork=dork,
            per_page=min(max(args.per_page, 1), 100),
            max_pages=max(args.max_pages, 1),
            verbose=args.verbose,
        )

        for item in items:
            normalized = normalize_item(item, dork=dork)
            full_name = normalized["repository"]["full_name"]
            if full_name and full_name not in repo_cache:
                repo_cache[full_name] = collect_repo_metadata(session, full_name, verbose=args.verbose)

            repo_meta = repo_cache.get(full_name, {})
            eligibility = is_bounty_eligible(repo_meta, allowed_orgs, bounty_topics)
            normalized["bounty_eligibility"] = eligibility
            normalized["repository"]["topics"] = repo_meta.get("topics", [])
            normalized["repository"]["license"] = (repo_meta.get("license") or {}).get("spdx_id")
            all_results.append(normalized)

    all_results = dedupe_results(all_results)
    eligible_count = sum(1 for r in all_results if r["bounty_eligibility"]["eligible"])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dorks": dorks,
        "summary": {
            "total_results": len(all_results),
            "eligible_results": eligible_count,
            "ineligible_results": len(all_results) - eligible_count,
        },
        "filters": {
            "allowed_orgs": allowed_orgs,
            "bounty_topics": bounty_topics,
        },
        "results": all_results,
    }

    write_json(args.out_json, payload)
    write_markdown(args.out_md, payload)

    print(f"Wrote JSON: {args.out_json}")
    print(f"Wrote Markdown: {args.out_md}")
    print(
        f"Results: total={payload['summary']['total_results']} eligible={payload['summary']['eligible_results']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())