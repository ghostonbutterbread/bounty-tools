#!/usr/bin/env python3
import argparse
import asyncio
import os
import re
import socket
import sys
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
TOOLS_ROOT = Path(__file__).resolve().parents[1]
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))
from recon_storage import atomic_write_json, atomic_write_text, recon_bucket, safe_slug

try:
    from playwright.async_api import async_playwright
except Exception:
    async_playwright = None


BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))
DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"


DEFAULT_COMMON_PATHS = [
    "admin",
    "login",
    "dashboard",
    "api",
    "robots.txt",
    "sitemap.xml",
    "uploads",
    "assets",
    "backup",
    "config",
]


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not re.match(r"^https?://", target, flags=re.IGNORECASE):
        return f"http://{target}"
    return target


def _sanitize_core_program(program: str, default: str = "visual-recon") -> str:
    safe_program = re.sub(r"[^a-z0-9_\-]+", "-", (program or default).lower()).strip("-")
    return safe_program or default


def _infer_core_program(targets: list[str]) -> str:
    if not targets:
        return "visual-recon"
    parsed = urlparse(normalize_target(targets[0]))
    host = (parsed.hostname or parsed.netloc or targets[0]).lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return _sanitize_core_program(host)


def _host_slug(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    host = parsed.hostname or parsed.netloc or target
    return safe_slug(host.lower(), default="batch")


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid.uuid4().hex[:8]}"


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
class DirResult:
    path: str
    status_code: int
    url: str


@dataclass
class TargetResult:
    input: str
    base_url: str
    final_url: str | None
    ip: str | None
    screenshot: str | None
    page_title: str | None
    status_code: int | None
    headers: dict[str, str]
    technologies: list[str]
    discovered_paths: list[DirResult]
    errors: list[str]


class VisualRecon:
    def __init__(self, output_dir: Path, wordlist: Path, timeout: int = 10, screenshot_timeout_ms: int = 15000):
        self.output_dir = output_dir
        self.screenshots_dir = output_dir / "screenshots"
        self.wordlist = wordlist
        self.timeout = timeout
        self.screenshot_timeout_ms = screenshot_timeout_ms

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)

    def load_paths(self) -> list[str]:
        if self.wordlist.exists():
            paths = []
            for line in self.wordlist.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                paths.append(line.lstrip("/"))
            if paths:
                return paths
        return DEFAULT_COMMON_PATHS

    def detect_technologies(self, headers: dict[str, str]) -> list[str]:
        detected = set()
        h = {k.lower(): v for k, v in headers.items()}
        combined = " | ".join([h.get("server", ""), h.get("x-powered-by", ""), h.get("via", "")]).lower()

        signatures = {
            "cloudflare": "Cloudflare",
            "nginx": "Nginx",
            "apache": "Apache",
            "iis": "Microsoft IIS",
            "litespeed": "LiteSpeed",
            "varnish": "Varnish",
            "envoy": "Envoy",
            "caddy": "Caddy",
            "express": "Express",
            "php": "PHP",
            "asp.net": "ASP.NET",
            "python": "Python",
            "node": "Node.js",
        }
        for marker, name in signatures.items():
            if marker in combined:
                detected.add(name)

        if "cf-ray" in h or "cf-cache-status" in h:
            detected.add("Cloudflare")
        if "x-amz-cf-id" in h:
            detected.add("AWS CloudFront")
        if "x-vercel-id" in h:
            detected.add("Vercel")
        if "x-netlify-request-id" in h:
            detected.add("Netlify")

        return sorted(detected)

    def resolve_ip(self, url: str) -> str | None:
        try:
            host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0]
            return socket.gethostbyname(host)
        except Exception:
            return None

    def request_headers(self, url: str):
        errors = []
        try:
            resp = requests.get(url, timeout=self.timeout, allow_redirects=True)
            return resp.status_code, resp.url, dict(resp.headers), errors
        except Exception as exc:
            errors.append(f"header_request_failed: {exc}")
            return None, None, {}, errors

    def dir_bruteforce(self, base_url: str, paths: list[str]):
        findings, errors = [], []
        clean_base = base_url.rstrip("/")
        for path in paths:
            probe_url = f"{clean_base}/{path}"
            try:
                resp = requests.get(probe_url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code < 400:
                    findings.append(DirResult(path=path, status_code=resp.status_code, url=probe_url))
            except Exception as exc:
                errors.append(f"dir_probe_failed[{path}]: {exc}")
        return findings, errors

    async def capture_screenshot(self, page_url: str, image_path: Path):
        errors = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page(viewport={"width": 1440, "height": 900})
                await page.goto(page_url, wait_until="networkidle", timeout=self.screenshot_timeout_ms)
                title = await page.title()
                await page.screenshot(path=str(image_path), full_page=True)
                await browser.close()
                return str(image_path), title, errors
        except Exception as exc:
            errors.append(f"screenshot_failed: {exc}")
            return None, None, errors

    async def scan_target(self, raw_target: str, paths: list[str], i: int, total: int):
        print(f"[{i}/{total}] scanning {raw_target}", flush=True)
        target = normalize_target(raw_target)
        if not target:
            return TargetResult(raw_target, "", None, None, None, None, None, {}, [], [], ["invalid_target"])

        status_code, final_url, headers, request_errors = self.request_headers(target)
        effective_url = final_url or target
        technologies = self.detect_technologies(headers)
        ip = self.resolve_ip(effective_url)

        slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_target.strip()) or f"target_{i}"
        image_path = self.screenshots_dir / f"{slug}.png"
        screenshot, title, screenshot_errors = await self.capture_screenshot(effective_url, image_path)
        discovered_paths, dir_errors = self.dir_bruteforce(effective_url, paths)

        print(f"[{i}/{total}] done {raw_target} | status={status_code} | paths={len(discovered_paths)}", flush=True)
        return TargetResult(
            raw_target,
            target,
            effective_url,
            ip,
            screenshot,
            title,
            status_code,
            headers,
            technologies,
            discovered_paths,
            request_errors + screenshot_errors + dir_errors,
        )

    def write_json(self, results: list[TargetResult], out: Path):
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(results),
            "results": [{**asdict(r), "discovered_paths": [asdict(p) for p in r.discovered_paths]} for r in results],
        }
        atomic_write_json(out, payload)

    def write_markdown(self, results: list[TargetResult], out: Path):
        lines = ["# Visual Recon Report", "", f"Generated: `{datetime.now(timezone.utc).isoformat()}`", ""]
        for r in results:
            lines += [
                f"## {r.input}",
                f"- Base URL: `{r.base_url}`",
                f"- Final URL: `{r.final_url or 'N/A'}`",
                f"- IP: `{r.ip or 'N/A'}`",
                f"- HTTP Status: `{r.status_code}`",
                f"- Title: `{r.page_title or 'N/A'}`",
                f"- Screenshot: `{r.screenshot or 'N/A'}`",
                f"- Technologies: {', '.join(r.technologies) if r.technologies else 'None detected'}",
            ]
            if r.discovered_paths:
                lines.append("- Discovered Paths:")
                for p in r.discovered_paths:
                    lines.append(f"  - `{p.path}` (`{p.status_code}`) -> {p.url}")
            else:
                lines.append("- Discovered Paths: none")
            if r.errors:
                lines.append("- Errors:")
                for e in r.errors:
                    lines.append(f"  - `{e}`")
            lines.append("")
        atomic_write_text(out, "\n".join(lines))

    def write_html_viewer(self, results: list[TargetResult], out: Path):
        cards = []
        for r in results:
            img = Path(r.screenshot).as_posix() if r.screenshot else ""
            tech = ", ".join(r.technologies) if r.technologies else "None"
            cards.append(
                f"""<article class="card">
<h2>{r.input}</h2>
<p><strong>Final URL:</strong> {r.final_url or 'N/A'}</p>
<p><strong>Status:</strong> {r.status_code}</p>
<p><strong>IP:</strong> {r.ip or 'N/A'}</p>
<p><strong>Tech:</strong> {tech}</p>
{f'<a href="{img}" target="_blank"><img src="{img}" alt="Screenshot for {r.input}" /></a>' if img else '<p>No screenshot</p>'}
</article>"""
            )

        html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Visual Recon Viewer</title>
<style>
body {{ font-family: Arial,sans-serif; margin:0; padding:1rem; background:#f4f6f8; color:#1f2937; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:1rem; }}
.card {{ background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:.75rem; }}
img {{ width:100%; margin-top:.5rem; border:1px solid #d1d5db; border-radius:6px; }}
</style>
</head>
<body>
<h1>Visual Recon Viewer</h1>
<div class="grid">{''.join(cards)}</div>
</body>
</html>"""
        atomic_write_text(out, html)


VISUAL_PROMOTION_MARKERS = (
    "admin", "administrator", "debug", "backup", "backups", "config", "secret",
    "secrets", "credential", "credentials", "internal", ".env", ".git",
    "server-status", "phpinfo",
)


def _dir_promotion_reason(path_result: DirResult) -> str | None:
    if path_result.status_code not in {200, 403, 500}:
        return None
    haystack = f"{path_result.path} {path_result.url}".lower()
    if any(marker in haystack for marker in VISUAL_PROMOTION_MARKERS):
        return f"security-path-status-{path_result.status_code}"
    return None


def _dir_result_payload(result: TargetResult, path_result: DirResult, *, program: str, family: str, lane: str, promotion: str) -> dict:
    return {
        "program": program,
        "family": family,
        "lane": lane,
        "type": "recon",
        "status": "raw",
        "severity": "LOW",
        "title": f"Recon discovered path: {path_result.url}",
        "asset": path_result.url,
        "url": path_result.url,
        "target": result.input,
        "base_url": result.base_url,
        "path": path_result.path,
        "status_code": path_result.status_code,
        "promotion_reason": promotion,
        "summary": "Visual recon directory probing found a security-relevant path candidate. Review manually before treating as a vulnerability.",
        "evidence": [
            f"url={path_result.url}",
            f"status_code={path_result.status_code}",
            f"target={result.input}",
            f"promotion={promotion}",
        ],
        "tags": ["visual-recon", "dir-probe", "recon", "promoted", promotion],
        "source_tool": "visual_recon.py",
        "source_repo": "bounty-tools",
        "agent": "bounty-tools.visual-recon",
    }


def write_core_findings(program: str, family: str, lane: str, results: list[TargetResult]) -> dict:
    add_finding, error = _load_bounty_core()
    if add_finding is None:
        return {"ok": False, "error": f"bounty-core unavailable: {error}", "written": 0, "new": 0}

    written = 0
    new = 0
    last_layout = None
    errors = []
    for result in results:
        for path_result in result.discovered_paths:
            reason = _dir_promotion_reason(path_result)
            if not reason:
                continue
            payload = _dir_result_payload(result, path_result, program=program, family=family, lane=lane, promotion=reason)
            try:
                core_result = add_finding(payload, program=program, family=family, lane=lane)
                written += 1
                if core_result.get("is_new"):
                    new += 1
                last_layout = core_result.get("layout") or last_layout
            except Exception as exc:
                errors.append(str(exc))

    return {"ok": not errors, "written": written, "new": new, "promoted": written, "layout": last_layout, "errors": errors}


async def run(args):
    if async_playwright is None:
        print("error: Playwright is required for visual recon (pip install playwright && playwright install chromium)", file=sys.stderr)
        return 2

    if args.targets_file:
        targets = [
            line.strip()
            for line in Path(args.targets_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        targets = args.targets

    if not targets:
        print("No targets provided. Use --targets or --targets-file.")
        return 1

    core_program = _sanitize_core_program(args.core_program) if args.core_program else _infer_core_program(targets)
    if args.output:
        out = Path(args.output)
    else:
        bucket = recon_bucket(
            core_program,
            family=args.family,
            lane=args.lane,
            parts=["visual", _host_slug(targets[0]), _new_run_id()],
        )
        out = bucket.bucket

    recon = VisualRecon(out, Path(args.wordlist), timeout=args.timeout, screenshot_timeout_ms=args.screenshot_timeout_ms)
    paths = recon.load_paths()
    print(f"Loaded {len(paths)} paths from {args.wordlist}", flush=True)
    print(f"Scanning {len(targets)} targets", flush=True)
    print(f"Output: {out}", flush=True)

    results = []
    for i, t in enumerate(targets, start=1):
        results.append(await recon.scan_target(t, paths, i, len(targets)))

    recon.write_json(results, out / "results.json")
    recon.write_markdown(results, out / "results.md")
    recon.write_html_viewer(results, out / "viewer.html")

    if not args.no_core and results:
        core_result = write_core_findings(core_program, args.family, args.lane, results)
        if core_result.get("ok"):
            print(f"bounty-core: promoted={core_result['promoted']} new={core_result['new']} program={core_program} family={args.family} lane={args.lane}", flush=True)
        else:
            print(f"bounty-core: skipped/failed: {core_result.get('error') or core_result.get('errors')}", file=sys.stderr, flush=True)

    print(f"Wrote JSON report: {out / 'results.json'}", flush=True)
    print(f"Wrote Markdown report: {out / 'results.md'}", flush=True)
    print(f"Wrote HTML viewer: {out / 'viewer.html'}", flush=True)
    return 0


def parser():
    p = argparse.ArgumentParser(description="Visual recon tool with Playwright screenshots + dir enumeration")
    p.add_argument("--targets", nargs="*", default=[], help="Targets e.g. https://example.com example.org")
    p.add_argument("--targets-file", help="File with one target per line")
    p.add_argument("--wordlist", default="wordlists/common.txt")
    p.add_argument("--output", default=None, help="Output directory (default: canonical ~/Shared/<family>/<program>/<lane>/recon/visual/<host>/<run>)")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--screenshot-timeout-ms", type=int, default=15000)
    p.add_argument("--core-program", "--name", dest="core_program", default=None, help="bounty-core program/target identity/name (default: infer from first target)")
    p.add_argument("--family", default=DEFAULT_CORE_FAMILY, help=f"bounty-core storage family (default: {DEFAULT_CORE_FAMILY})")
    p.add_argument("--lane", default=DEFAULT_CORE_LANE, help=f"bounty-core storage lane (default: {DEFAULT_CORE_LANE})")
    p.add_argument("--no-core", action="store_true", help="Disable bounty-core ledger/report/index writes")
    return p


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run(parser().parse_args())))
