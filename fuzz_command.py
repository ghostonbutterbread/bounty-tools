#!/usr/bin/env python3
"""
/fuzz command — intelligent web fuzzing with context-aware wordlists.

Usage:
    python3 fuzz_command.py <target_url> [mode] [options]

Examples:
    python3 fuzz_command.py https://example.com dir
    python3 fuzz_command.py https://api.example.com param --mc "200,301,403"
    python3 fuzz_command.py https://example.com subdomain
    python3 fuzz_command.py https://app.example.com --generate-wordlist
"""

import argparse
import subprocess
import sys
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from recon_storage import atomic_write_json, atomic_write_text, recon_bucket, safe_slug

# Shared core fallback path. Bounty Tools remains cloneable on its own, but can
# use ~/projects/bounty-core when available.
BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))

# Paths
SECLISTS = Path.home() / "wordlists" / "SecLists"
FFUF = "/home/linuxbrew/.linuxbrew/bin/ffuf"

# Ryushe's correct -mc: match these status codes
DEFAULT_MC = "200,201,204,301,307,308,403,500"
DEFAULT_CORE_FAMILY = "web_bounty"
DEFAULT_CORE_LANE = "web"

# Wordlist registry — organized by target type
WORDLISTS = {
    # Directories / endpoints
    "dir": {
        "fast":    SECLISTS / "Discovery/Web-Content/common.txt",
        "medium":  SECLISTS / "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "big":     SECLISTS / "Discovery/Web-Content/directory-list-2.3-large.txt",
        "api":     SECLISTS / "Discovery/Web-Content/api-endpoints.txt",
        "raft":    SECLISTS / "Discovery/Web-Content/raft-small-directories.txt",
        "auto":    None,  # determined by context analysis
    },
    # Parameters
    "param": {
        "fast":    SECLISTS / "Discovery/Web-Content/burp-parameter-names.txt",
        "medium":  SECLISTS / "Discovery/Web-Content/parameter-names.txt",
        "larger":  SECLISTS / "Fuzzing/big-param.txt",
        "auto":    None,
    },
    # Subdomains
    "subdomain": {
        "fast":    SECLISTS / "Discovery/DNS/subdomains-top1million-5000.txt",
        "medium":  SECLISTS / "Discovery/DNS/subdomains-top1million-20000.txt",
        "big":     SECLISTS / "Discovery/DNS/bitquark-subdomains-top100000.txt",
        "combined": SECLISTS / "Discovery/DNS/combined_subdomains.txt",
        "auto":    None,
    },
}

# Interesting path/filename patterns (⚑ = high priority)
HIGH_PRIORITY_PATTERNS = [
    "admin", "api", "graphql", "swagger", "console", "debug", "test", "staging",
    "dev", "uat", "sandbox", "preview", "beta", "alpha", "internal", "private",
    "backup", "backups", "config", "configuration", "settings", "credentials",
    ".env", ".git", ".htaccess", ".htpasswd", ".DS_Store", "server-status",
    "phpmyadmin", "wp-admin", "wp-login", "xmlrpc", "readme", "README", "CHANGELOG",
    "deploy", "deployment", "scripts", "build", ".gitignore", ".git/config",
]

MEDIUM_PRIORITY_PATTERNS = [
    "v1", "v2", "v3", "v4", "old", "new", "archive", "backup", "bak",
    "upload", "uploads", "files", "media", "assets", "static", "images", "img",
    "css", "js", "javascript", "api-docs", "docs", "documentation",
    "swagger-ui", "api-explorer", "graphiql", "playground",
    "login", "signin", "sign-up", "register", "auth", "oauth", "oidc",
    "user", "users", "account", "profile", "dashboard", "panel", "portal",
    "manage", "management", "admin", "administrator", "cpanel", "plesk",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
]

# Unusual file extensions
INTERESTING_EXTENSIONS = [
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".conf", ".config",
    ".log", ".bak", ".backup", ".old", ".src", ".tmp", ".cache", ".sql",
    ".db", ".sqlite", ".env", ".key", ".pem", ".cert", ".crt", ".p12",
    ".zip", ".tar", ".tar.gz", ".rar", ".7z", ".pdf", ".doc", ".docx",
    ".xls", ".xlsx", ".csv", ".pptx", ".md", ".txt", ".rtf",
    ".js", ".ts", ".jsx", ".tsx", ".vue", ".php", ".php~", ".asp", ".aspx",
    ".jsp", ".jsp~", ".do", ".action", ".cgi", ".rb", ".py", ".py~",
    ".war", ".jar", ".ear", ".exe", ".dll", ".so", ".sh", ".bash",
]


def analyze_target(url: str) -> dict:
    """
    Analyze target URL to determine:
    - Best fuzz mode
    - Best wordlist
    - Whether to generate a custom wordlist
    - Special flags to pass to ffuf
    """
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()
    scheme = parsed.scheme

    analysis = {
        "mode": "dir",
        "wordlist": None,
        "wordlist_size": "medium",
        "generate_custom": False,
        "threads": 20,
        "exts": [],  # file extensions to look for
        "recursion": False,
        "recursion_depth": 2,
        "notes": [],
    }

    # Determine mode from URL patterns
    if any(x in path for x in ["/api", "/rest", "/graphql", "/v1", "/v2", "/v3"]):
        analysis["mode"] = "dir"
        analysis["wordlist"] = str(WORDLISTS["dir"]["api"])
        analysis["notes"].append("API endpoint detected — using api-endpoints wordlist")

    elif any(x in host for x in ["api", "rest", "cdn", "static", "assets"]):
        analysis["mode"] = "dir"
        analysis["wordlist"] = str(WORDLISTS["dir"]["medium"])
        analysis["notes"].append("CDN/static host — using medium wordlist")

    elif "?" in url or "param" in path:
        analysis["mode"] = "param"
        analysis["wordlist"] = str(WORDLISTS["param"]["fast"])
        analysis["notes"].append("Parameter fuzzing mode")

    elif any(x in path for x in ["/admin", "/manage", "/dashboard", "/panel"]):
        analysis["mode"] = "dir"
        analysis["wordlist"] = str(WORDLISTS["dir"]["medium"])
        analysis["notes"].append("Admin area — deeper scan")

    else:
        # Default: medium directory scan
        analysis["mode"] = "dir"
        analysis["wordlist"] = str(WORDLISTS["dir"]["medium"])
        analysis["notes"].append("Standard web target")

    # Check for tech stack hints in URL
    tech_patterns = {
        "php": [".php", ".php~"],
        "python": [".py", ".py~", "/cgi-bin/"],
        "ruby": [".rb", ".rb~"],
        "java": [".jsp", ".jsp~", ".do", ".action"],
        "asp": [".asp", ".aspx", ".aspx~"],
        "node": [".js", ".jsx", ".ts", ".tsx"],
        "wordpress": ["/wp-admin", "/wp-login", "/wp-content"],
        "drupal": ["/user", "/node", "/admin"],
        "jenkins": ["/jenkins", "/job", "/script"],
        "grafana": ["/grafana", "/api"],
        "swagger": ["/swagger", "/api-docs", "/openapi"],
    }

    for tech, exts in tech_patterns.items():
        if any(ext in host + path for ext in exts):
            analysis["exts"].extend(exts)
            analysis["notes"].append(f"Detected {tech} stack")

    return analysis


def generate_custom_wordlist(url: str, output_path: Path = None) -> Path:
    """
    Generate a custom wordlist from the target's JavaScript, sitemap, and robots.txt.
    This helps find application-specific paths that generic wordlists miss.
    """
    wordlist_lines = set()
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    print(f"   Generating custom wordlist from: {base_url}")

    # 1. Fetch robots.txt
    try:
        result = subprocess.run(
            ["curl", "-s", "-L", f"{base_url}/robots.txt", "--max-time", "10",
             "-A", "Mozilla/5.0 (compatible; RyusheFuzzer/1.0)"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                stripped = line.strip()
                if stripped.startswith(("Disallow:", "Allow:", "Sitemap:")):
                    parts = stripped.split(":", 1)
                    if len(parts) == 2:
                        path = parts[1].strip()
                        if path and path != "/":
                            # Extract clean paths
                            for p in re.findall(r'/[\w\-\._~:/\?#\[\]@!\$&\(\)\*\+\,\;\=\%]+', path):
                                wordlist_lines.add(p.rstrip("/").lstrip("/"))
            if wordlist_lines:
                print(f"   Found {len(wordlist_lines)} paths from robots.txt")
    except Exception:
        pass

    # 2. Fetch sitemap.xml
    try:
        result = subprocess.run(
            ["curl", "-s", "-L", f"{base_url}/sitemap.xml", "--max-time", "10",
             "-A", "Mozilla/5.0 (compatible; RyusheFuzzer/1.0)"],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                for p in re.findall(r'<loc>[^<]+</loc>', line):
                    path = p.replace("<loc>", "").replace("</loc>", "")
                    parsed_p = urlparse(path)
                    if parsed_p.netloc == parsed.netloc:
                        clean = parsed_p.path.strip("/")
                        if clean:
                            wordlist_lines.add(clean)
            if wordlist_lines:
                print(f"   Found {len(wordlist_lines)} paths from sitemap")
    except Exception:
        pass

    # 3. Try common JSON/YAML API endpoints
    for api_path in ["api/v1", "api/v2", "api/v3", "api/endpoints", "swagger.json",
                     "openapi.json", "api-docs", "api/swagger"]:
        if api_path not in wordlist_lines:
            wordlist_lines.add(api_path)

    # 4. Try fetching JSON API listings
    for api_try in [f"{base_url}/api", f"{base_url}/api/v1", f"{base_url}/swagger"]:
        try:
            result = subprocess.run(
                ["curl", "-s", "-L", api_try, "--max-time", "5",
                 "-A", "Mozilla/5.0 (compatible; RyusheFuzzer/1.0)"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout:
                content = result.stdout
                if "{" in content or "[" in content:
                    # Looks like JSON — extract path-like strings
                    for p in re.findall(r'"/([\w\-\._/]+)"', content):
                        if p and len(p) > 2:
                            wordlist_lines.add(p)
        except Exception:
            pass

    # Write custom wordlist
    if output_path is None:
        inferred_program = safe_slug(parsed.hostname or parsed.netloc, default="generated-wordlists")
        bucket = recon_bucket(inferred_program, parts=["fuzz", safe_slug(parsed.netloc, default="target"), "generated-wordlists"])
        output_path = bucket.bucket / f"wordlist_custom_{safe_slug(parsed.netloc, default='target')}_{_new_run_id()}.txt"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_lines = sorted(wordlist_lines)
    atomic_write_text(output_path, "\n".join(sorted_lines) + ("\n" if sorted_lines else ""))
    print(f"   Custom wordlist saved: {output_path}")
    print(f"   Total entries: {len(sorted_lines)}")

    return output_path


def build_ffuf_cmd(url: str, mode: str, wordlist: Path, mc: str,
                   threads: int = 20, recursion: bool = False,
                   recursion_depth: int = 2, exts: list = None,
                   filter_size: str = "0") -> list:
    """Build ffuf command based on mode and options."""
    parsed = urlparse(url)
    base = url.rstrip("/")

    if mode == "subdomain":
        # Replace domain with FUZZ for subdomain enumeration
        target = f"http://FUZZ.{parsed.netloc}/"
    elif mode == "param":
        # For parameter fuzzing, fuzz the query parameter name
        target = f"{base}/?FUZZ=value"
    else:
        # Directory fuzzing
        target = f"{base}/FUZZ"

    cmd = [
        FFUF,
        "-u", target,
        "-w", str(wordlist),
        "-mc", mc,
        "-fc", "404",           # Filter 404s
        "-fs", filter_size,     # Filter zero-size responses
        "-c",
        "-v",
        "-t", str(threads),
    ]

    # Add recursion for directory fuzzing
    if recursion and mode == "dir":
        cmd.extend(["-recursion", "-recursion-depth", str(recursion_depth)])

    # Add extension filters if tech detected
    if exts:
        ext_str = ",".join(exts)
        cmd.extend(["-e", ext_str])

    return cmd


def run_ffuf(cmd: list, timeout: int = 300) -> tuple[str, int]:
    """Run ffuf and return stdout + return code."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "COLUMNS": "200"}  # prevent line wrapping
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "TIMEOUT: scan exceeded timeout", 124
    except FileNotFoundError:
        return f"ERROR: ffuf not found at {FFUF}", 1
    except Exception as e:
        return f"ERROR: {e}", 1


def parse_findings(output: str) -> tuple[list, dict]:
    """
    Parse ffuf output for findings.

    ffuf -v output format (one result block):
      [Status: 200, Size: 8, Words: 2, Lines: 1, Duration: 0ms]
      | URL | http://127.0.0.1:8765/admin
          * FUZZ: admin

    We extract status + size from the [Status: ...] line,
    and the URL from the | URL | line.
    """
    findings = []
    stats = {"total_requests": 0, "total_time": "", "found": 0}

    # ffuf -v result block spans 3 lines:
    #   [Status: 200, Size: 8, ...]
    #   | URL | <url>
    #       * FUZZ: <fuzzed_value>
    pending_status = None
    pending_size = None

    for line in output.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue

        # Capture stats from summary lines
        if "Requests/sec:" in stripped:
            parts = stripped.split()
            for i, p in enumerate(parts):
                if p == "Duration:" and i+1 < len(parts):
                    stats["total_time"] = parts[i+1]
                if p == "Requests:" and i+1 < len(parts):
                    stats["total_requests"] = parts[i+1]
            continue

        # Parse [Status: 200, Size: 8, ...] line
        if stripped.startswith("["):
            m = re.match(r"\[Status:\s*(\d+),\s*Size:\s*(\d+)", stripped)
            if m:
                pending_status = int(m.group(1))
                pending_size = m.group(2)
            continue

        # Parse | URL | <url> line (must have pending status from above)
        if stripped.startswith("| URL |") and pending_status is not None:
            parts = stripped.split("|")
            if len(parts) >= 3:
                url = parts[2].strip()
            else:
                url = stripped.replace("| URL |", "").strip()

            if pending_status == 404:
                pending_status = None
                pending_size = None
                continue

            url_lower = url.lower()
            priority = "⚑" if any(p in url_lower for p in HIGH_PRIORITY_PATTERNS) else \
                      "○" if any(p in url_lower for p in MEDIUM_PRIORITY_PATTERNS) else \
                      " "
            has_ext = any(url_lower.endswith(ext) for ext in INTERESTING_EXTENSIONS)

            # Special handling: empty 403 = skip
            if pending_status == 403:
                try:
                    if int(pending_size) == 0:
                        priority = "✗"
                except ValueError:
                    pass

            findings.append({
                "status": pending_status,
                "size": pending_size,
                "url": url,
                "priority": priority,
                "interesting": has_ext or priority in ("⚑", "○"),
            })

            pending_status = None
            pending_size = None
            continue

        # Reset pending if we hit a progress/separator line
        if ":: Progress" in stripped or stripped.startswith("---"):
            pending_status = None
            pending_size = None

    stats["found"] = len(findings)
    return findings, stats


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


def _host_slug(target: str) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or parsed.netloc or target
    return safe_slug(host.lower(), default="unknown-host")


def _new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid.uuid4().hex[:8]}"


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


SECURITY_PATH_MARKERS = (
    "admin", "administrator", "debug", "backup", "backups", "bak", "config",
    "configuration", "secret", "secrets", "credential", "credentials", "private",
    "internal", "console", "server-status", "phpinfo",
)

SENSITIVE_FILE_MARKERS = (
    ".env", ".git/config", ".git/HEAD", ".htpasswd", ".htaccess", "id_rsa",
    "private.key", "config.php", "settings.py", "database.yml", "wp-config",
    "web.config", "credentials.json", "service-account", "docker-compose",
)

LEAK_INDICATORS = (
    "token", "api_key", "apikey", "access_key", "secret_key", "client_secret",
    "password", "passwd", "authorization", "bearer", "oauth", "jwt",
)

PROMOTABLE_STATUSES = {200, 403, 500}


def promotion_reason(finding: dict) -> str | None:
    """Return a conservative ledger-promotion reason for security-relevant hits."""
    status = finding.get("status")
    if status not in PROMOTABLE_STATUSES:
        return None

    parsed = urlparse(finding.get("url") or "")
    path = (parsed.path or finding.get("url") or "").lower()
    query = parsed.query.lower()
    haystack = f"{path}?{query}" if query else path

    if any(marker.lower() in path for marker in SENSITIVE_FILE_MARKERS):
        return f"sensitive-file-status-{status}"
    if any(marker in haystack for marker in LEAK_INDICATORS):
        return f"leak-indicator-status-{status}"
    if any(marker in haystack for marker in SECURITY_PATH_MARKERS):
        return f"security-path-status-{status}"
    if status == 500 and any(ext in path for ext in (".bak", ".backup", ".old", ".sql", ".zip", ".tar", ".gz")):
        return "error-on-sensitive-artifact"
    return None


def _finding_to_core_payload(finding: dict, *, program: str, family: str, lane: str,
                             mode: str, target: str, analysis: dict,
                             wordlist_used: str, mc: str, promotion: str) -> dict:
    """Convert one ffuf finding into bounty-core's normalized finding shape."""
    parsed = urlparse(finding.get("url") or target)
    status = finding.get("status")
    priority = str(finding.get("priority") or "").strip()
    severity = "MEDIUM" if promotion.startswith(("sensitive-file", "leak-indicator")) else "LOW"
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "") if parsed.scheme else finding.get("url", "")
    title = f"Fuzz discovery: {path or finding.get('url', 'unknown')}"

    return {
        "program": program,
        "family": family,
        "lane": lane,
        "type": "fuzz",
        "status": "raw",
        "severity": severity,
        "title": title,
        "asset": f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else finding.get("url", target),
        "url": finding.get("url", ""),
        "status_code": status,
        "response_size": finding.get("size"),
        "fuzz_mode": mode,
        "target": target,
        "wordlist": wordlist_used,
        "match_codes": mc,
        "priority": priority,
        "interesting": bool(finding.get("interesting")),
        "promotion_reason": promotion,
        "summary": "ffuf discovered a security-relevant endpoint candidate under conservative promotion rules. Review manually before treating as a vulnerability.",
        "evidence": [
            f"ffuf status={status} size={finding.get('size')}",
            f"url={finding.get('url', '')}",
            f"mode={mode} wordlist={wordlist_used}",
            f"promotion={promotion}",
        ],
        "tags": ["fuzz", mode, "promoted", promotion],
        "analysis_notes": analysis.get("notes", []),
        "source_tool": "fuzz_command.py",
        "source_repo": "bounty-tools",
        "agent": "bounty-tools.fuzz",
    }


def write_core_findings(program: str, family: str, lane: str, mode: str, target: str,
                        findings: list, analysis: dict, mc: str, wordlist_used: str) -> dict:
    """Promote only security-relevant ffuf findings to bounty-core."""
    add_finding, error = _load_bounty_core()
    if add_finding is None:
        return {"ok": False, "error": f"bounty-core unavailable: {error}", "written": 0, "new": 0, "promoted": 0}

    written = 0
    new = 0
    last_layout = None
    errors = []
    for finding in findings:
        reason = promotion_reason(finding)
        if not reason:
            continue
        payload = _finding_to_core_payload(
            finding,
            program=program,
            family=family,
            lane=lane,
            mode=mode,
            target=target,
            analysis=analysis,
            wordlist_used=wordlist_used,
            mc=mc,
            promotion=reason,
        )
        try:
            result = add_finding(payload, program=program, family=family, lane=lane)
            written += 1
            if result.get("is_new"):
                new += 1
            last_layout = result.get("layout") or last_layout
        except Exception as exc:
            errors.append(str(exc))

    return {"ok": not errors, "written": written, "new": new, "promoted": written, "layout": last_layout, "errors": errors}


def _finding_path(finding: dict) -> str:
    try:
        parsed_url = urlparse(finding["url"])
        return parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
    except Exception:
        return finding.get("url", "")


def _interesting_text(findings: list) -> str:
    rows = []
    for finding in findings:
        reason = promotion_reason(finding)
        if not finding.get("interesting") and not reason:
            continue
        prefix = "PROMOTE" if reason else "REVIEW"
        suffix = f"\t{reason}" if reason else ""
        rows.append(
            f"{prefix}\t{finding.get('priority', '').strip() or '-'}\t"
            f"{finding.get('status')}\t{finding.get('size')}\t"
            f"{_finding_path(finding)}{suffix}"
        )
    return "\n".join(rows) + ("\n" if rows else "")


def save_recon_output(bucket, *, run_id: str, purpose: str, target: str, mode: str,
                      raw_output: str, findings: list, stats: dict, analysis: dict,
                      mc: str, wordlist_used: str, ffuf_cmd: list, exit_code: int,
                      core_result: dict | None):
    """Save canonical fuzz recon artifacts."""
    raw_file = bucket.bucket / f"raw_{run_id}.txt"
    parsed_file = bucket.bucket / f"parsed_{run_id}.json"
    interesting_file = bucket.bucket / f"interesting_{run_id}.txt"
    manifest_file = bucket.bucket / f"manifest_{run_id}.json"

    promotions = [f for f in findings if promotion_reason(f)]
    parsed_payload = {
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "mode": mode,
        "purpose": purpose,
        "stats": stats,
        "analysis": analysis,
        "match_codes": mc,
        "wordlist": wordlist_used,
        "exit_code": exit_code,
        "promotion_candidates": len(promotions),
        "findings": findings,
    }
    manifest = {
        "run_id": run_id,
        "target": target,
        "mode": mode,
        "purpose": purpose,
        "program": bucket.program,
        "family": bucket.family,
        "lane": bucket.lane,
        "bucket": str(bucket.bucket),
        "generated_at": parsed_payload["generated_at"],
        "exit_code": exit_code,
        "counts": {
            "findings": len(findings),
            "interesting": len([f for f in findings if f.get("interesting")]),
            "promotion_candidates": len(promotions),
            "promoted": (core_result or {}).get("promoted", 0),
        },
        "files": {
            "raw": raw_file.name,
            "parsed_json": parsed_file.name,
            "interesting_text": interesting_file.name,
        },
        "ffuf": {
            "cmd": ffuf_cmd,
            "match_codes": mc,
            "wordlist": wordlist_used,
        },
    }

    atomic_write_text(raw_file, raw_output)
    atomic_write_json(parsed_file, parsed_payload)
    atomic_write_text(interesting_file, _interesting_text(findings))
    atomic_write_json(manifest_file, manifest, compact=True)
    return {
        "raw": raw_file,
        "parsed_json": parsed_file,
        "interesting_text": interesting_file,
        "manifest": manifest_file,
        "promotion_candidates": len(promotions),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Intelligent web fuzzing — context-aware wordlists + ffuf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com                    # Smart dir scan; bounty-core program auto-infers example-com
  %(prog)s https://example.com dir                # Directory fuzzing
  %(prog)s https://api.example.com param          # Parameter fuzzing
  %(prog)s https://example.com subdomain          # Subdomain fuzzing
  %(prog)s https://example.com --mc "200,403"    # Custom status codes
  %(prog)s https://example.com --generate         # Generate custom wordlist first
  %(prog)s https://example.com --recursion        # Recursive directory scan
  %(prog)s https://example.com --purpose admin-endpoints --name acme
                                                 # Store under ~/Shared/web_bounty/acme/web/recon/fuzz/<host>/admin-endpoints
  %(prog)s https://example.com --core-program acme --family web_bounty --lane web
                                                 # Recommended canonical storage identity
        """
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("mode", nargs="?", default="auto",
                        choices=["dir", "param", "subdomain", "auto"],
                        help="Fuzz mode: dir (default), param, subdomain, auto")
    parser.add_argument("--program", "-p", default=None,
                        help="Deprecated compatibility program name; used as canonical identity only when --core-program/--name is omitted")
    parser.add_argument("--purpose", default=None,
                        help="Recon purpose bucket under fuzz/<host>/, e.g. admin-endpoints (default: fuzz mode)")
    parser.add_argument("--threads", "-t", type=int, default=20,
                        help="Thread count (default: 20)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Timeout in seconds (default: 300)")
    parser.add_argument("--mc", default=DEFAULT_MC,
                        help=f"Match status codes (default: {DEFAULT_MC})")
    parser.add_argument("--wordlist", "-w", default=None,
                        help="Custom wordlist path (overrides auto-selection)")
    parser.add_argument("--wordlist-size", "-ws", default="auto",
                        choices=["fast", "medium", "big", "auto"],
                        help="Wordlist size (default: auto)")
    parser.add_argument("--generate", "-g", action="store_true",
                        help="Generate custom wordlist from target's JS/sitemap/robots")
    parser.add_argument("--recursion", "-r", action="store_true",
                        help="Enable recursive directory fuzzing")
    parser.add_argument("--recursion-depth", "-rd", type=int, default=2,
                        help="Recursion depth (default: 2)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show ffuf command without running")
    parser.add_argument("--core-program", "--name", dest="core_program", default=None,
                        help="bounty-core program/target identity/name (default: --program when set, otherwise infer from target hostname)")
    parser.add_argument("--family", default=DEFAULT_CORE_FAMILY,
                        help=f"bounty-core storage family for ledger writes (default: {DEFAULT_CORE_FAMILY})")
    parser.add_argument("--lane", default=DEFAULT_CORE_LANE,
                        help=f"bounty-core storage lane for ledger writes (default: {DEFAULT_CORE_LANE})")
    parser.add_argument("--no-core", action="store_true",
                        help="Disable bounty-core ledger/report/index writes")

    args = parser.parse_args()

    # Validate target
    if not args.target.startswith(("http://", "https://")):
        print(f"❌ Invalid target: must start with http:// or https://")
        sys.exit(1)

    # Analyze target
    analysis = analyze_target(args.target)

    # Determine mode
    mode = args.mode
    if mode == "auto":
        mode = analysis["mode"]

    core_program = _sanitize_core_program(args.core_program or args.program) if (args.core_program or args.program) else _infer_core_program(args.target)
    purpose = safe_slug(args.purpose or mode, default=mode)
    run_id = _new_run_id()
    bucket = recon_bucket(
        core_program,
        family=args.family,
        lane=args.lane,
        parts=["fuzz", _host_slug(args.target), purpose],
    )
    custom_wordlist_path = bucket.bucket / f"wordlist_custom_{_host_slug(args.target)}_{run_id}.txt"

    # Determine wordlist
    if args.wordlist:
        # User explicitly specified a wordlist
        wordlist = Path(args.wordlist)
        if not wordlist.exists():
            print(f"❌ Wordlist not found: {wordlist}")
            sys.exit(1)
        wordlist_used = str(wordlist)

    elif args.generate:
        # Explicitly ask for custom wordlist generation from target
        wordlist = generate_custom_wordlist(args.target, custom_wordlist_path)
        wordlist_used = f"(custom) {wordlist}"

    elif mode == "param":
        # Parameter fuzzing — use fast param wordlist
        wordlist = WORDLISTS["param"]["fast"]
        if not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target, custom_wordlist_path)
        wordlist_used = str(wordlist)

    elif mode == "auto" and analysis.get("wordlist"):
        # Auto mode with pre-selected wordlist from analysis
        wordlist = Path(analysis["wordlist"])
        if not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target, custom_wordlist_path)
        wordlist_used = str(wordlist)

    elif args.wordlist_size != "auto":
        # User selected a specific size
        wl_dict = WORDLISTS.get(mode, {})
        wordlist = wl_dict.get(args.wordlist_size) or wl_dict.get("medium")
        if not wordlist or not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target, custom_wordlist_path)
        wordlist_used = str(wordlist)

    else:
        # Default: find the first available wordlist for this mode
        wl_dict = WORDLISTS.get(mode, {})
        wordlist = None
        for size in ["fast", "medium", "big"]:
            candidate = wl_dict.get(size)
            if candidate and candidate.exists():
                wordlist = candidate
                wordlist_used = str(wordlist)
                break
        if wordlist is None:
            # No wordlists found — generate one
            wordlist = generate_custom_wordlist(args.target, custom_wordlist_path)
            wordlist_used = f"(generated) {wordlist}"

    # Build ffuf command
    cmd = build_ffuf_cmd(
        args.target, mode, wordlist, args.mc,
        threads=args.threads,
        recursion=args.recursion,
        recursion_depth=args.recursion_depth,
        exts=analysis.get("exts", []),
    )

    # Pre-compute output path so we can reference it in error messages.
    precomputed_raw = bucket.bucket / f"raw_{run_id}.txt"

    print(f"🎯 Fuzz: {args.target}")
    print(f"   Mode: {mode} | Wordlist: {wordlist_used}")
    print(f"   Purpose: {purpose} | Run: {run_id}")
    print(f"   Match codes: {args.mc} | Threads: {args.threads}")
    print(f"   Recon bucket: {bucket.bucket}")
    if not args.no_core:
        print(f"   bounty-core promotion identity: program={bucket.program} family={bucket.family} lane={bucket.lane}")
    else:
        print("   bounty-core ledger promotion: disabled (--no-core)")
    for note in analysis["notes"]:
        print(f"   → {note}")

    if args.recursion:
        print(f"   → Recursive scan (depth={args.recursion_depth})")

    if args.dry_run:
        print(f"\n✅ Would run: {' '.join(cmd)}")
        sys.exit(0)

    print(f"\n   Running ffuf... (timeout: {args.timeout}s)")
    output, code = run_ffuf(cmd, args.timeout)

    if code == 124:
        print(f"\n⚠️  Scan timed out after {args.timeout}s")
        print(f"   Raw output will be saved: {precomputed_raw}")
    elif code != 0:
        print(f"\n⚠️  ffuf exited with code {code}")
        print(f"   Raw output will be saved: {precomputed_raw}")
        # Continue — try to parse whatever output we have

    findings, stats = parse_findings(output)

    core_result = None
    if not args.no_core:
        core_result = write_core_findings(
            bucket.program,
            bucket.family,
            bucket.lane,
            mode,
            args.target,
            findings,
            analysis,
            args.mc,
            wordlist_used,
        )

    recon_files = save_recon_output(
        bucket,
        run_id=run_id,
        purpose=purpose,
        target=args.target,
        mode=mode,
        raw_output=output,
        findings=findings,
        stats=stats,
        analysis=analysis,
        mc=args.mc,
        wordlist_used=wordlist_used,
        ffuf_cmd=cmd,
        exit_code=code,
        core_result=core_result,
    )
    # Summary
    interesting = [f for f in findings if f["interesting"]]
    promotions = [f for f in findings if promotion_reason(f)]
    print(f"\n✅ Scan complete!")
    print(f"   Total requests: {stats.get('total_requests', '?')}")
    print(f"   Interesting findings: {len(interesting)}")
    print(f"   Promotion candidates: {len(promotions)}")
    print(f"   Raw output: {recon_files['raw']}")
    print(f"   Parsed JSON: {recon_files['parsed_json']}")
    print(f"   Interesting text: {recon_files['interesting_text']}")
    print(f"   Manifest: {recon_files['manifest']}")
    if core_result:
        if core_result.get("ok"):
            layout = core_result.get("layout") or {}
            print(f"   bounty-core: promoted {core_result.get('promoted', 0)} findings ({core_result.get('new', 0)} new)")
            if layout.get("canonical_root"):
                print(f"   bounty-core root: {layout['canonical_root']}")
        else:
            print(f"   bounty-core: skipped/partial — {core_result.get('error') or core_result.get('errors')}")

    if findings:
        print(f"\n📋 Top findings:")
        high_priority = [f for f in findings if f["priority"] == "⚑"][:10]
        others = [f for f in findings if f["priority"] != "⚑"][:5]
        display = high_priority + others

        for f in display:
            try:
                parsed_url = urlparse(f["url"])
                path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
            except Exception:
                path = f["url"]
            print(f"   {f['priority']} [{f['status']}] {f['size']:>8} — {path[:80]}")

        if len(findings) > 15:
            print(f"   ... and {len(findings) - 15} more")

    if code == 124:
        sys.exit(1)


if __name__ == "__main__":
    main()
