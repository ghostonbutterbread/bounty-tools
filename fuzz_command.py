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
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Paths
SECLISTS = Path.home() / "wordlists" / "SecLists"
FFUF = "/home/linuxbrew/.linuxbrew/bin/ffuf"

# Ryushe's correct -mc: match these status codes
DEFAULT_MC = "200,201,204,301,307,308,403,500"

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
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = Path.home() / "Shared" / "bounty_recon" / "ghost" / "fuzz" / f"custom_{parsed.netloc}_{date_str}.txt"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_lines = sorted(wordlist_lines)
    output_path.write_text("\n".join(sorted_lines))
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


def save_output(program: str, mode: str, raw_output: str, findings: list,
                analysis: dict, mc: str, wordlist_used: str):
    """Save raw output and findings to files."""
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")

    # Sanitize program name to prevent path traversal
    # Only allow alphanumeric, hyphens, underscores
    safe_program = re.sub(r"[^a-zA-Z0-9_\-]", "", program or "ghost")
    if not safe_program:
        safe_program = "ghost"

    # Build safe path — only write inside bounty_recon/
    base_dir = Path.home() / "Shared" / "bounty_recon" / safe_program / "fuzz"
    # Resolve and verify it's inside bounty_recon/
    try:
        resolved = base_dir.resolve()
        expected_prefix = (Path.home() / "Shared" / "bounty_recon").resolve()
        resolved.relative_to(expected_prefix)  # raises if outside
    except ValueError:
        # Program name tried to escape — use safe default
        base_dir = Path.home() / "Shared" / "bounty_recon" / "ghost" / "fuzz"

    base_dir.mkdir(parents=True, exist_ok=True)

    # Save raw output
    raw_file = base_dir / f"raw_{mode}_{date_str}.txt"
    raw_file.write_text(raw_output)

    # Save findings report
    findings_file = base_dir / f"findings_{mode}_{date_str}.md"
    with open(findings_file, "w") as f:
        f.write(f"# Fuzz Findings — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"**Target mode:** {mode} | **Wordlist:** {wordlist_used}\n")
        f.write(f"**Match codes:** {mc} | **Program:** {program or 'ghost'}\n\n")
        if analysis["notes"]:
            f.write(f"**Context:** {' | '.join(analysis['notes'])}\n\n")

        f.write("## Summary\n")
        interesting = [x for x in findings if x["interesting"]]
        f.write(f"- Total findings: {len(findings)}\n")
        f.write(f"- Interesting: {len(interesting)}\n\n")

        f.write("## Findings\n")
        f.write("| Priority | Status | Size | Path |\n")
        f.write("|----------|--------|------|------|\n")
        for finding in findings[:50]:
            prio = finding["priority"]
            # Extract just the path from full URL if possible
            path = finding["url"]
            try:
                parsed_url = urlparse(path)
                path = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
            except Exception:
                pass
            f.write(f"| {prio} | {finding['status']} | {finding['size']} | `{path[:80]}` |\n")

        if len(findings) > 50:
            f.write(f"\n*... and {len(findings) - 50} more (see raw output)*\n")

    return raw_file, findings_file


def main():
    parser = argparse.ArgumentParser(
        description="Intelligent web fuzzing — context-aware wordlists + ffuf",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com                    # Smart dir scan
  %(prog)s https://example.com dir                # Directory fuzzing
  %(prog)s https://api.example.com param         # Parameter fuzzing
  %(prog)s https://example.com subdomain          # Subdomain fuzzing
  %(prog)s https://example.com --mc "200,403"    # Custom status codes
  %(prog)s https://example.com --generate        # Generate custom wordlist first
  %(prog)s https://example.com --recursion       # Recursive directory scan
        """
    )
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("mode", nargs="?", default="auto",
                        choices=["dir", "param", "subdomain", "auto"],
                        help="Fuzz mode: dir (default), param, subdomain, auto")
    parser.add_argument("--program", "-p", default=None,
                        help="Bug bounty program name (for output directory)")
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
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        parsed = urlparse(args.target)
        custom_path = Path.home() / "Shared" / "bounty_recon" / "ghost" / "fuzz" / f"custom_{parsed.netloc}_{date_str}.txt"
        wordlist = generate_custom_wordlist(args.target, custom_path)
        wordlist_used = f"(custom) {wordlist}"

    elif mode == "param":
        # Parameter fuzzing — use fast param wordlist
        wordlist = WORDLISTS["param"]["fast"]
        if not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target)
        wordlist_used = str(wordlist)

    elif mode == "auto" and analysis.get("wordlist"):
        # Auto mode with pre-selected wordlist from analysis
        wordlist = Path(analysis["wordlist"])
        if not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target)
        wordlist_used = str(wordlist)

    elif args.wordlist_size != "auto":
        # User selected a specific size
        wl_dict = WORDLISTS.get(mode, {})
        wordlist = wl_dict.get(args.wordlist_size) or wl_dict.get("medium")
        if not wordlist or not wordlist.exists():
            wordlist = generate_custom_wordlist(args.target)
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
            wordlist = generate_custom_wordlist(args.target)
            wordlist_used = f"(generated) {wordlist}"

    # Build ffuf command
    cmd = build_ffuf_cmd(
        args.target, mode, wordlist, args.mc,
        threads=args.threads,
        recursion=args.recursion,
        recursion_depth=args.recursion_depth,
        exts=analysis.get("exts", []),
    )

    # Pre-compute output path so we can reference it in error messages
    safe_program = re.sub(r"[^a-zA-Z0-9_\-]", "", args.program or "ghost") or "ghost"
    base_out_dir = Path.home() / "Shared" / "bounty_recon" / safe_program / "fuzz"
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    precomputed_raw = base_out_dir / f"raw_{mode}_{date_str}.txt"

    print(f"🎯 Fuzz: {args.target}")
    print(f"   Mode: {mode} | Wordlist: {wordlist_used}")
    print(f"   Match codes: {args.mc} | Threads: {args.threads}")
    for note in analysis["notes"]:
        print(f"   → {note}")

    if args.recursion:
        print(f"   → Recursive scan (depth={args.recursion_depth})")

    if args.dry_run:
        print(f"\n✅ Would run: {' '.join(cmd)}")
        sys.exit(0)

    print(f"\n   Running ffuf... (timeout: {args.timeout}s)")
    output, code = run_ffuf(cmd, args.timeout)

    # Check for timeout / error
    if code == 124:
        print(f"\n⚠️  Scan timed out after {args.timeout}s")
        print(f"   Raw output: {precomputed_raw}")
        sys.exit(1)
    elif code != 0:
        print(f"\n⚠️  ffuf exited with code {code}")
        print(f"   Raw output: {precomputed_raw}")
        # Continue — try to parse whatever output we have

    findings, stats = parse_findings(output)
    raw_file, findings_file = save_output(
        args.program or "ghost", mode, output, findings,
        analysis, args.mc, wordlist_used
    )

    # Summary
    interesting = [f for f in findings if f["interesting"]]
    print(f"\n✅ Scan complete!")
    print(f"   Total requests: {stats.get('total_requests', '?')}")
    print(f"   Interesting findings: {len(interesting)}")
    print(f"   Raw output: {raw_file}")
    print(f"   Findings report: {findings_file}")

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


if __name__ == "__main__":
    main()
