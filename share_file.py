#!/usr/bin/env python3
"""Share files via multiple hosting services. Returns first successful URL."""

import argparse
import subprocess
import sys
import tempfile
import os
import re
import time


def try_transfer_sh(filepath: str) -> str | None:
    """transfer.sh - no auth, 14 day expiry, 200MB limit"""
    try:
        result = subprocess.run(
            ["curl", "--progress-bar", "-H", "Max-File-Size: 209715200",
             "--upload-file", filepath, "https://transfer.sh/" + os.path.basename(filepath)],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout.strip()
        if output.startswith("https://"):
            return output
    except Exception as e:
        print(f"transfer.sh failed: {e}", file=sys.stderr)
    return None


def try_0x0_st(filepath: str) -> str | None:
    """0x0.st - no auth, 512MB max, no expiry"""
    try:
        result = subprocess.run(
            ["curl", "--progress-bar", "-F", f"file=@{filepath}",
             "https://0x0.st"],
            capture_output=True, text=True, timeout=600
        )
        output = result.stdout.strip()
        if output.startswith("https://"):
            return output
    except Exception as e:
        print(f"0x0.st failed: {e}", file=sys.stderr)
    return None


def try_catbox(filepath: str) -> str | None:
    """catbox.moe - no auth, 200MB max, permanent storage"""
    try:
        result = subprocess.run(
            ["curl", "--progress-bar",
             "-F", "reqtype=fileupload",
             "-F", f"fileToUpload=@{filepath}",
             "https://catbox.moe/user/api.php"],
            capture_output=True, text=True, timeout=300
        )
        output = result.stdout.strip()
        if output.startswith("https://"):
            return output
    except Exception as e:
        print(f"catbox.moe failed: {e}", file=sys.stderr)
    return None


def try_gofile(filepath: str) -> str | None:
    """Gofile.io - no auth, no size limit, needs server selection"""
    try:
        # First get a server
        r = subprocess.run(
            ["curl", "-s", "https://api.gofile.io/servers"],
            capture_output=True, text=True, timeout=10
        )
        import json
        data = json.loads(r.stdout)
        if data.get("status") != "ok":
            return None
        servers = data.get("data", {}).get("servers", [])
        if not servers:
            return None
        server = servers[0].get("name", "store1")

        # Upload
        result = subprocess.run(
            ["curl", "--progress-bar",
             "-F", f"file=@{filepath}",
             "-F", "description=",
             f"https://{server}.gofile.io/contents/uploadfile"],
            capture_output=True, text=True, timeout=600
        )
        data = json.loads(result.stdout)
        if data.get("status") == "ok":
            return data.get("data", {}).get("downloadPage", "")
    except Exception as e:
        print(f"gofile.io failed: {e}", file=sys.stderr)
    return None


def try_file_io(filepath: str) -> str | None:
    """file.io - auto-deletes after first download, 2GB max"""
    try:
        result = subprocess.run(
            ["curl", "--progress-bar",
             "-F", f"file=@{filepath}",
             "https://file.io"],
            capture_output=True, text=True, timeout=300
        )
        import json
        data = json.loads(result.stdout)
        if data.get("success"):
            return data.get("link", "")
    except Exception as e:
        print(f"file.io failed: {e}", file=sys.stderr)
    return None


def try_pixeldrain(filepath: str) -> str | None:
    """Pixeldrain - privacy focused, 10GB max, no auth"""
    try:
        result = subprocess.run(
            ["curl", "--progress-bar",
             "-F", f"file=@{filepath}",
             "https://pixeldrain.com/api/file"],
            capture_output=True, text=True, timeout=600
        )
        import json
        data = json.loads(result.stdout)
        if "id" in data:
            return f"https://pixeldrain.com/l/{data['id']}"
    except Exception as e:
        print(f"pixeldrain.com failed: {e}", file=sys.stderr)
    return None


PROVIDERS = [
    # JustBeamIt is P2P/browser-only — no CLI/API access, skip for automation
    ("Catbox", try_catbox),          # Fast, 200MB, permanent, no auth
    ("Gofile", try_gofile),         # No size limit, needs server lookup
    ("Pixeldrain", try_pixeldrain), # 10GB max, privacy focused
    ("0x0.st", try_0x0_st),         # 512MB max, fast but slow for large files
    ("File.io", try_file_io),       # Auto-deletes after 1 download (use for temp)
    ("Transfer.sh", try_transfer_sh),  # 200MB, 14 day expiry
]


def share(filepath: str, provider: str | None = None) -> str | None:
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}", file=sys.stderr)
        return None

    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    print(f"Sharing {filepath} ({size_mb:.1f} MB)...", file=sys.stderr)

    if provider:
        for name, fn in PROVIDERS:
            if name.lower() == provider.lower():
                print(f"Using {name}...", file=sys.stderr)
                return fn(filepath)
        print(f"Unknown provider: {provider}", file=sys.stderr)
        return None

    for name, fn in PROVIDERS:
        print(f"Trying {name}...", file=sys.stderr, end=" ", flush=True)
        url = fn(filepath)
        if url:
            print(f"✅ {url}", file=sys.stderr)
            return url
        print("❌", file=sys.stderr)

    print("All providers failed.", file=sys.stderr)
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Share a file via multiple hosts")
    parser.add_argument("file", help="File to share")
    parser.add_argument("--provider", "-p", help="Force specific provider")
    args = parser.parse_args()

    url = share(args.file, args.provider)
    if url:
        print(url)
        sys.exit(0)
    else:
        sys.exit(1)
