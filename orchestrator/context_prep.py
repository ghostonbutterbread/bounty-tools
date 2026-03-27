"""
Context Preparation — Prepares reconnaissance context for agents before they are spawned.
"""

import os
import json
from datetime import datetime
from typing import Optional


def prep_recon_context(program_name: str, vuln_types: list = None, max_endpoints: int = 50) -> dict:
    """Prepare reconnaissance context for a target.

    Args:
        program_name: Bug bounty program name
        vuln_types: List of vulnerability types to focus on (xss, sqli, ssrf, etc.)
        max_endpoints: Maximum number of endpoints to include

    Returns:
        dict with recon data ready for agent context
    """
    recon_dir = os.path.expanduser(f"~/Shared/bounty_recon/{program_name}/ghost")

    context = {
        "program": program_name,
        "prepared_at": datetime.now().isoformat(),
        "scope": [],
        "endpoints": [],
        "js_endpoints": [],
        "parameters": [],
        "interesting_urls": [],
        "tested_endpoints": [],
        "previous_findings": []
    }

    # Load scope if available
    scope_file = os.path.join(recon_dir, "scope.json")
    if os.path.exists(scope_file):
        with open(scope_file, 'r') as f:
            context["scope"] = json.load(f)

    # Load all gathered URLs
    urls_dir = os.path.join(recon_dir, "urls")
    if os.path.exists(urls_dir):
        for filename in os.listdir(urls_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(urls_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        urls = [u.strip() for u in f.readlines() if u.strip()]
                        context["endpoints"].extend(urls)
                except OSError:
                    pass

    # Load JS endpoints
    js_file = os.path.join(recon_dir, "js_analysis.json")
    if os.path.exists(js_file):
        try:
            with open(js_file, 'r') as f:
                js_data = json.load(f)
                context["js_endpoints"] = js_data.get("endpoints", [])
                context["js_secrets"] = js_data.get("secrets", [])
        except (OSError, json.JSONDecodeError):
            pass

    # Load tested endpoints
    tested_file = os.path.join(recon_dir, "tested.json")
    if os.path.exists(tested_file):
        try:
            with open(tested_file, 'r') as f:
                context["tested_endpoints"] = json.load(f)
        except (OSError, json.JSONDecodeError):
            pass

    # Load previous findings
    findings_dir = os.path.join(recon_dir, "findings")
    if os.path.exists(findings_dir):
        for filename in os.listdir(findings_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(findings_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        context["previous_findings"].append(json.load(f))
                except (OSError, json.JSONDecodeError):
                    pass

    # Filter by vuln type if specified
    if vuln_types:
        context["vuln_types_focus"] = vuln_types
        relevant = []
        for url in context["endpoints"]:
            for vtype in vuln_types:
                if vtype.lower() in url.lower():
                    relevant.append(url)
                    break
        context["endpoints"] = relevant[:max_endpoints]

    # Deduplicate
    context["endpoints"] = list(set(context["endpoints"]))[:max_endpoints]

    # Categorize URLs by type
    context["categorized"] = categorize_urls(context["endpoints"])

    return context


def categorize_urls(urls: list) -> dict:
    """Categorize URLs by vulnerability potential."""
    categories = {
        "api": [],
        "user": [],
        "admin": [],
        "auth": [],
        "search": [],
        "product": [],
        "checkout": [],
        "profile": [],
        "static": [],
        "other": []
    }

    for url in urls:
        url_lower = url.lower()
        # Check for API in subdomain (api.test.com) or path (/api/)
        parsed = url_lower.replace("https://", "").replace("http://", "")
        hostname = parsed.split("/")[0]
        path = "/" + "/".join(parsed.split("/")[1:]) if "/" in parsed else ""

        if ("api." in hostname or "/api/" in path or
            "_api" in hostname or "-api" in hostname):
            categories["api"].append(url)
        elif "/user" in url_lower or "/account" in url_lower or "/profile" in url_lower:
            categories["user"].append(url)
        elif "/admin" in url_lower or "/dashboard" in url_lower or "/manage" in url_lower:
            categories["admin"].append(url)
        elif "/auth" in url_lower or "/login" in url_lower or "/register" in url_lower or "/password" in url_lower:
            categories["auth"].append(url)
        elif "/search" in url_lower or "/q=" in url_lower or "?q=" in url_lower:
            categories["search"].append(url)
        elif "/product" in url_lower or "/p/" in url_lower or "/item" in url_lower:
            categories["product"].append(url)
        elif "/checkout" in url_lower or "/basket" in url_lower or "/cart" in url_lower or "/order" in url_lower:
            categories["checkout"].append(url)
        elif ".js" in url_lower or ".css" in url_lower or "/static/" in url_lower:
            categories["static"].append(url)
        else:
            categories["other"].append(url)

    return categories


def format_context_for_agent(context: dict, task: str) -> str:
    """Format context as a readable prompt section for an agent."""
    lines = [
        f"# Context for {task}",
        "",
        f"**Program:** {context['program']}",
        f"**Prepared:** {context['prepared_at']}",
        "",
    ]

    # Scope
    if context.get("scope"):
        lines.append("## Scope")
        for item in context["scope"]:
            lines.append(f"- {item}")
        lines.append("")

    # Categorized endpoints
    if context.get("categorized"):
        lines.append("## Target URLs by Category")
        cat = context["categorized"]
        for category, urls in cat.items():
            if urls:
                lines.append(f"\n### {category.upper()} ({len(urls)})")
                for url in urls[:20]:  # Limit to 20 per category
                    lines.append(f"- {url}")
                if len(urls) > 20:
                    lines.append(f"- ... and {len(urls) - 20} more")
        lines.append("")

    # JS secrets
    if context.get("js_secrets"):
        lines.append("## Potential Secrets Found in JS")
        for secret in context["js_secrets"][:10]:
            lines.append(f"- {secret}")
        lines.append("")

    # Tested endpoints (what NOT to retest)
    if context.get("tested_endpoints"):
        lines.append(f"## Already Tested ({len(context['tested_endpoints'])})")
        lines.append("These have already been tested — focus on new endpoints.")
        lines.append("")

    # Previous findings
    if context.get("previous_findings"):
        lines.append(f"## Previous Findings ({len(context['previous_findings'])})")
        for f in context["previous_findings"][:5]:
            lines.append(f"- {f.get('vuln_type', 'Unknown')}: {f.get('endpoint', 'Unknown URL')}")
        lines.append("")

    return "\n".join(lines)


def prep_test_context(program_name: str, test_urls: list) -> dict:
    """Create a minimal context for quick testing."""
    return {
        "program": program_name,
        "prepared_at": datetime.now().isoformat(),
        "scope": [],
        "endpoints": test_urls,
        "categorized": categorize_urls(test_urls),
        "tested_endpoints": [],
        "previous_findings": []
    }

def prep_superdrug_context():
    """Quick context prep for superdrug specifically."""
    return prep_recon_context("superdrug")
