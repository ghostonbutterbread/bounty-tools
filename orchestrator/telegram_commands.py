#!/usr/bin/env python3
"""
Telegram Command Handlers for Ghost Orchestrator

Commands:
    /hunt <program> [tasks]     Hunt a target (xss, sqli, ssrf, bac, recon, fuzz)
    /status                      Show orchestrator status
    /findings [program]          Show findings
    /targets                     List all targets  
    /spawn <program> <task>       Spawn a specific agent
    /report [program]             Generate report
    /add-target <name> --scope   Add a new target

Usage:
    from orchestrator.telegram_commands import handle_command
    handle_command(message_text) -> str (response)
"""

import sys
import re
from datetime import datetime

sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

from orchestrator.state_manager import state_mgr
from orchestrator.findings_store import load_all_findings, generate_report, save_finding
from orchestrator.context_prep import prep_recon_context, prep_test_context
from orchestrator.spawn import AgentRuntime, spawn_agent, spawn_parallel_agents
from orchestrator.hunt import hunt as run_hunt


# ─── Command Router ────────────────────────────────────────────────────────────

def handle_command(text: str) -> str:
    """Route a Telegram message to the appropriate handler.
    
    Args:
        text: The raw message text from Telegram
        
    Returns:
        Response message to send back
    """
    text = text.strip()
    
    # Parse command and args
    parts = text.split()
    if not parts:
        return "Empty command. Try /help"
    
    cmd = parts[0].lower()
    args = parts[1:]
    
    try:
        if cmd == "/hunt":
            return cmd_hunt(args)
        elif cmd == "/status":
            return cmd_status(args)
        elif cmd == "/findings":
            return cmd_findings(args)
        elif cmd == "/targets":
            return cmd_targets(args)
        elif cmd == "/spawn":
            return cmd_spawn(args)
        elif cmd == "/report":
            return cmd_report(args)
        elif cmd == "/add-target":
            return cmd_add_target(args)
        elif cmd == "/help":
            return cmd_help(args)
        elif cmd == "/myskills":
            return cmd_myskills(args)
        elif cmd == "/quick":
            return cmd_quick(args)
        elif cmd == "/xss":
            return cmd_xss(args)
        elif cmd == "/sqli":
            return cmd_sqli(args)
        elif cmd == "/ssrf":
            return cmd_ssrf(args)
        elif cmd == "/bac":
            return cmd_bac(args)
        elif cmd == "/fuzz":
            return cmd_fuzz(args)
        elif cmd == "/recon":
            return cmd_recon(args)
        elif cmd == "/js":
            return cmd_js(args)
        elif cmd == "/subdomain":
            return cmd_subdomain(args)
        elif cmd == "/dork":
            return cmd_dork(args)
        elif cmd == "/secrets":
            return cmd_secrets(args)
        else:
            return f"Unknown command: {cmd}\n\nTry /help"
    except Exception as e:
        return f"Error: {e}"


# ─── Command Handlers ──────────────────────────────────────────────────────────

def cmd_status(args: list) -> str:
    """Show orchestrator status."""
    state = state_mgr.read()
    
    lines = [
        "👻 *Ghost Orchestrator Status*",
        "",
        f"Last updated: {state.get('last_updated', 'Never') or 'Never'}",
        "",
        f"*Targets:* {len(state.get('targets', {}))}",
    ]
    
    for name, target in state.get('targets', {}).items():
        last = target.get('last_tested') or 'Never tested'
        lines.append(f"  • {name} — {last}")
    
    lines.append(f"\n*Findings:* {len(state.get('findings', []))}")
    by_status = {}
    for f in state.get('findings', []):
        s = f.get('status', 'unknown')
        by_status[s] = by_status.get(s, 0) + 1
    for status, count in sorted(by_status.items()):
        lines.append(f"  • {status}: {count}")
    
    lines.append(f"\n*Active Agents:* {len(state.get('active_agents', []))}")
    for agent in state.get('active_agents', []):
        lines.append(f"  • {agent['task']} on {agent['target']}")
    
    return "\n".join(lines)


def cmd_hunt(args: list) -> str:
    """Start a hunt session."""
    from orchestrator.config import RUNTIME_BY_TASK, TASK_INFO
    
    if not args:
        return "Usage: /hunt <program> [tasks] [--parallel] [--runtime claude|subagent]\n\nExample: /hunt superdrug xss,sqli --parallel\n\n*Runtime by task:*\n🕷️ xss → claude (needs browser)\n💉 sqli → claude (needs reasoning)\n🌐 ssrf → claude (needs reasoning)\n🔓 bac → claude (complex auth)\n💥 fuzz → subagent (fast ffuf)\n🔍 recon → subagent (fast)\n📜 js → subagent (fast)\n🌍 subdomain → subagent (fast)"
    
    program = args[0]
    
    # Parse options
    tasks = ["xss"]  # default
    parallel = False
    runtime_override = None  # User-specified override
    
    VALID_TASKS = ["xss", "sqli", "ssrf", "bac", "recon", "fuzz", "js", "subdomain", "all"]
    
    for arg in args[1:]:
        if arg.startswith("--"):
            opt = arg[2:]
            if opt == "parallel":
                parallel = True
            elif opt.startswith("runtime="):
                runtime_override = opt.split("=")[1]
        elif "," in arg:
            # Comma-separated list: extend, don't replace
            found = [t.strip() for t in arg.split(",") if t.strip() in VALID_TASKS]
            if found:
                tasks = found
        elif arg in VALID_TASKS:
            # Single task: extend list
            tasks = [arg]
    
    if "all" in tasks:
        tasks = ["xss", "sqli", "ssrf", "bac", "fuzz", "recon"]
    
    # Check target exists
    state = state_mgr.read()
    if program not in state.get("targets", {}):
        return f"Target '{program}' not found. Add it first: /add-target {program} --scope *.target.com"
    
    # Determine runtime for each task
    runtime_map = {}
    for task in tasks:
        task_key = task.lower().strip()
        if runtime_override:
            runtime_map[task] = runtime_override
        else:
            runtime_map[task] = RUNTIME_BY_TASK.get(task_key, "claude")
    
    # Group by runtime
    by_runtime = {}
    for task, rt in runtime_map.items():
        if rt not in by_runtime:
            by_runtime[rt] = []
        by_runtime[rt].append(task)
    
    # Build response
    runtime_emoji = {"claude": "🤖", "subagent": "🐍", "codex": "⚡"}
    runtime_name = {"claude": "Claude Code", "subagent": "Sub-Agent", "codex": "Codex"}
    
    lines = [
        f"🎯 *Hunt: {program}*",
        f"Tasks: {', '.join(tasks)}",
        f"Mode: {'Parallel' if parallel else 'Sequential'}",
        "",
    ]
    
    for rt, task_list in by_runtime.items():
        emoji = runtime_emoji.get(rt, "•")
        name = runtime_name.get(rt, rt)
        lines.append(f"{emoji} *{name}*: {', '.join(task_list)}")
    
    lines.append("")
    
    # Actually spawn the agents
    try:
        # Only run subagents directly (Claude Code needs ACP sessions)
        subagent_tasks = [t for t in tasks if RUNTIME_BY_TASK.get(t, "claude") == "subagent"]
        claude_tasks = [t for t in tasks if RUNTIME_BY_TASK.get(t, "claude") == "claude"]
        
        if subagent_tasks:
            # Build task list for hunt
            from orchestrator.hunt import hunt
            from orchestrator.spawn import AgentRuntime
            result = hunt(
                program_name=program,
                tasks=subagent_tasks,
                runtime=AgentRuntime.SUBAGENT,
                parallel=parallel,
            )
            lines.append(f"✅ Spawned {len(result['agents'])} agent(s)")
            lines.append(f"Agent IDs: {', '.join(a['agent_id'] for a in result['agents'])}")
        
        if claude_tasks:
            lines.append(f"🤖 Claude tasks queued (need Max plan + ACP sessions): {', '.join(claude_tasks)}")
            lines.append("Configure Claude Code ACP to enable Claude agent spawning.")
        
    except Exception as e:
        lines.append(f"❌ Error: {e}")
    
    return "\n".join(lines)


def cmd_findings(args: list) -> str:
    """Show findings."""
    program = None
    severity = None
    
    for arg in args:
        if arg.startswith("--"):
            if arg.startswith("--severity="):
                severity = arg.split("=")[1]
        else:
            program = arg
    
    findings = load_all_findings()
    
    if program:
        findings = [f for f in findings if program.lower() in f.get('target', '').lower()]
    
    if severity:
        findings = [f for f in findings if severity.upper() in f.get('severity', '').upper()]
    
    if not findings:
        return "🔍 *No findings yet*\n\nStart a hunt to find vulnerabilities!"
    
    lines = [f"📋 *{len(findings)} Findings*"]
    
    if program:
        lines.append(f"Target: {program}")
    if severity:
        lines.append(f"Severity: {severity}")
    
    lines.append("")
    
    # Group by severity
    by_sev = {}
    for f in findings:
        sev = f.get('severity', 'Info')
        if sev not in by_sev:
            by_sev[sev] = []
        by_sev[sev].append(f)
    
    for sev in sorted(by_sev.keys()):
        lines.append(f"\n*{sev}* ({len(by_sev[sev])})")
        for f in by_sev[sev][:3]:  # Max 3 per severity
            lines.append(f"  • {f['vuln_type']} @ {f.get('endpoint', 'N/A')[:50]}")
        if len(by_sev[sev]) > 3:
            lines.append(f"  ... and {len(by_sev[sev]) - 3} more")
    
    return "\n".join(lines)


def cmd_targets(args: list) -> str:
    """List all targets."""
    state = state_mgr.read()
    targets = state.get("targets", {})
    
    if not targets:
        return "🎯 *No targets yet*\n\nAdd one: /add-target <name> --scope example.com"
    
    lines = [f"🎯 *{len(targets)} Targets*", ""]
    
    for name, target in targets.items():
        scope = ", ".join(target.get("scope", [])[:2])
        if len(target.get("scope", [])) > 2:
            scope += "..."
        last = target.get("last_tested") or "Never"
        history = len(target.get("test_history", []))
        
        lines.append(f"*{name}*")
        lines.append(f"  Scope: {scope}")
        lines.append(f"  Tests: {history} | Last: {last[:10] if last else 'Never'}")
        lines.append("")
    
    return "\n".join(lines).strip()


def cmd_spawn(args: list) -> str:
    """Spawn a specific agent."""
    if len(args) < 2:
        return "Usage: /spawn <program> <task> [--runtime claude|codex]\n\nExample: /spawn superdrug xss --runtime claude"
    
    program = args[0]
    task = args[1]
    runtime = "claude"
    
    for arg in args[2:]:
        if arg.startswith("--runtime="):
            runtime = arg.split("=")[1]
    
    lines = [
        f"🤖 *Spawning Agent*",
        f"Target: {program}",
        f"Task: {task}",
        f"Runtime: {runtime.upper()}",
        "",
        "⚠️ Agent spawning via Telegram not yet wired.",
        "Use CLI or API for now.",
    ]
    
    return "\n".join(lines)


def cmd_report(args: list) -> str:
    """Generate a report."""
    program = None
    fmt = "markdown"
    
    for arg in args:
        if arg.startswith("--"):
            if arg.startswith("--format="):
                fmt = arg.split("=")[1]
        else:
            program = arg
    
    findings = load_all_findings()
    
    if program:
        findings = [f for f in findings if program.lower() in f.get('target', '').lower()]
    
    if not findings:
        return "📋 *No findings to report*"
    
    report = generate_report(findings, fmt)
    
    # Truncate if too long for Telegram
    if len(report) > 4000:
        report = report[:4000] + "\n\n... (truncated)"
    
    return f"📊 *Report*\n\n{report}"


def cmd_add_target(args: list) -> str:
    """Add a new target."""
    if not args:
        return "Usage: /add-target <name> --scope example.com,api.example.com [--accounts user@email.com]"
    
    name = args[0]
    scope = []
    accounts = []
    
    for arg in args[1:]:
        if arg.startswith("--scope="):
            scope = arg.split("=", 1)[1].split(",")
        elif arg.startswith("--accounts="):
            accounts = arg.split("=", 1)[1].split(",")
    
    if not scope:
        return "Error: --scope required\n\nUsage: /add-target <name> --scope example.com"
    
    state_mgr.add_target(name, scope, accounts)
    
    lines = [
        f"✅ *Target Added: {name}*",
        f"Scope: {', '.join(scope)}",
    ]
    
    if accounts:
        lines.append(f"Accounts: {', '.join(accounts)}")
    
    return "\n".join(lines)


def cmd_quick(args: list) -> str:
    """Quick single-URL test."""
    if len(args) < 2:
        return "Usage: /quick <program> <url> <vuln_type>\n\nExample: /quick superdrug https://example.com/search?q=test xss"
    
    program = args[0]
    url = args[1]
    vuln_type = args[2] if len(args) > 2 else "xss"
    
    lines = [
        f"⚡ *Quick Test*",
        f"Program: {program}",
        f"URL: {url}",
        f"Type: {vuln_type}",
        "",
        "⚠️ Quick hunt via Telegram not yet wired.",
        "Use API for now.",
    ]
    
    return "\n".join(lines)


def cmd_help(args: list) -> str:
    """Show help."""
    return """
👻 *Ghost Orchestrator Commands*

*Status & Info*
/status — Orchestrator status
/targets — List all targets
/findings [program] — Show findings
/report [program] — Generate report

*Quick Hunt (direct commands)*
/xss <program> — XSS hunting (🤖 Claude)
/sqli <program> — SQL injection (🤖 Claude)
/ssrf <program> — SSRF testing (🤖 Claude)
/bac <program> — Broken Access Control (🤖 Claude)
/fuzz <program> — Web fuzzing (🐍 Sub-agent)
/recon <program> — Recon enumeration (🐍 Sub-agent)
/js <program> — JS analysis (🐍 Sub-agent)
/subdomain <program> — Subdomain enum (🐍 Sub-agent)

*Full Hunt*
/hunt <program> [tasks] — Hunt with auto-runtime selection

*Options*
--parallel — Run tasks simultaneously
--runtime claude|subagent — Override runtime
--severity P1 — Filter by severity

*Examples*
/hunt superdrug xss,sqli --parallel
/xss superdrug --runtime claude
/fuzz superdrug
/bac superdrug
/findings superdrug --severity P1
"""

# ─── Individual Task Commands ──────────────────────────────────────────────────

def cmd_xss(args: list) -> str:
    """Spawn XSS hunter agent."""
    return cmd_generic_spawn(args, "xss", "XSS", "claude")

def cmd_sqli(args: list) -> str:
    """Spawn SQL injection hunter agent."""
    return cmd_generic_spawn(args, "sqli", "SQL Injection", "claude")

def cmd_ssrf(args: list) -> str:
    """Spawn SSRF hunter agent."""
    return cmd_generic_spawn(args, "ssrf", "SSRF", "claude")

def cmd_bac(args: list) -> str:
    """Spawn BAC tester agent."""
    return cmd_generic_spawn(args, "bac", "Broken Access Control", "claude")

def cmd_fuzz(args: list) -> str:
    """Spawn fuzz agent (sub-agent)."""
    return cmd_generic_spawn(args, "fuzz", "Web Fuzzing", "subagent")

def cmd_recon(args: list) -> str:
    """Spawn recon agent (sub-agent)."""
    return cmd_generic_spawn(args, "recon", "Reconnaissance", "subagent")

def cmd_js(args: list) -> str:
    """Spawn JS analyst agent (sub-agent)."""
    return cmd_generic_spawn(args, "js", "JS Analysis", "subagent")

def cmd_subdomain(args: list) -> str:
    """Spawn subdomain enum agent (sub-agent)."""
    return cmd_generic_spawn(args, "subdomain", "Subdomain Enumeration", "subagent")


def cmd_dork(args: list) -> str:
    """Run Google dorking against a target — searches for admin panels, sensitive files, and exposed endpoints.

    Usage: /dork <program> [max_dorks] [--domains domain1 domain2]

    Example:
        /dork superdrug
        /dork superdrug 30
        /dork superdrug 50 --domains superdrug.com api.superdrug.com
    """
    import sys
    sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

    from orchestrator.state_manager import state_mgr

    if not args:
        return (
            "Usage: /dork <program> [max_dorks] [--domains domain1 domain2]\n\n"
            "Example:\n"
            "  /dork superdrug          — run all dorks\n"
            "  /dork superdrug 30       — run first 30 dorks\n"
            "  /dork superdrug 50 --domains superdrug.com api.superdrug.com\n\n"
            "What it searches:\n"
            "  • Admin panels and control panels\n"
            "  • Sensitive files (.env, .sql, .bak, configs)\n"
            "  • API docs (Swagger, OpenAPI, /api/v1/)\n"
            "  • Debug pages and exposed internal tools\n"
            "  • Source code repos (.git, .svn)\n"
            "  • Cloud storage buckets"
        )

    program = args[0]

    # Parse optional max_dorks
    max_dorks = None
    domains = None
    for i, arg in enumerate(args[1:], 1):
        if arg == "--domains":
            domains = args[i + 1:]
            break
        elif arg.isdigit():
            max_dorks = int(arg)

    # Load target scope
    state = state_mgr.read()
    target = state.get("targets", {}).get(program, {})
    if not target:
        return f"Target '{program}' not found. Add it: /add-target {program} --scope *.target.com"

    # Use provided domains or fall back to target scope
    if not domains:
        scope = target.get("scope", [])
        if isinstance(scope, list):
            domains = [s.lstrip("*. ") for s in scope if s]
        elif isinstance(scope, str):
            domains = [scope.lstrip("*. ")]
        else:
            domains = [program]

    # Extract base domains from wildcard scope
    clean_domains = []
    for d in domains:
        d = d.replace("*.", "").replace("*", "").strip()
        if d:
            clean_domains.append(d)

    if not clean_domains:
        return f"No scope domains found for '{program}'. Add scope with /add-target {program} --scope *.target.com"

    # Count how many dorks will run
    sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")
    from agents.google_dorker import DORK_CATEGORIES
    total_dorks = sum(len(info["dorks"]) for info in DORK_CATEGORIES.values())
    dork_count = min(max_dorks or total_dorks, total_dorks)
    categories = ", ".join(DORK_CATEGORIES.keys())

    # Write a runner script that the subprocess will execute
    import json
    import uuid
    import os

    agent_id = str(uuid.uuid4())[:8]
    runner_dir = os.path.expanduser(f"~/.openclaw/agents/dork-{agent_id}")
    os.makedirs(runner_dir, exist_ok=True)

    runner_script = os.path.join(runner_dir, "run_dork.py")
    with open(runner_script, "w") as f:
        f.write(f"""
import sys
sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")
from agents.google_dorker import GoogleDorker

dorker = GoogleDorker(
    program="{program}",
    domains={json.dumps(clean_domains)}
)
stats = dorker.run(max_dorks={max_dorks or total_dorks}, delay=3.0)

# Write results summary to a file for inspection
results_file = stats.get("findings_file", "")
print(f"DONE: {{stats['interesting_results']}} hits from {{stats['total_searches']}} searches")
print(f"Results: {{results_file}}")
""")

    # Spawn background process
    log_file = os.path.join(runner_dir, "dork.log")
    fh = open(log_file, "w")

    try:
        import subprocess
        proc = subprocess.Popen(
            ["python3", runner_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=runner_dir,
        )
        # Don't wait for it — let it run in background
    except Exception as e:
        return f"❌ Failed to start dork process: {e}"

    results_dir = os.path.expanduser(f"/home/ryushe/Shared/bounty_recon/{program}/ghost/dorks")

    lines = [
        f"🔍 *Google Dorking Started*",
        f"Target: {program}",
        f"Domains: {', '.join(clean_domains[:5])}",
        f"Dorks: ~{dork_count} ({categories})",
        f"Agent ID: dork-{agent_id}",
        "",
        "Running in background... I'll check results when done.",
        f"Log: `{log_file}`",
        f"Results dir: `{results_dir}/`",
    ]
    return "\n".join(lines)


def cmd_secrets(args: list) -> str:
    """Run secrets finder on a program.

    Usage: /secrets <program> [--source js_dir|urls_file|wayback]

    Example:
        /secrets superdrug
        /secrets superdrug --source js_dir
        /secrets superdrug --source wayback
    """
    import sys
    sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

    from agents.secrets_finder import SecretsFinder

    if not args:
        return (
            "Usage: /secrets <program> [--source js_dir|urls_file|wayback]\n\n"
            "Scan JS files, URL lists, or Wayback for secrets.\n\n"
            "Sources:\n"
            "  js_dir    - Scan downloaded JS files in ghost/js_analysis/raw_js/\n"
            "  urls_file - Scan params.txt for secrets in URLs\n"
            "  wayback  - Query Wayback Machine for JS files\n\n"
            "Example:\n"
            "  /secrets superdrug\n"
            "  /secrets superdrug --source wayback\n"
        )

    # Parse args
    source = "auto"
    program = args[0]

    if len(args) > 1:
        if args[1] == "--source" and len(args) > 2:
            source = args[2]
        else:
            return f"Unknown argument: {args[1]}\nUse --source js_dir|urls_file|wayback"

    from pathlib import Path
    program_dir = Path.home() / "Shared" / "bounty_recon" / program
    if not program_dir.exists():
        return f"Program directory not found: {program_dir}"

    # Determine source paths
    js_dir = program_dir / "ghost" / "js_analysis" / "raw_js"
    urls_file = program_dir / "params.txt"
    output_dir = program_dir / "ghost" / "secrets_scan"

    finder = SecretsFinder(program=program)

    try:
        if source in {"auto", "js_dir"} and js_dir.exists():
            finder.scan_directory(js_dir)

        if source in {"auto", "urls_file"} and urls_file.exists():
            finder.scan_url_list(urls_file)

        if source in {"auto", "wayback"}:
            finder.scan_wayback(f"{program}.com", limit=20)

        results = finder.get_results()
        finder.save_results(output_dir)

        # Write findings to Obsidian notes (auto-organized by category)
        try:
            notes_result = finder.save_notes()
            notes_written = notes_result.get("notes_written", [])
        except Exception:
            notes_written = []

        lines = [
            f"🕵️ Secrets Scan — {program}",
            "",
            f"Total findings: {results['total_findings']}",
            "",
            "By severity:",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = results["summary"]["by_severity"].get(sev, 0)
            if count:
                lines.append(f"  {sev}: {count}")

        if results["findings"]:
            lines.append("")
            lines.append("Top findings:")
            for f in results["findings"][:5]:
                lines.append(f"  [{f['severity']}] {f['type']}: {f['value'][:50]}...")

        lines.append("")
        lines.append(f"Results: {output_dir}/")
        if notes_written:
            lines.append(f"Notes written: {len(notes_written)} files → notes/{program}/findings/")

        return "\n".join(lines)

    except Exception as e:
        return f"Error: {e}"


def cmd_generic_spawn(args: list, task_type: str, display_name: str, preferred_runtime: str) -> str:
    """Generic handler for individual task commands with fallback support."""
    # Import inside function to avoid circular imports
    from orchestrator.config import RUNTIME_BY_TASK
    from orchestrator.state_manager import state_mgr
    from orchestrator.context_prep import prep_recon_context
    # Import directly from spawn.py to avoid circular import with hunt.py
    import orchestrator.spawn as spawn_module
    AgentRuntime = spawn_module.AgentRuntime
    spawn_agent = spawn_module.spawn_agent
    
    if not args:
        return f"Usage: /{task_type} <program>\n\nExample: /{task_type} superdrug"
    
    program = args[0]
    runtime = RUNTIME_BY_TASK.get(task_type, preferred_runtime)
    
    # Check for runtime override
    for arg in args[1:]:
        if arg.startswith("--runtime="):
            runtime = arg.split("=")[1]
    
    # Check target exists
    state = state_mgr.read()
    if program not in state.get("targets", {}):
        return f"Target '{program}' not found. Add it first: /add-target {program} --scope *.target.com"
    
    # Get context for the program
    context = prep_recon_context(program)
    
    # Try to spawn, with fallback
    agent_info = None
    fallback = False
    error_msg = None
    
    if runtime == "claude":
        # Try Claude Code first, fallback to sub-agent
        try:
            agent = spawn_agent(
                program_name=program,
                task_type=task_type,
                task_description=f"{display_name} on {program}",
                context=context,
                runtime=AgentRuntime.CLAUDE
            )
            agent_info = agent
        except Exception as e:
            error_msg = str(e)
            if "Max" in error_msg or "ACP" in error_msg or "OAuth" in error_msg or "provider" in error_msg.lower():
                fallback = True
            else:
                return f"❌ Claude Code spawn failed: {error_msg}\n\nFallback not available for this error."
    
    if runtime == "subagent" or fallback or agent_info is None:
        # Spawn sub-agent with tailored prompt
        try:
            agent_info = run_subagent_task(program, task_type)
            
            # Also spawn via spawn_agent for proper tracking
            agent = spawn_agent(
                program_name=program,
                task_type=task_type,
                task_description=agent_info.get("description", display_name),
                context=context,
                runtime=AgentRuntime.SUBAGENT
            )
            agent_info.update(agent)
            
            if fallback:
                runtime_note = f"🤖 Claude Code unavailable ({error_msg}), fell back to 🐍 Sub-agent"
            else:
                runtime_note = f"🐍 Spawned Sub-agent"
        except Exception as e:
            return f"❌ Failed to spawn sub-agent: {e}"
    else:
        runtime_note = f"🤖 Spawned Claude Code agent"
    
    emoji = {"claude": "🤖", "subagent": "🐍", "codex": "⚡"}
    runtime_name = {"claude": "Claude Code", "subagent": "Sub-Agent", "codex": "Codex"}
    
    lines = [
        f"{emoji.get(runtime, '•')} *{display_name}*",
        f"Target: {program}",
        f"Status: Started",
        f"Agent ID: {agent_info.get('agent_id', 'unknown')}",
        f"",
        runtime_note,
        f"",
        "Results will be reported when complete. Check /status for active agents."
    ]
    
    return "\n".join(lines)


def cmd_myskills(args: list) -> str:
    """Show all skills with their runtime and status."""
    from orchestrator.config import RUNTIME_BY_TASK, TASK_INFO
    
    # Sub-agent tasks (these work right now)
    subagent_tasks = ["fuzz", "recon", "js", "subdomain"]
    
    # Claude tasks (need Max plan)
    claude_tasks = ["xss", "sqli", "ssrf", "bac"]
    
    lines = [
        "👻 *My Skills — Ghost Orchestrator*",
        "",
        "*🐍 Sub-Agent Tasks (Working Now)*",
    ]
    
    for task in subagent_tasks:
        info = TASK_INFO.get(task, {})
        emoji = info.get("emoji", "•")
        name = info.get("name", task)
        lines.append(f"  /{task} — {emoji} {name} — ✅ Ready")
    
    lines.extend([
        "",
        "*🤖 Claude Code Tasks (Need Max Plan)*",
        "  ⚠️ Will fallback to sub-agent if Claude unavailable",
    ])
    
    for task in claude_tasks:
        info = TASK_INFO.get(task, {})
        emoji = info.get("emoji", "•")
        name = info.get("name", task)
        lines.append(f"  /{task} — {emoji} {name} — ⚠️ Needs Max")
    
    lines.extend([
        "",
        "*📋 Other Commands*",
        "  /status — Orchestrator status",
        "  /targets — List targets",
        "  /findings — View findings",
        "  /hunt — Multi-task hunt",
        "  /orchestrator — Main orchestrator",
        "",
        "*ℹ️ Notes*",
        "• Sub-agents: Fast, working, no extra config needed",
        "• Claude Code: Powerful but needs Max plan setup",
        "• Fallback: Claude tasks auto-fallback to sub-agent if unavailable",
        "• To test: /fuzz superdrug (works now)",
    ])
    
    return "\n".join(lines)


def spawn_subagent_task(program: str, task_type: str, context: dict = None) -> dict:
    """Spawn a sub-agent with a tailored task.
    
    Returns agent info dict.
    """
    import sys
    sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
    from orchestrator.state_manager import state_mgr
    import uuid
    
    agent_id = str(uuid.uuid4())[:8]
    
    # Register agent
    state_mgr.register_agent(
        agent_id=agent_id,
        task=f"{task_type}: {program}",
        target=program
    )
    
    return {
        "agent_id": agent_id,
        "task_type": task_type,
        "program": program,
        "runtime": "subagent"
    }


# Sub-agent task prompts for each type
SUBAGENT_TASKS = {
    "fuzz": {
        "description": "Web fuzzing with ffuf",
        "system_prompt": """You are a Fuzz Agent. Fuzz a target website to discover hidden endpoints.

Target: https://www.superdrug.com
Program: superdrug

Setup:
```python
import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
from subagent_logger import SubagentLogger
log = SubagentLogger("fuzz", "superdrug", "{agent_id}")
log.start(target="https://www.superdrug.com", mode="dir")
```

Task:
1. Run ffuf directory scan:
```
ffuf -u https://www.superdrug.com/FUZZ -w /home/ryushe/wordlists/SecLists/Discovery/Web-Content/common.txt -mc 200-299,301,302,307,401,403,405,500 -fc 404 -c -v -t 20
```

2. Filter interesting findings (admin, api, debug, config, .env, staging, git)

3. Save results:
```python
log.finish(success=True)
```

Report your findings.""",
    },
    "recon": {
        "description": "Reconnaissance enumeration",
        "system_prompt": """You are a Recon Agent. Perform reconnaissance on a target.

Target: https://www.superdrug.com
Program: superdrug

Setup:
```python
import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
from subagent_logger import SubagentLogger
log = SubagentLogger("recon", "superdrug", "{agent_id}")
log.start(target="https://www.superdrug.com")
```

Task:
1. Crawl the homepage and extract all links
2. Identify API endpoints, forms, and parameters
3. Check for common exposed files (robots.txt, sitemap.xml)
4. Look for interesting JavaScript files

Tools to use:
- curl for fetching pages
- grep for extracting URLs
- Python for parsing

Report all interesting findings with full URLs.""",
    },
    "js": {
        "description": "JavaScript analysis for secrets",
        "system_prompt": """You are a JS Analyst Agent. Analyze JavaScript files for secrets and endpoints.

Target: https://www.superdrug.com
Program: superdrug

Setup:
```python
import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
from subagent_logger import SubagentLogger
log = SubagentLogger("js", "superdrug", "{agent_id}")
log.start(target="https://www.superdrug.com")
```

Task:
1. Find all JavaScript files on the homepage
2. Download and analyze each JS file
3. Look for:
   - API keys, tokens, credentials
   - Internal API endpoints
   - Debug statements
   - Interesting comments
   - Hardcoded URLs
   - Environment variables

Use curl to fetch JS files, grep to search patterns.

Report secrets and interesting findings.""",
    },
    "subdomain": {
        "description": "Subdomain enumeration",
        "system_prompt": """You are a Subdomain Enum Agent. Enumerate subdomains for a target.

Target: superdrug.com
Program: superdrug

Setup:
```python
import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
from subagent_logger import SubagentLogger
log = SubagentLogger("subdomain", "superdrug", "{agent_id}")
log.start(target="superdrug.com")
```

Task:
1. Use common subdomain wordlists to enumerate
2. Check for wildcards
3. Probe each subdomain for alive hosts

Use ffuf or similar tools:
```
ffuf -u https://FUZZ.superdrug.com -w /home/ryushe/wordlists/commonspeak2/subdomains.txt -mc 200-299,301,302,307,401,403 -c -v
```

Report discovered subdomains.""",
    },
    "xss": {
        "description": "XSS testing",
        "system_prompt": """You are an XSS Hunter Agent. Test for Cross-Site Scripting vulnerabilities.

Target: https://www.superdrug.com
Program: superdrug

Setup:
```python
import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
from subagent_logger import SubagentLogger
log = SubagentLogger("xss", "superdrug", "{agent_id}")
log.start(target="https://www.superdrug.com")
```

Task:
1. Identify all input points (search, forms, URL parameters)
2. Test basic XSS payloads: <script>alert(1)</script>, "><script>alert(1)</script>, <img src=x onerror=alert(1)>
3. Test for reflected XSS by injecting payloads and checking responses
4. Use browser automation if available

Use curl to test reflected parameters:
```
curl 'https://www.superdrug.com/search?q=<script>alert(1)</script>'
```

Report XSS findings with PoC.""",
    },
}


def run_subagent_task(program: str, task_type: str) -> dict:
    """Run a sub-agent task with proper setup.
    
    Returns dict with agent_id and task details.
    """
    import sys
    sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
    from orchestrator.state_manager import state_mgr
    import uuid
    
    agent_id = str(uuid.uuid4())[:8]
    
    # Get task prompt
    task_info = SUBAGENT_TASKS.get(task_type, {})
    if not task_info:
        return {"error": f"Unknown task type: {task_type}"}
    
    # Format the prompt
    prompt = task_info["system_prompt"].format(agent_id=agent_id)
    
    # Register agent
    state_mgr.register_agent(
        agent_id=agent_id,
        task=f"{task_type}: {program}",
        target=program
    )
    
    return {
        "agent_id": agent_id,
        "task_type": task_type,
        "program": program,
        "runtime": "subagent",
        "description": task_info["description"],
        "prompt": prompt
    }


def cmd_threat_map(args: list) -> str:
    """Run AI-powered threat landscape analysis for a bug bounty program.

    Usage: /threat-map <program>

    Example:
        /threat-map superdrug
        /threat-map intigriti-se
    """
    import sys
    sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")
    from threat_map import run_threat_map

    if not args:
        return (
            "Usage: /threat-map <program>\n\n"
            "Generates a comprehensive threat landscape report using AI.\n"
            "Reads existing findings, recon data, and searches public reports.\n\n"
            "Example:\n"
            "  /threat-map superdrug\n"
        )

    program = args[0]

    # Quick validation
    from pathlib import Path
    program_dir = Path.home() / "Shared" / "bounty_recon" / program
    if not program_dir.exists():
        return f"Program directory not found: {program_dir}\n\nUse a program that exists in ~/Shared/bounty_recon/"

    # Run threat map
    try:
        result = run_threat_map(program, use_claude=True)
        if "error" in result:
            return f"Error: {result['error']}"

        output = result.get("output_path", "unknown")
        findings = result.get("findings_count", 0)
        reports = result.get("public_reports", {})
        report_len = result.get("report_length", 0)

        lines = [
            f"🗺️  **Threat Map Complete — {program}**",
            "",
            f"**Analysis:** {findings} existing findings + {sum(reports.values())} public reports",
            f"**Report:** {output}",
            f"**Length:** {report_len} chars",
            "",
        ]

        return "\n".join(lines)

    except Exception as e:
        return f"Error running threat map: {e}"
