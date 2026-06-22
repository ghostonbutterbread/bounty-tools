"""
Hunt Workflow — High-level hunting orchestration that ties everything together.

Integrates:
  - BAC checks from bac_checks.py
  - Fuzzing via fuzz_command.py
  - Credential management via credential_store.py
  - Audit logging via subagent_logger
  - Agent spawning via spawn.py
"""

import sys
import os
import json
from datetime import datetime
from typing import Optional

sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

from orchestrator.spawn import AgentRuntime, run_agent, spawn_agent
from orchestrator.context_prep import prep_recon_context
from orchestrator.state_manager import state_mgr
from orchestrator.findings_store import (
    DEFAULT_CORE_FAMILY,
    DEFAULT_CORE_LANE,
    infer_core_program,
    save_finding,
    create_finding,
)


# ─── Logging Setup ────────────────────────────────────────────────────────────

def get_logger(program: str, tool: str = "hunt", *, family: str = DEFAULT_CORE_FAMILY, lane: str = DEFAULT_CORE_LANE):
    """Get a SubagentLogger instance if available."""
    try:
        from subagent_logger import SubagentLogger
        import uuid
        agent_id = f"{tool}_{datetime.now().strftime('%H%M%S')}"
        return SubagentLogger(tool, program, agent_id, family=family, lane=lane)
    except ImportError:
        return None


# ─── Credential Loading ───────────────────────────────────────────────────────

def load_credentials(program: str, *, family: str = DEFAULT_CORE_FAMILY, lane: str = DEFAULT_CORE_LANE):
    """Load credentials for a program."""
    try:
        from credential_store import CredentialStore
        store = CredentialStore(program, family=family, lane=lane)
        creds = store.get()
        account = store.get_account()
        return creds, account
    except ImportError:
        return None, None


# ─── BAC Integration ─────────────────────────────────────────────────────────

def get_bac_tests(target_base_url: str):
    """Get BAC test matrix from bac_checks.py."""
    try:
        from bac_checks import BACChecks
        checks = BACChecks()
        return checks.build_test_matrix(target_base_url)
    except ImportError:
        return []


def format_bac_tests_for_agent(bac_tests: list) -> str:
    """Format BAC tests as a task description for an agent."""
    lines = [
        "Run the following Broken Access Control (BAC) tests:",
        ""
    ]
    for i, test in enumerate(bac_tests[:10], 1):
        lines.append(f"{i}. {test.test_name}")
        lines.append(f"   - Method: {test.method} {test.endpoint}")
        lines.append(f"   - Expected: {test.expected}")
        lines.append(f"   - PoC: {test.poc}")
        lines.append("")
    return "\n".join(lines)


# ─── Fuzz Integration ────────────────────────────────────────────────────────

def run_fuzz(
    target: str,
    mode: str,
    wordlist: str = "auto",
    program: str = None,
    *,
    core_program: str = None,
    family: str = DEFAULT_CORE_FAMILY,
    lane: str = DEFAULT_CORE_LANE,
    no_core: bool = False,
):
    """Run fuzz_command.py and return results.

    Note: This spawns ffuf directly rather than using an agent.
    """
    import subprocess

    # Import wordlist mapping
    wordlist_map = {
        "dir": "~/wordlists/SecLists/Discovery/Web-Content/common.txt",
        "param": "~/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
        "subdomain": "~/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    }

    wordlist_path = wordlist_map.get(mode, wordlist_map["dir"])
    wordlist_path = os.path.expanduser(wordlist_path)

    cmd = [
        "python3",
        "/home/ryushe/projects/bounty-tools/fuzz_command.py",
        target,
        mode,
    ]
    if program:
        cmd.extend(["--program", program])
    if core_program:
        cmd.extend(["--core-program", core_program])
    if family:
        cmd.extend(["--family", family])
    if lane:
        cmd.extend(["--lane", lane])
    if no_core:
        cmd.append("--no-core")
    if wordlist and wordlist != "auto":
        cmd.extend(["--wordlist", os.path.expanduser(wordlist)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": cmd,
        }
    except Exception as e:
        return {
            "returncode": -1,
            "error": str(e),
        }


# ─── Hunt Workflow ───────────────────────────────────────────────────────────

def hunt(
    program_name: str,
    tasks: list = None,
    runtime: AgentRuntime = AgentRuntime.CLAUDE,
    model: str = None,
    parallel: bool = False,
    target_base: str = None,
    core_program: str = None,
    family: str = DEFAULT_CORE_FAMILY,
    lane: str = DEFAULT_CORE_LANE,
    no_core: bool = False,
) -> dict:
    """Run an automated hunting workflow.

    Args:
        program_name: Bug bounty program name
        tasks: List of task types (xss, sqli, ssrf, bac, recon, fuzz)
        runtime: AgentRuntime.CLAUDE or CODEX
        model: Model variant (sonnet/opus)
        parallel: If True, run agents in parallel (not yet implemented)
        target_base: Override target base URL (auto-detected from scope if None)
        core_program: Optional bounty-core program identity. Defaults to target_base hostname inference.
        family: bounty-core storage family (default: web_bounty)
        lane: bounty-core storage lane (default: web)
        no_core: Disable bounty-core ledger/report/index writes when True

    Returns:
        dict with keys: agents, findings_saved, errors
    """
    if tasks is None:
        tasks = ["recon"]

    # Load credentials
    creds, account = load_credentials(program_name, family=family, lane=lane)

    # Prepare context
    context = prep_recon_context(program_name, family=family, lane=lane)

    # Get scope for target_base
    if target_base is None:
        scope = context.get("scope", [])
        if scope:
            target_base = scope[0] if isinstance(scope[0], str) else scope[0].get("url", "")
        if not target_base:
            target_base = f"https://www.{program_name}.com"

    # Compatibility rule: the legacy hunt positional program remains the default
    # shared identity. A real URL is still used for target_base/context, but it
    # should not silently turn `hunt acme` into core program `acme-com`.
    resolved_core_program = infer_core_program(core_program or program_name or target_base)

    results = {
        "agents": [],
        "findings_saved": 0,
        "core_findings_written": 0,
        "core_findings_new": 0,
        "core_errors": [],
        "errors": [],
        "program": program_name,
        "core_program": None if no_core else resolved_core_program,
        "family": family,
        "lane": lane,
        "tasks": tasks,
    }

    # Get logger
    logger = get_logger(program_name, "hunt", family=family, lane=lane)
    if logger:
        logger.start(target=target_base, tasks=",".join(tasks), runtime=runtime.value)

    # Map task types to descriptions
    task_descriptions = {
        "recon": "Enumerate all discoverable endpoints and collect JavaScript files for analysis.",
        "xss": "Test for Cross-Site Scripting vulnerabilities in all input parameters.",
        "sqli": "Test for SQL injection in search, filter, and ID parameters.",
        "ssrf": "Test for Server-Side Request Forgery in URL and file parameters.",
        "bac": "Test for Broken Access Control and IDOR vulnerabilities.",
        "fuzz": "Run directory and parameter fuzzing to discover hidden endpoints.",
        "auth": "Test authentication and session handling mechanisms.",
        "js": "Analyze JavaScript files for hardcoded secrets and API endpoints.",
    }

    # Run each task
    for task in tasks:
        task_type = task.lower()
        task_description = task_descriptions.get(task_type, f"Run {task_type} security tests.")

        # Add BAC tests to context if needed
        if task_type == "bac":
            bac_tests = get_bac_tests(target_base)
            if bac_tests:
                bac_section = format_bac_tests_for_agent(bac_tests)
                task_description += "\n\n" + bac_section
                # Store tests in context for agent
                context["bac_tests"] = [
                    {"name": t.test_name, "endpoint": t.endpoint, "method": t.method}
                    for t in bac_tests
                ]

        try:
            if logger:
                logger.step(f"Running task: {task_type}")

            result = run_agent(
                program_name=program_name,
                task_type=task_type,
                task_description=task_description,
                context=context,
                runtime=runtime,
                model=model,
                account_name=account.email if account else None,
            )

            results["agents"].append({
                "task": task_type,
                "agent_id": result.get("agent_id"),
                "returncode": result.get("returncode"),
                "duration_ms": result.get("duration_ms"),
            })

            # Try to parse findings from agent output
            findings = parse_findings_from_output(result.get("stdout", ""), program_name, task_type)
            for finding in findings:
                save_finding(
                    finding,
                    core_program=resolved_core_program,
                    family=family,
                    lane=lane,
                    no_core=no_core,
                    record_core_result=True,
                )
                results["findings_saved"] += 1
                core_result = finding.get("core_result") or {}
                if core_result.get("ok"):
                    results["core_findings_written"] += core_result.get("written", 0)
                    results["core_findings_new"] += core_result.get("new", 0)
                elif core_result:
                    results["core_errors"].append(core_result.get("error") or core_result.get("errors"))

            if logger:
                logger.result(f"Completed {task_type}: {len(findings)} findings", findings_count=len(findings))

        except Exception as e:
            error_msg = f"Task {task_type} failed: {e}"
            results["errors"].append(error_msg)
            if logger:
                logger.error(error_msg, e)

    if logger:
        logger.finish(success=len(results["errors"]) == 0)

    return results


def parse_findings_from_output(output: str, program: str, task_type: str) -> list:
    """Parse findings from agent output.

    This is a basic parser — agents can output JSON or Markdown format.
    """
    findings = []

    # Try to find JSON array in output
    try:
        # Look for JSON block
        import re
        json_match = re.search(r'\[[\s\S]*"findings"[\s\S]*\]', output)
        if json_match:
            data = json.loads(json_match.group())
            if "findings" in data:
                for f in data["findings"]:
                    finding = create_finding(
                        target=program,
                        vuln_type=f.get("type", task_type),
                        endpoint=f.get("url", ""),
                        severity=f.get("severity", "Medium - P3"),
                        poc=f.get("poc", ""),
                        description=f.get("description", ""),
                    )
                    findings.append(finding)
                return findings
    except Exception:
        pass

    # Try markdown format parsing
    try:
        import re
        # Look for markdown headings like "### XSS - /endpoint"
        pattern = r'###\s+(\w+)\s+-\s+(https?://[^\s\n]+)'
        matches = re.findall(pattern, output)
        for vuln_type, endpoint in matches:
            finding = create_finding(
                target=program,
                vuln_type=vuln_type,
                endpoint=endpoint,
                severity="Medium - P3",  # Default
                poc="See agent output",
                description=f"{vuln_type} vulnerability found during {task_type} testing",
            )
            findings.append(finding)
    except Exception:
        pass

    return findings


# ─── Simple CLI for Direct Module Use ────────────────────────────────────────

def hunt_cli():
    """Simple CLI for hunting workflow."""
    import argparse
    parser = argparse.ArgumentParser(description="Ghost Hunt Workflow")
    parser.add_argument("program", help="Program name")
    parser.add_argument("--tasks", default="recon", help="Comma-separated tasks")
    parser.add_argument("--runtime", default="claude", choices=["claude", "codex"])
    parser.add_argument("--model", choices=["sonnet", "opus"])
    parser.add_argument("--core-program", "--name", dest="core_program", default=None,
                        help="bounty-core program/target identity/name (default: legacy program argument)")
    parser.add_argument("--family", default=DEFAULT_CORE_FAMILY,
                        help=f"bounty-core storage family for ledger writes (default: {DEFAULT_CORE_FAMILY})")
    parser.add_argument("--lane", default=DEFAULT_CORE_LANE,
                        help=f"bounty-core storage lane for ledger writes (default: {DEFAULT_CORE_LANE})")
    parser.add_argument("--no-core", action="store_true",
                        help="Disable bounty-core ledger/report/index writes")
    args = parser.parse_args()

    tasks = args.tasks.split(",")
    runtime = AgentRuntime.CLAUDE if args.runtime == "claude" else AgentRuntime.CODEX

    results = hunt(
        args.program,
        tasks,
        runtime,
        args.model,
        core_program=args.core_program,
        family=args.family,
        lane=args.lane,
        no_core=args.no_core,
    )
    print(f"Completed {len(results['agents'])} tasks")
    print(f"Findings saved: {results['findings_saved']}")
    if not args.no_core:
        print(f"bounty-core identity: program={results.get('core_program')} family={args.family} lane={args.lane}")
        print(f"bounty-core findings: wrote {results.get('core_findings_written', 0)} ({results.get('core_findings_new', 0)} new)")
    if results["errors"]:
        print(f"Errors: {results['errors']}")


if __name__ == "__main__":
    hunt_cli()
