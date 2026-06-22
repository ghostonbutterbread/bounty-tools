#!/usr/bin/env python3
"""
Ghost Orchestrator CLI — Entry point for the bug bounty hunting coordination layer.

Usage:
    python cli.py status
    python cli.py add-target acme --scope "*.example.com"
    python cli.py spawn acme xss "Test reflected XSS"
    python cli.py hunt acme --tasks xss,sqli --runtime claude

Or via module:
    python -m orchestrator.cli status
"""

import sys
import argparse
from datetime import datetime

# Add project to path
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

from orchestrator.state_manager import state_mgr
from orchestrator.context_prep import prep_recon_context
from orchestrator.findings_store import DEFAULT_CORE_FAMILY, DEFAULT_CORE_LANE, load_all_findings, generate_report
from orchestrator.spawn import AgentRuntime, spawn_agent, run_agent
from orchestrator.hunt import hunt


# ─── CLI Commands ──────────────────────────────────────────────────────────────

def cmd_status(args):
    """Show current orchestrator status."""
    state = state_mgr.read()
    print(f"\n=== Ghost Orchestrator Status ===")
    print(f"Last updated: {state.get('last_updated', 'Never')}")

    print(f"\nTargets: {len(state.get('targets', {}))}")
    for name, target in state.get('targets', {}).items():
        print(f"  - {name}: last tested {target.get('last_tested', 'Never')}")

    print(f"\nFindings: {len(state.get('findings', []))}")
    by_status = {}
    for f in state.get('findings', []):
        s = f.get('status', 'unknown')
        by_status[s] = by_status.get(s, 0) + 1
    for status, count in by_status.items():
        print(f"  - {status}: {count}")

    print(f"\nActive Agents: {len(state.get('active_agents', []))}")
    for agent in state.get('active_agents', []):
        print(f"  - {agent['agent_id']}: {agent['task']} ({agent['target']})")


def cmd_add_target(args):
    """Add a new target program."""
    scope = args.scope.split(',') if args.scope else []
    accounts = args.accounts.split(',') if args.accounts else []
    state_mgr.add_target(args.program, scope, accounts)
    print(f"Added target: {args.program}")


def cmd_findings(args):
    """Show findings."""
    findings = load_all_findings()
    if args.target:
        findings = [f for f in findings if args.target.lower() in f.get('target', '').lower()]
    if args.severity:
        findings = [f for f in findings if args.severity in f.get('severity', '')]

    if args.format == 'markdown':
        print(generate_report(findings, 'markdown'))
    else:
        print(generate_report(findings, 'json'))


def cmd_spawn(args):
    """Spawn a hunting agent (runs it immediately)."""
    context = prep_recon_context(args.program, family=args.family, lane=args.lane)

    runtime = AgentRuntime.CLAUDE if args.runtime == 'claude' else AgentRuntime.CODEX

    try:
        result = run_agent(
            program_name=args.program,
            task_type=args.task_type,
            task_description=args.task,
            context=context,
            runtime=runtime,
            model=args.model,
            chrome_port=int(args.chrome_port) if args.chrome_port else None
        )
        print(f"Agent completed: {result.get('agent_id')}")
        print(f"Return code: {result.get('returncode')}")
        if result.get('stdout'):
            print(f"\nOutput:\n{result['stdout'][:500]}")
        if result.get('stderr'):
            print(f"\nErrors:\n{result['stderr'][:500]}")
    except Exception as e:
        print(f"Error spawning agent: {e}")


def cmd_hunt(args):
    """Run automated hunting workflow."""
    tasks = args.tasks.split(',') if args.tasks else ['recon']
    runtime = AgentRuntime.CLAUDE if args.runtime == 'claude' else AgentRuntime.CODEX

    print(f"Starting hunt on '{args.program}' with tasks: {tasks}")
    print(f"Runtime: {args.runtime}")

    try:
        results = hunt(
            program_name=args.program,
            tasks=tasks,
            runtime=runtime,
            model=args.model,
            parallel=args.parallel,
            core_program=args.core_program,
            family=args.family,
            lane=args.lane,
            no_core=args.no_core,
        )
        print(f"\nHunt complete. Agents spawned: {len(results.get('agents', []))}")
        print(f"Findings saved: {results.get('findings_saved', 0)}")
        if not args.no_core:
            print(f"bounty-core identity: program={results.get('core_program')} family={args.family} lane={args.lane}")
            print(f"bounty-core findings: wrote {results.get('core_findings_written', 0)} ({results.get('core_findings_new', 0)} new)")
            if results.get('core_errors'):
                print(f"bounty-core errors: {results.get('core_errors')}")
    except Exception as e:
        print(f"Error during hunt: {e}")


def cmd_report(args):
    """Generate a report."""
    report = generate_report(format=args.format)
    print(report)


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ghost Orchestrator — Bug Bounty Hunting Coordination",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py status
  python cli.py add-target acme --scope "*.example.com" --accounts "test@example.com"
  python cli.py spawn acme xss "Test reflected XSS" --runtime claude
  python cli.py hunt acme --tasks xss,bac --runtime codex
        """
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Status
    subparsers.add_parser('status', help='Show orchestrator status')

    # Add target
    add_parser = subparsers.add_parser('add-target', help='Add a new target')
    add_parser.add_argument('program', help='Program name')
    add_parser.add_argument('--scope', help='Comma-separated scope entries')
    add_parser.add_argument('--accounts', help='Comma-separated account names')

    # Findings
    findings_parser = subparsers.add_parser('findings', help='Show findings')
    findings_parser.add_argument('--target', help='Filter by target')
    findings_parser.add_argument('--severity', help='Filter by severity')
    findings_parser.add_argument('--format', choices=['markdown', 'json'], default='markdown')

    # Spawn agent
    spawn_parser = subparsers.add_parser('spawn', help='Spawn and run a single hunting agent')
    spawn_parser.add_argument('program', help='Target program')
    spawn_parser.add_argument('task_type', help='Task type (xss, ssrf, sqli, bac, recon, fuzz)')
    spawn_parser.add_argument('task', help='Task description')
    spawn_parser.add_argument('--runtime', choices=['claude', 'codex'], default='claude',
                              help='Agent runtime (default: claude)')
    spawn_parser.add_argument('--model', choices=['sonnet', 'opus'],
                              help='Model variant (auto-selected by task if omitted)')
    spawn_parser.add_argument('--chrome-port', help='Specific Chrome debug port')
    spawn_parser.add_argument('--family', default=DEFAULT_CORE_FAMILY,
                              help=f'bounty-core storage family for context reads (default: {DEFAULT_CORE_FAMILY})')
    spawn_parser.add_argument('--lane', default=DEFAULT_CORE_LANE,
                              help=f'bounty-core storage lane for context reads (default: {DEFAULT_CORE_LANE})')

    # Hunt workflow
    hunt_parser = subparsers.add_parser('hunt', help='Run automated multi-task hunting workflow')
    hunt_parser.add_argument('program', help='Target program')
    hunt_parser.add_argument('--tasks', default='recon',
                             help='Comma-separated tasks: xss,sqli,bac,ssrf,recon,fuzz (default: recon)')
    hunt_parser.add_argument('--runtime', choices=['claude', 'codex'], default='claude')
    hunt_parser.add_argument('--model', choices=['sonnet', 'opus'])
    hunt_parser.add_argument('--parallel', action='store_true', help='Run tasks in parallel')
    hunt_parser.add_argument('--core-program', '--name', dest='core_program', default=None,
                             help='bounty-core program/target identity/name (default: legacy program argument)')
    hunt_parser.add_argument('--family', default=DEFAULT_CORE_FAMILY,
                             help=f'bounty-core storage family for ledger writes (default: {DEFAULT_CORE_FAMILY})')
    hunt_parser.add_argument('--lane', default=DEFAULT_CORE_LANE,
                             help=f'bounty-core storage lane for ledger writes (default: {DEFAULT_CORE_LANE})')
    hunt_parser.add_argument('--no-core', action='store_true',
                             help='Disable bounty-core ledger/report/index writes')

    # Report
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('--format', choices=['markdown', 'json'], default='markdown')

    args = parser.parse_args()

    if args.command == 'status':
        cmd_status(args)
    elif args.command == 'add-target':
        cmd_add_target(args)
    elif args.command == 'findings':
        cmd_findings(args)
    elif args.command == 'spawn':
        cmd_spawn(args)
    elif args.command == 'hunt':
        cmd_hunt(args)
    elif args.command == 'report':
        cmd_report(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
