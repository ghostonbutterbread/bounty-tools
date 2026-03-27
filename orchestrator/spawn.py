# Agent Spawning Module

import os
import json
import uuid
from enum import Enum

from .config import CHROME_PORTS, MODEL_BY_TASK
from .state_manager import StateManager

class AgentRuntime(Enum):
    CLAUDE = "claude"
    CODEX = "codex"
    SUBAGENT = "subagent"

CLAUDE_CLI = os.path.expanduser("/home/linuxbrew/.linuxbrew/bin/claude")

def spawn_agent(program_name, task_type, task_description, context, runtime=AgentRuntime.CLAUDE, model=None, chrome_port=None, account_name=None):
    agent_id = str(uuid.uuid4())[:8]
    if chrome_port is None:
        chrome_port = CHROME_PORTS[0]
    if model is None:
        model = MODEL_BY_TASK.get(task_type, "sonnet")
    
    working_dir = os.path.expanduser("~/.openclaw/agents/" + agent_id)
    os.makedirs(working_dir, exist_ok=True)
    
    prompt = _build_prompt(program_name, task_type, task_description, context, chrome_port, account_name)
    prompt_path = os.path.join(working_dir, "task.md")
    with open(prompt_path, "w") as f:
        f.write(prompt)
    
    if runtime == AgentRuntime.CLAUDE:
        cmd = [CLAUDE_CLI, "--print", "--system-prompt-file=" + prompt_path, "--no-input"]
    else:
        cmd = None
    
    return {
        "agent_id": agent_id,
        "runtime": runtime.value,
        "model": model,
        "chrome_port": chrome_port,
        "working_dir": working_dir,
        "prompt_path": prompt_path,
        "cmd": cmd,
    }

def _build_prompt(program_name, task_type, task_description, context, chrome_port, account_name):
    scope = context.get("scope", [])
    categorized = context.get("categorized", {})
    
    lines = [
        "# Bug Bounty Hunting Agent",
        "",
        "You are testing **" + program_name + "** for **" + task_type + "** vulnerabilities.",
        "",
        "## Your Task",
        task_description,
        "",
        "## Chrome Access",
        "Use openclaw browser --browser-profile user commands.",
        "",
        "## Scope",
    ]
    for s in scope[:5]:
        lines.append("  - " + s)
    
    if categorized:
        lines.append("")
        for cat, urls in categorized.items():
            if urls:
                lines.append(cat.upper() + " (" + str(len(urls)) + "):")
                for url in urls[:5]:
                    lines.append("  - " + url)
    
    lines.extend([
        "",
        "## Instructions",
        "1. Use Chrome to navigate and test the target",
        "2. Focus on " + task_type + " vectors",
        "3. Document ALL findings",
        "",
        "Begin hunting now.",
    ])
    
    return "\n".join(lines)

def run_agent(agent_config, timeout=600):
    import subprocess
    cmd = agent_config.get("cmd")
    if not cmd:
        return {"error": "No command", "agent_id": agent_config.get("agent_id")}
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=agent_config.get("working_dir"))
        return {
            "agent_id": agent_config.get("agent_id"),
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[:5000],
            "stderr": (result.stderr or "")[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"agent_id": agent_config.get("agent_id"), "returncode": -1, "error": "Timeout"}
    except Exception as e:
        return {"agent_id": agent_config.get("agent_id"), "returncode": -1, "error": str(e)}

def spawn_parallel_agents(program_name, tasks, context, runtime=AgentRuntime.SUBAGENT, model=None):
    agents = []
    for i, task in enumerate(tasks):
        chrome_port = CHROME_PORTS[i % len(CHROME_PORTS)]
        agent = spawn_agent(
            program_name=program_name,
            task_type=task["task_type"],
            task_description=task["task_description"],
            context=context,
            runtime=runtime,
            model=model,
            chrome_port=chrome_port,
        )
        agents.append(agent)
    return agents

def ensure_chrome_running(port=9222):
    import urllib.request
    try:
        response = urllib.request.urlopen("http://127.0.0.1:" + str(port) + "/json/version", timeout=2)
        return response.status == 200
    except Exception:
        return False

def get_chrome_for_agent(chrome_port=9222):
    if ensure_chrome_running(chrome_port):
        return {"port": chrome_port, "ready": True, "message": "Chrome running"}
    return {"port": chrome_port, "ready": False, "message": "Chrome not available"}
