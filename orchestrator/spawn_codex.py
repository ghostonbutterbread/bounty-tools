# Agent Spawner for Codex
# Spawns Codex agents with Chrome MCP access and proper context

import os
import json
import uuid
from datetime import datetime
from .config import MCP_SERVER, CHROME_PORTS, MODEL_BY_TASK
from .state_manager import state_mgr
from .context_prep import format_context_for_agent

# Codex CLI path
CODEX_CLI = os.path.expanduser("/home/linuxbrew/.linuxbrew/lib/node_modules/@openai/codex/bin/codex.js")

# Model mapping for Codex (GPT models)
MODEL_MAP = {
    "sonnet": "claude-sonnet-4-20250514",
    "opus": "claude-opus-4-20250514",
    "gpt-5.4": "gpt-5.4",
    "default": "gpt-5.4"
}

def spawn_codex_agent(
    program_name,
    task_type,
    task_description,
    context,
    model=None,
    chrome_port=None,
    account_name=None,
    working_dir=None
):
    """Spawn a Codex hunting agent with Chrome MCP access.
    
    Args:
        program_name: Target program (e.g., "superdrug")
        task_type: Type of hunt (xss, ssrf, sqli, bac, recon, etc.)
        task_description: Specific task for the agent
        context: Recon context from context_prep.py
        model: Override model (sonnet/opus/gpt-5.4, auto-selected if None)
        chrome_port: Specific Chrome debug port to use
        account_name: Name of account for this session
        working_dir: Working directory for the agent
    
    Returns:
        agent_id: UUID for this agent
    """
    agent_id = str(uuid.uuid4())[:8]
    
    # Auto-select model if not specified
    if model is None:
        codex_model = MODEL_MAP["default"]
    else:
        codex_model = MODEL_MAP.get(model, MODEL_MAP["default"])
    
    # Select Chrome port
    if chrome_port is None:
        chrome_port = CHROME_PORTS[0]
    
    # Create working directory for this agent
    if working_dir is None:
        working_dir = os.path.expanduser(f"~/.openclaw/agents/{agent_id}")
    os.makedirs(working_dir, exist_ok=True)
    
    # Register agent in state
    state_mgr.register_agent(
        agent_id=agent_id,
        task=f"{task_type}: {task_description[:50]}",
        target=program_name
    )
    
    # Build the system prompt
    system_prompt = build_agent_prompt(
        program_name=program_name,
        task_type=task_type,
        task_description=task_description,
        context=context,
        chrome_port=chrome_port,
        account_name=account_name
    )
    
    # Create MCP config for this agent
    mcp_config = {
        "mcpServers": {
            "chrome-devtools": {
                "command": "npx",
                "args": ["-y", "chrome-devtools-mcp@latest", "--browserUrl", f"http://127.0.0.1:{chrome_port}"]
            }
        }
    }
    
    # Write MCP config
    mcp_config_path = os.path.join(working_dir, "mcp_config.json")
    with open(mcp_config_path, 'w') as f:
        json.dump(mcp_config, f)
    
    # Write prompt to file
    prompt_path = os.path.join(working_dir, "task.md")
    with open(prompt_path, 'w') as f:
        f.write(system_prompt)
    
    # Build Codex exec command
    cmd = [
        "node", CODEX_CLI, "exec",
        f"--model={codex_model}",
        "--dangerously-bypass-approvals-and-sandbox",
        f"--cd={working_dir}",
        f"--output-last-message={os.path.join(working_dir, 'output.json')}",
        # Pass the task via stdin or file
    ]
    
    return {
        "agent_id": agent_id,
        "cmd": cmd,
        "prompt_path": prompt_path,
        "mcp_config": mcp_config_path,
        "mcp_config_raw": mcp_config,
        "chrome_port": chrome_port,
        "model": codex_model,
        "working_dir": working_dir
    }

def build_agent_prompt(program_name, task_type, task_description, context, chrome_port, account_name):
    """Build the task prompt for a Codex hunting agent."""
    
    context_section = format_context_for_agent(context, task_type)
    
    prompt = f"""# Bug Bounty Hunting Agent

You are a specialized bug bounty hunter testing **{program_name}** for **{task_type}** vulnerabilities.

## Your Task
{task_description}

## Chrome MCP Access
You have access to Chrome via the chrome-devtools-mcp server.
- Chrome debug port: {chrome_port}
- MCP config is in the current directory: mcp_config.json

## Available Tools
You can use shell commands to interact with Chrome:
```bash
# Check browser status
openclaw browser --browser-profile user status

# Navigate to a URL
openclaw browser --browser-profile user navigate "https://www.superdrug.com"

# Take a snapshot of the page
openclaw browser --browser-profile user snapshot

# Click an element
openclaw browser --browser-profile user click <ref>

# Type text
openclaw browser --browser-profile user type <ref> "text"

# Evaluate JavaScript
openclaw browser --browser-profile user evaluate --fn '() => document.title'
```

## Context
{context_section}

## Instructions
1. First, verify Chrome is accessible: `openclaw browser --browser-profile user status`
2. Use Chrome to navigate and test the target application
3. Focus on {task_type} vectors in the provided endpoints
4. Look for:
   - Reflected/stored XSS in parameters and forms
   - SSRF via URL parameters or image fetch
   - SQL injection in search/filter parameters
   - IDOR by manipulating object IDs
   - Auth bypass in login/token handling
   - Business logic flaws in checkout/promo codes

5. For each finding, confirm with a PoC (proof of concept)

6. When done, save your findings to findings.json in this format:
```json
{{
  "task": "{task_type}",
  "target": "{program_name}",
  "findings": [
    {{
      "type": "XSS",
      "severity": "P2",
      "url": "https://...",
      "parameter": "q",
      "poc": "...",
      "description": "..."
    }}
  ],
  "tested_urls": ["..."],
  "notes": "..."
}}
```

## Important
- Test only in-scope targets (www.superdrug.com, api.superdrug.com, *.superdrug.com)
- Do NOT DoS or excessively spam requests
- Be thorough but focused
- Document ALL attempts (not just successes)
- For SSRF testing, you can use: https://8z37t172avo5brod2ovrmxp0jvs2qezwu.oast.site

Begin hunting now. Work methodically and save your findings when complete.
"""
    return prompt

def spawn_parallel_agents(program_name, tasks, context):
    """Spawn multiple Codex hunting agents in parallel.
    
    Args:
        program_name: Target program
        tasks: List of dicts with task_type, task_description
        context: Recon context
    
    Returns:
        List of agent configs
    """
    agents = []
    for i, task in enumerate(tasks):
        chrome_port = CHROME_PORTS[i % len(CHROME_PORTS)]
        agent_config = spawn_codex_agent(
            program_name=program_name,
            task_type=task["task_type"],
            task_description=task["task_description"],
            context=context,
            chrome_port=chrome_port,
            account_name=task.get("account")
        )
        agents.append(agent_config)
    
    return agents

def run_agent(agent_config):
    """Execute a spawned agent and return its output."""
    import subprocess
    
    # First, configure MCP for this agent's session
    # Codex reads MCP config from config.toml project section
    
    # Write the task prompt
    with open(agent_config["prompt_path"], 'r') as f:
        prompt = f.read()
    
    # Run codex exec with the prompt
    cmd = agent_config["cmd"]
    
    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=600  # 10 minute timeout
        )
        
        return {
            "agent_id": agent_config["agent_id"],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            "agent_id": agent_config["agent_id"],
            "returncode": -1,
            "error": "Timeout after 10 minutes"
        }

def configure_mcp_for_agent(agent_config):
    """Configure Codex to use the Chrome MCP for this agent.
    
    Codex needs MCP servers configured in its config.toml.
    We'll create a project-specific config.
    """
    agent_dir = agent_config["working_dir"]
    chrome_port = agent_config["chrome_port"]
    
    # Create a minimal codex config for this project
    codex_config = f"""[projects."{agent_dir}"]
trust_level = "trusted"

[mcp_servers]
"""
    
    # Add MCP server config
    mcp_config = agent_config["mcp_config_raw"]
    for name, config in mcp_config.get("mcpServers", {}).items():
        codex_config += f"""
[mcp_servers.chrome-{chrome_port}]
command = "{config['command']}"
args = {json.dumps(config['args'])}
"""
    
    config_path = os.path.join(agent_dir, "codex_config.toml")
    with open(config_path, 'w') as f:
        f.write(codex_config)
    
    return config_path
