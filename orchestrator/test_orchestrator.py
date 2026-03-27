#!/usr/bin/env python3
"""
Orchestrator Tests — Verify the Ghost orchestrator works correctly.

Run with: python -m pytest test_orchestrator.py -v
"""

import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project to path
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")
sys.path.insert(0, "/home/ryushe/projects/bounty-tools/orchestrator")


class TestStateManager(unittest.TestCase):
    """Test thread-safe state management."""

    @classmethod
    def setUpClass(cls):
        """Create temp state file for testing."""
        cls.temp_dir = tempfile.mkdtemp()
        cls.state_file = os.path.join(cls.temp_dir, "test_state.json")

    def setUp(self):
        """Re-import with temp state file."""
        # Patch config before import
        with patch('orchestrator.config.STATE_FILE', self.state_file):
            from orchestrator import state_manager
            # Reload to pick up patched config
            import importlib
            importlib.reload(state_manager)
            self.state_mgr = state_manager.StateManager(self.state_file)

    def test_add_target(self):
        """Test adding a target program."""
        self.state_mgr.add_target("testprogram", ["*.test.com"], ["test@test.com"])
        target = self.state_mgr.get_target("testprogram")
        self.assertIsNotNone(target)
        self.assertEqual(target["name"], "testprogram")
        self.assertIn("*.test.com", target["scope"])

    def test_add_finding(self):
        """Test adding a finding with deduplication."""
        finding = {
            "target": "test.com",
            "vuln_type": "xss",
            "endpoint": "/search?q=test",
            "severity": "Medium - P3",
            "poc": "alert(1)",
        }
        self.state_mgr.add_finding(finding)
        findings = self.state_mgr.get_findings(vuln_type="xss")
        self.assertEqual(len(findings), 1)

    def test_deduplication(self):
        """Test that duplicate findings are not added."""
        finding = {
            "target": "test.com",
            "vuln_type": "xss",
            "endpoint": "/search?q=test",
            "severity": "Medium - P3",
            "poc": "alert(1)",
        }
        self.state_mgr.add_finding(finding)
        self.state_mgr.add_finding(finding)  # Duplicate
        findings = self.state_mgr.get_findings(vuln_type="xss")
        self.assertEqual(len(findings), 1)

    def test_agent_registration(self):
        """Test agent registration and unregistration."""
        self.state_mgr.register_agent("agent-123", "xss test", "testprogram")
        agents = self.state_mgr.get_active_agents()
        self.assertEqual(len(agents), 1)
        self.assertEqual(agents[0]["agent_id"], "agent-123")

        self.state_mgr.unregister_agent("agent-123")
        agents = self.state_mgr.get_active_agents()
        self.assertEqual(len(agents), 0)

    @classmethod
    def tearDownClass(cls):
        """Clean up temp files."""
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)


class TestFindingsStore(unittest.TestCase):
    """Test findings storage."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.findings_dir = os.path.join(cls.temp_dir, "findings")

    def setUp(self):
        with patch('orchestrator.findings_store.FINDINGS_DIR', self.findings_dir):
            import importlib
            from orchestrator import findings_store
            importlib.reload(findings_store)
            self.fs = findings_store

    def test_create_finding(self):
        """Test creating a structured finding."""
        finding = self.fs.create_finding(
            target="test.com",
            vuln_type="xss",
            endpoint="/search",
            severity="High - P2",
            poc="alert(1)",
            description="Reflected XSS in search param"
        )
        self.assertEqual(finding["target"], "test.com")
        self.assertEqual(finding["vuln_type"], "xss")
        self.assertIn("created_at", finding)

    def test_save_and_load_finding(self):
        """Test saving and loading a finding."""
        finding = self.fs.create_finding(
            target="test.com",
            vuln_type="xss",
            endpoint="/search",
            severity="High - P2",
            poc="alert(1)"
        )
        filepath = self.fs.save_finding(finding)
        loaded = self.fs.load_finding(filepath)
        self.assertEqual(loaded["vuln_type"], "xss")

    @classmethod
    def tearDownClass(cls):
        import shutil
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir)


class TestContextPrep(unittest.TestCase):
    """Test context preparation."""

    def test_categorize_urls(self):
        """Test URL categorization."""
        from orchestrator.context_prep import categorize_urls
        urls = [
            "https://api.test.com/users",
            "https://test.com/login",
            "https://test.com/admin/dashboard",
            "https://test.com/search?q=test",
            "https://test.com/static/app.js",
        ]
        categorized = categorize_urls(urls)
        self.assertEqual(len(categorized["api"]), 1)
        self.assertEqual(len(categorized["auth"]), 1)
        self.assertEqual(len(categorized["admin"]), 1)
        self.assertEqual(len(categorized["search"]), 1)
        self.assertEqual(len(categorized["static"]), 1)

    def test_prep_test_context(self):
        """Test minimal context for testing."""
        from orchestrator.context_prep import prep_test_context
        context = prep_test_context("testprogram", ["https://test.com/api"])
        self.assertEqual(context["program"], "testprogram")
        self.assertIn("https://test.com/api", context["endpoints"])


class TestSpawn(unittest.TestCase):
    """Test agent spawning."""

    def test_agent_runtime_enum(self):
        """Test AgentRuntime enum."""
        from orchestrator.spawn import AgentRuntime
        self.assertEqual(AgentRuntime.CLAUDE.value, "claude")
        self.assertEqual(AgentRuntime.CODEX.value, "codex")

    @patch('orchestrator.spawn.state_mgr')
    @patch('orchestrator.spawn.format_context_for_agent')
    def test_spawn_agent_config(self, mock_format, mock_state):
        """Test agent config generation."""
        mock_format.return_value = "# Test Context"
        
        from orchestrator.spawn import spawn_agent, AgentRuntime
        context = {"program": "test", "endpoints": []}
        
        config = spawn_agent(
            program_name="testprogram",
            task_type="xss",
            task_description="Test XSS",
            context=context,
            runtime=AgentRuntime.CLAUDE,
        )
        
        self.assertIn("agent_id", config)
        self.assertIn("cmd", config)
        self.assertIn("chrome_port", config)
        self.assertEqual(config["runtime"], "claude")


class TestHunt(unittest.TestCase):
    """Test hunt workflow."""

    @patch('orchestrator.hunt.run_agent')
    @patch('orchestrator.hunt.prep_recon_context')
    @patch('orchestrator.hunt.load_credentials')
    def test_hunt_workflow(self, mock_creds, mock_context, mock_run):
        """Test basic hunt workflow."""
        mock_context.return_value = {"program": "test", "scope": []}
        mock_creds.return_value = (None, None)
        mock_run.return_value = {
            "agent_id": "test-123",
            "returncode": 0,
            "stdout": "",
            "duration_ms": 5000,
        }

        from orchestrator.hunt import hunt
        from orchestrator.spawn import AgentRuntime
        
        with patch('orchestrator.hunt.get_logger', return_value=None):
            result = hunt("testprogram", tasks=["recon"], runtime=AgentRuntime.CLAUDE)
        
        self.assertIn("agents", result)
        self.assertIn("findings_saved", result)
        self.assertEqual(len(result["agents"]), 1)


class TestIntegration(unittest.TestCase):
    """Integration tests for full workflow."""

    def test_import_hunt_from_module(self):
        """Test importing hunt from orchestrator module."""
        from orchestrator import hunt
        self.assertTrue(callable(hunt))

    def test_import_agent_runtime(self):
        """Test importing AgentRuntime."""
        from orchestrator import AgentRuntime
        self.assertEqual(AgentRuntime.CLAUDE.value, "claude")

    def test_import_state_manager(self):
        """Test importing state manager."""
        from orchestrator import state_mgr
        self.assertIsNotNone(state_mgr)


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
