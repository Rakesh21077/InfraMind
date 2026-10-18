"""
InfraMind - Automated Unit Tests for CLI Runner (scripts/test_findings.py)

Tests cover:
- Normal synthetic batch execution
- Single verified S3 public finding execution
- Empty findings execution
- Critical incomplete evidence handling
- Prompt injection finding resilience
- Deliberately malformed JSON rejection and nonzero exit code
- Missing file rejection and nonzero exit code
- Verification that remediation is NEVER executed during CLI reporting
"""

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from inframind.remediation_bridge import RemediationBridge
import scripts.test_findings as test_findings_cli

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI_SCRIPT = os.path.join(REPO_ROOT, "scripts", "test_findings.py")
FIXTURES_DIR = os.path.join(REPO_ROOT, "tests", "fixtures")


class TestCLIRunner(unittest.TestCase):
    """Test CLI execution and reporting against synthetic fixtures."""

    def run_cli_process(self, *args):
        """Helper to run the CLI in a subprocess with the current Python executable."""
        cmd = [sys.executable, CLI_SCRIPT] + list(args)
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO_ROOT,
        )
        return proc

    def test_cli_normal_synthetic_batch(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_normal.json")
        proc = self.run_cli_process(fixture_path)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("Total Findings Processed: 5", proc.stdout)
        self.assertIn("PRIORITY: [CRITICAL]", proc.stdout)
        self.assertIn("fix_s3_bucket", proc.stdout)
        self.assertIn("Zero AWS API calls made", proc.stdout)

    def test_cli_single_s3_public(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_s3_public.json")
        proc = self.run_cli_process(fixture_path)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("Total Findings Processed: 1", proc.stdout)
        self.assertIn("PRIORITY: [CRITICAL] (Score: 100.0/100)", proc.stdout)
        self.assertIn("RESTRICT_S3_PUBLIC_ACCESS", proc.stdout)
        self.assertIn("READY_FOR_APPROVAL", proc.stdout)
        self.assertIn("Approval Required: True", proc.stdout)
        self.assertIn("Executable:        True", proc.stdout)

    def test_cli_empty_findings(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_empty.json")
        proc = self.run_cli_process(fixture_path)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("No findings to process (empty findings payload)", proc.stdout)
        self.assertIn("Total Findings: 0", proc.stdout)

    def test_cli_incomplete_findings(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_incomplete.json")
        proc = self.run_cli_process(fixture_path)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        self.assertIn("PRIORITY: [CRITICAL]", proc.stdout)
        self.assertIn("Evidence Gaps (Unknowns):", proc.stdout)
        self.assertIn("MANUAL_INVESTIGATION_REQUIRED", proc.stdout)
        self.assertIn("Status:            BLOCKED", proc.stdout)

    def test_cli_prompt_injection(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_prompt_injection.json")
        proc = self.run_cli_process(fixture_path)
        self.assertEqual(proc.returncode, 0, f"CLI stderr: {proc.stderr}")
        # Verify prompt injection fails to lower score to INFORMATIONAL
        self.assertIn("PRIORITY: [HIGH]", proc.stdout)
        self.assertNotIn("PRIORITY: [INFORMATIONAL]", proc.stdout)

    def test_cli_malformed_json_exits_nonzero(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_malformed.json")
        proc = self.run_cli_process(fixture_path)
        self.assertNotEqual(proc.returncode, 0)
        combined_err = proc.stdout + proc.stderr
        self.assertIn("Malformed JSON", combined_err)

    def test_cli_missing_file_exits_nonzero(self):
        fixture_path = os.path.join(FIXTURES_DIR, "non_existent_file.json")
        proc = self.run_cli_process(fixture_path)
        self.assertNotEqual(proc.returncode, 0)
        combined_err = proc.stdout + proc.stderr
        self.assertIn("does not exist", combined_err)

    def test_cli_no_remediation_execution_during_report_generation(self):
        fixture_path = os.path.join(FIXTURES_DIR, "findings_s3_public.json")
        with patch.object(RemediationBridge, "execute") as mock_exec:
            with patch.object(sys, "argv", ["scripts/test_findings.py", fixture_path]):
                with self.assertRaises(SystemExit) as exit_ctx:
                    test_findings_cli.main()
                self.assertEqual(exit_ctx.exception.code, 0)
            mock_exec.assert_not_called()


if __name__ == "__main__":
    unittest.main()

