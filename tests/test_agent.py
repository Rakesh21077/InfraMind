"""
InfraMind - AI Threat Detection & Analysis Engine Test Suite
Tests for agent.py and mock_logs.json

Verifies:
1. Structured log analysis (S3, IAM, generic).
2. Deterministic rule-based fallback behavior when LLM is unavailable.
3. LLM API integration with mocked OpenAI-compatible endpoint.
4. Resilience to malformed JSON, invalid inputs, and out-of-range risk scores.
5. Natural language Incident Time-Machine query engine.
6. Schema validation of mock_logs.json.

All tests run completely offline with no network or credentials required.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from agent import (
    _deterministic_analysis,
    _validate_and_sanitize_analysis,
    analyze_security_log,
    ask_incident_history,
    get_llm_config,
)


class TestAgentAnalysis(unittest.TestCase):
    """Test security log event analysis, classification, and score bounding."""

    def setUp(self):
        self.sample_s3_log = {
            "event_id": "evt-101",
            "event_source": "s3.amazonaws.com",
            "event_name": "PutBucketAcl",
            "resource_id": "inframind-customer-data-backup",
            "resource_type": "AWS::S3::Bucket",
            "details": "Public-read and public-write ACL granted to AllUsers group.",
            "timestamp": "2026-10-18T10:15:30Z",
        }

        self.sample_iam_log = {
            "event_id": "evt-102",
            "event_source": "iam.amazonaws.com",
            "event_name": "CreateAccessKey",
            "resource_id": "AKIAIOSFODNN7EXAMPLE",
            "resource_type": "AWS::IAM::AccessKey",
            "user_name": "demo-compromised-user",
            "details": "Active IAM access key leaked on public GitHub repository.",
            "timestamp": "2026-10-18T11:02:14Z",
        }

    def test_s3_event_classification_deterministic(self):
        """Verify S3 public exposure is classified as CRITICAL with fix_s3_bucket action."""
        result = _deterministic_analysis(self.sample_s3_log)
        self.assertEqual(result["event_id"], "evt-101")
        self.assertEqual(result["priority"], "CRITICAL")
        self.assertGreaterEqual(result["threat_score"], 8)
        self.assertEqual(result["remediation_action"], "fix_s3_bucket")
        self.assertEqual(result["resource_id"], "inframind-customer-data-backup")
        self.assertIn("Public S3 Bucket", result["vulnerability_type"])
        self.assertIn("Offline Fallback", result["engine"])

    def test_iam_event_classification_deterministic(self):
        """Verify compromised IAM key is classified as CRITICAL with revoke_iam_key action."""
        result = _deterministic_analysis(self.sample_iam_log)
        self.assertEqual(result["event_id"], "evt-102")
        self.assertEqual(result["priority"], "CRITICAL")
        self.assertEqual(result["threat_score"], 10)
        self.assertEqual(result["remediation_action"], "revoke_iam_key")
        self.assertEqual(result["resource_id"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(result["user_name"], "demo-compromised-user")
        self.assertIn("Compromised IAM", result["vulnerability_type"])

    def test_unknown_event_type(self):
        """Verify generic cloud event gracefully maps to MEDIUM priority and 'none' action."""
        generic_log = {
            "event_id": "evt-999",
            "event_source": "ec2.amazonaws.com",
            "event_name": "DescribeInstances",
            "resource_id": "i-1234567890abcdef0",
            "resource_type": "AWS::EC2::Instance",
            "details": "Routine describe instances call.",
        }
        result = _deterministic_analysis(generic_log)
        self.assertEqual(result["priority"], "MEDIUM")
        self.assertEqual(result["remediation_action"], "none")
        self.assertEqual(result["threat_score"], 5)

    def test_invalid_event_input(self):
        """Verify empty or non-dict input does not raise an exception."""
        for invalid_input in [None, {}, "not-a-dict", 12345, []]:
            with self.subTest(invalid_input=invalid_input):
                result = analyze_security_log(invalid_input)  # type: ignore
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(result["remediation_action"], "none")

    def test_score_normalization_and_bounding(self):
        """Verify threat scores and blast radius are bounded within [0, 10]."""
        raw_overscored = {
            "priority": "SUPER_CRITICAL",
            "threat_score": 999,
            "blast_radius_score": -50,
            "remediation_action": "delete_account_now",
            "summary": "Bad things happened",
        }
        sanitized = _validate_and_sanitize_analysis(raw_overscored, self.sample_s3_log)
        self.assertEqual(sanitized["threat_score"], 10)
        self.assertEqual(sanitized["blast_radius_score"], 0)
        self.assertEqual(sanitized["priority"], "HIGH")  # Invalid priority coerced
        self.assertEqual(sanitized["remediation_action"], "fix_s3_bucket")  # Whitelisted fallback

    @patch("openai.OpenAI")
    def test_llm_happy_path(self, mock_openai_cls):
        """Verify successful LLM response is parsed and validated."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        mock_completion = MagicMock()
        mock_message = MagicMock()
        mock_message.content = json.dumps({
            "event_id": "evt-101",
            "priority": "CRITICAL",
            "threat_score": 9,
            "vulnerability_type": "Public S3 Bucket Exposure",
            "summary": "AI verified public bucket risk.",
            "blast_radius_score": 8,
            "remediation_action": "fix_s3_bucket",
            "resource_id": "inframind-customer-data-backup",
            "recommended_action": "Enable public access block.",
        })
        mock_completion.choices = [MagicMock(message=mock_message)]
        mock_client.chat.completions.create.return_value = mock_completion

        result = analyze_security_log(self.sample_s3_log)
        self.assertEqual(result["status"], "ANALYZED")
        self.assertEqual(result["priority"], "CRITICAL")
        self.assertIn("AMD ROCm vLLM", result["engine"])
        self.assertEqual(result["remediation_action"], "fix_s3_bucket")

    def test_fallback_when_llm_fails(self):
        """Verify analyze_security_log falls back to deterministic analysis on connection error."""
        with patch("openai.OpenAI", side_effect=RuntimeError("Endpoint offline")):
            result = analyze_security_log(self.sample_s3_log)
            self.assertEqual(result["status"], "ANALYZED")
            self.assertEqual(result["priority"], "CRITICAL")
            self.assertEqual(result["remediation_action"], "fix_s3_bucket")
            self.assertIn("Offline Fallback", result["engine"])


class TestIncidentTimeMachine(unittest.TestCase):
    """Test natural language incident queries and deterministic solver."""

    def setUp(self):
        self.logs = [
            {
                "event_id": "evt-101",
                "event_source": "s3.amazonaws.com",
                "event_name": "PutBucketAcl",
                "resource_id": "inframind-customer-data-backup",
                "resource_type": "AWS::S3::Bucket",
                "details": "Public-read ACL enabled.",
                "timestamp": "2026-10-18T10:15:30Z",
                "remediation_status": "OPEN",
            },
            {
                "event_id": "evt-102",
                "event_source": "iam.amazonaws.com",
                "event_name": "CreateAccessKey",
                "resource_id": "AKIAIOSFODNN7EXAMPLE",
                "user_name": "demo-compromised-user",
                "details": "Access key leaked publicly.",
                "timestamp": "2026-10-18T11:02:14Z",
                "remediation_status": "RESOLVED",
            },
        ]
        self.analyses = {
            "evt-101": {
                "event_id": "evt-101",
                "priority": "CRITICAL",
                "threat_score": 9,
                "vulnerability_type": "Public S3 Bucket Exposure",
                "summary": "Customer backup bucket exposed.",
                "blast_radius_score": 8,
                "remediation_action": "fix_s3_bucket",
                "recommended_action": "Apply Public Access Block.",
                "resource_id": "inframind-customer-data-backup",
            },
            "evt-102": {
                "event_id": "evt-102",
                "priority": "CRITICAL",
                "threat_score": 10,
                "vulnerability_type": "Compromised IAM Access Key",
                "summary": "IAM key leaked.",
                "blast_radius_score": 9,
                "remediation_action": "revoke_iam_key",
                "recommended_action": "Deactivate IAM key.",
                "resource_id": "AKIAIOSFODNN7EXAMPLE",
                "user_name": "demo-compromised-user",
            },
        }

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_flagged_api_keys(self, _mock_llm):
        """Querying for API keys lists AKIAIOSFODNN7EXAMPLE."""
        ans = ask_incident_history("What API keys were flagged?", self.logs, self.analyses)
        self.assertIn("AKIAIOSFODNN7EXAMPLE", ans)
        self.assertIn("demo-compromised-user", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_critical_incidents(self, _mock_llm):
        """Querying for critical incidents returns both evt-101 and evt-102."""
        ans = ask_incident_history("Which incidents are critical?", self.logs, self.analyses)
        self.assertIn("evt-101", ans)
        self.assertIn("evt-102", ans)
        self.assertIn("CRITICAL", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_s3_bucket(self, _mock_llm):
        """Querying for S3 buckets details inframind-customer-data-backup."""
        ans = ask_incident_history("What happened to the S3 bucket?", self.logs, self.analyses)
        self.assertIn("inframind-customer-data-backup", ans)
        self.assertIn("fix_s3_bucket", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_specific_event(self, _mock_llm):
        """Querying specifically for evt-101 returns detailed report."""
        ans = ask_incident_history("Tell me about evt-101", self.logs, self.analyses)
        self.assertIn("evt-101", ans)
        self.assertIn("inframind-customer-data-backup", ans)
        self.assertIn("Public S3 Bucket Exposure", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_unresolved_incidents(self, _mock_llm):
        """Querying for unresolved incidents shows evt-101 (OPEN) and excludes evt-102 (RESOLVED)."""
        ans = ask_incident_history("Which incidents are still unresolved?", self.logs, self.analyses)
        self.assertIn("evt-101", ans)
        self.assertNotIn("evt-102", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_unknown_event(self, _mock_llm):
        """Querying for a non-existent incident politely informs the operator."""
        ans = ask_incident_history("What happened in evt-999?", self.logs, self.analyses)
        self.assertIn("No incident record matching `evt-999`", ans)

    @patch("openai.OpenAI", side_effect=RuntimeError("Offline mode"))
    def test_query_empty_input(self, _mock_llm):
        """Querying with empty text prompts user to provide an inquiry."""
        ans = ask_incident_history("", self.logs, self.analyses)
        self.assertIn("Please ask a question", ans)

    @patch("openai.OpenAI")
    def test_llm_chat_happy_path(self, mock_openai_cls):
        """Verify ask_incident_history returns LLM response when client succeeds."""
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client

        mock_completion = MagicMock()
        mock_message = MagicMock()
        mock_message.content = "AI Assistant: Both S3 bucket and IAM key are critical."
        mock_completion.choices = [MagicMock(message=mock_message)]
        mock_client.chat.completions.create.return_value = mock_completion

        ans = ask_incident_history("Summarize the risk", self.logs, self.analyses)
        self.assertIn("AI Assistant", ans)


class TestMockLogsData(unittest.TestCase):
    """Verify mock_logs.json file validity and required integration properties."""

    def test_mock_logs_json_valid_and_non_empty(self):
        """Verify mock_logs.json is valid JSON and contains at least 2 realistic incidents."""
        path = os.path.join(os.path.dirname(__file__), "..", "mock_logs.json")
        self.assertTrue(os.path.exists(path), f"File {path} does not exist")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 2)

        # Verify S3 incident
        s3_inc = next((i for i in data if "s3" in i.get("event_source", "")), None)
        self.assertIsNotNone(s3_inc, "Missing S3 incident in mock_logs.json")
        self.assertIn("resource_id", s3_inc)
        self.assertIn("details", s3_inc)

        # Verify IAM incident
        iam_inc = next((i for i in data if "iam" in i.get("event_source", "")), None)
        self.assertIsNotNone(iam_inc, "Missing IAM incident in mock_logs.json")
        self.assertIn("resource_id", iam_inc)
        self.assertTrue(
            iam_inc.get("user_name") or iam_inc.get("user_identity", {}).get("user_name"),
            "IAM incident must contain a valid username for live remediation integration",
        )


if __name__ == "__main__":
    unittest.main()
