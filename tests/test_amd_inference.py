"""
InfraMind - Automated Unit Tests for AMD ROCm Inference & Service Hardening (Phase 7)

Comprehensive mocked tests covering:
1. AMD provider successful OpenAI-compatible response.
2. AMD HTTP error handling.
3. Connection failure and timeout resilience.
4. Missing required credentials gate.
5. Malformed JSON and missing/empty choices/content.
6. Invalid model response schema validation.
7. Provider factory selection for 'amd_vllm'.
8. Accurate fallback status (never masquerading as successful AMD inference).
9. Inappropriate model-proposed actions cannot override deterministic policy.
10. Missing or mismatched target resource information blocks remediation preview.
11. Provider exceptions isolated per-finding without crashing batches or altering scores.
12. Triage and preview generation strictly read-only (zero remediation execution).
"""

from __future__ import annotations
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import httpx

from inframind.inference import (
    AMDvLLMProvider,
    BaseInferenceProvider,
    MockInferenceProvider,
    StructuredLLMResponse,
    get_inference_provider,
    normalize_vllm_endpoint,
)
from inframind.ingestion import ASFFParser, ingest_findings
from inframind.models import (
    DeterministicAssessment,
    LLMExplanation,
    NormalizedFinding,
    PredefinedAction,
    PriorityTier,
    RemediationRecommendation,
    FindingResource,
)
from inframind.prioritization import assess_finding
from inframind.remediation_bridge import RemediationBridge
from inframind.service import ThreatTriageService, triage_findings
import remediation
from tests.synthetic_fixtures import (
    CRITICAL_INCOMPLETE_EVIDENCE,
    MEDIUM_CONFIG_ISSUE,
    SYNTHETIC_BATCH,
    VERIFIED_HIGH_IMPACT_S3,
)


def _make_mock_response(status_code: int = 200, json_data: dict = None, text: str = "") -> MagicMock:
    """Helper to construct a mock httpx.Response."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = status_code
    if json_data is not None:
        mock_resp.json.return_value = json_data
        mock_resp.text = json.dumps(json_data)
    else:
        mock_resp.text = text
        mock_resp.json.side_effect = json.JSONDecodeError("Invalid JSON", text, 0)
    return mock_resp


class TestAMDInferenceAndServiceHardening(unittest.TestCase):
    """Mocked unit tests for AMD inference, service safety, and preview boundaries."""

    def setUp(self):
        self.finding = ASFFParser().parse_single_finding(VERIFIED_HIGH_IMPACT_S3)
        self.assessment = assess_finding(self.finding)

    # -------------------------------------------------------------------------
    # 1. AMD provider successful OpenAI-compatible response
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_01_amd_provider_successful_openai_response(self, mock_post):
        """Test successful OpenAI-compatible chat completion response on AMD endpoint."""
        model_payload = {
            "priority_justification": "Public S3 bucket financial records exposes confidential audits.",
            "business_impact_summary": "High risk of unauthorized data exfiltration.",
            "missing_evidence_notes": [],
            "recommended_investigation_steps": ["Inspect S3 bucket ACLs", "Review CloudTrail logs"],
            "recommended_action_id": "RESTRICT_S3_PUBLIC_ACCESS",
            "action_rationale": "Enforce S3 public access block immediately.",
        }
        api_response = {
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(model_payload),
                    },
                    "finish_reason": "stop",
                }
            ]
        }
        mock_post.return_value = _make_mock_response(200, json_data=api_response)

        provider = AMDvLLMProvider(
            endpoint_url="http://amd-cloud.local:8000/v1",
            model_name="meta-llama/Meta-Llama-3-8B-Instruct",
            api_key="mock-amd-api-key",
            timeout=10.0,
        )
        explanation = provider.explain(self.finding, self.assessment)

        self.assertTrue(explanation.is_llm_available)
        self.assertEqual(explanation.provider, "amd_vllm")
        self.assertEqual(explanation.model_name, "meta-llama/Meta-Llama-3-8B-Instruct")
        self.assertIsNone(explanation.error_message)
        self.assertIn("financial records", explanation.priority_justification)
        self.assertIsNotNone(explanation.recommended_action)
        self.assertEqual(
            explanation.recommended_action.action_id,
            PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value,
        )
        self.assertEqual(
            explanation.recommended_action.parameters.get("bucket_name"),
            "financial-audit-records-2026",
        )

    # -------------------------------------------------------------------------
    # 2. AMD HTTP error
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_02_amd_http_error(self, mock_post):
        """Test graceful fallback when AMD vLLM server returns an HTTP 500 error."""
        mock_post.return_value = _make_mock_response(
            500, text="Internal Server Error: ROCm kernel out of memory"
        )

        provider = AMDvLLMProvider(
            endpoint_url="http://amd-cloud.local:8000/v1",
            model_name="meta-llama/Meta-Llama-3-8B-Instruct",
        )
        explanation = provider.explain(self.finding, self.assessment)

        self.assertFalse(explanation.is_llm_available)
        self.assertEqual(explanation.provider, "amd_vllm_fallback")
        self.assertIn("500", explanation.error_message)
        self.assertIn("deterministic", explanation.priority_justification.lower())
        self.assertEqual(
            explanation.recommended_action.action_id,
            PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value,
        )

    # -------------------------------------------------------------------------
    # 3. Connection failure and timeout
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_03_connection_failure_and_timeout(self, mock_post):
        """Test resilience against network connection errors and timeouts."""
        provider = AMDvLLMProvider(endpoint_url="http://amd-cloud.local:8000/v1")

        # Subcase A: Connection Error
        mock_post.side_effect = httpx.ConnectError("Connection refused by host")
        exp_conn = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_conn.is_llm_available)
        self.assertEqual(exp_conn.provider, "amd_vllm_fallback")
        self.assertIn("unavailable", exp_conn.error_message.lower())

        # Subcase B: Timeout Exception
        mock_post.side_effect = httpx.TimeoutException("Read operation timed out after 30s")
        exp_time = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_time.is_llm_available)
        self.assertEqual(exp_time.provider, "amd_vllm_fallback")
        self.assertIn("timed out", exp_time.error_message.lower())

    # -------------------------------------------------------------------------
    # 4. Missing required credentials
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_04_missing_required_credentials(self, mock_post):
        """Test that missing API keys fail safely before any network requests when auth is required."""
        provider = AMDvLLMProvider(
            endpoint_url="http://amd-cloud.local:8000/v1",
            api_key="",
            require_auth=True,
        )
        explanation = provider.explain(self.finding, self.assessment)

        # Must fail immediately without making HTTP calls
        mock_post.assert_not_called()
        self.assertFalse(explanation.is_llm_available)
        self.assertEqual(explanation.provider, "amd_vllm_fallback")
        self.assertIn("authentication required", explanation.error_message.lower())
        self.assertIn("deterministic", explanation.priority_justification.lower())

    # -------------------------------------------------------------------------
    # 5. Malformed JSON and missing/empty choices or message.content
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_05_malformed_json_and_missing_choices_or_content(self, mock_post):
        """Test defensive parsing of malformed HTTP payloads, empty choices, and missing content."""
        provider = AMDvLLMProvider(endpoint_url="http://amd-cloud.local:8000/v1")

        # Subcase A: Non-JSON raw HTTP response (e.g. HTML 502 Bad Gateway)
        mock_post.return_value = _make_mock_response(200, text="<html>502 Bad Gateway</html>")
        exp_a = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_a.is_llm_available)
        self.assertEqual(exp_a.provider, "amd_vllm_fallback")
        self.assertIn("invalid http json", exp_a.error_message.lower())

        # Subcase B: Empty choices list
        mock_post.return_value = _make_mock_response(200, json_data={"choices": []})
        exp_b = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_b.is_llm_available)
        self.assertIn("no choices", exp_b.error_message.lower())

        # Subcase C: Choice missing message object
        mock_post.return_value = _make_mock_response(200, json_data={"choices": [{"index": 0}]})
        exp_c = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_c.is_llm_available)
        self.assertIn("missing message", exp_c.error_message.lower())

        # Subcase D: Message content is empty or whitespace
        mock_post.return_value = _make_mock_response(
            200, json_data={"choices": [{"message": {"content": "   "}}]}
        )
        exp_d = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_d.is_llm_available)
        self.assertIn("empty or missing", exp_d.error_message.lower())

        # Subcase E: Content is not valid JSON
        mock_post.return_value = _make_mock_response(
            200, json_data={"choices": [{"message": {"content": "Sorry, I cannot answer this request."}}]}
        )
        exp_e = provider.explain(self.finding, self.assessment)
        self.assertFalse(exp_e.is_llm_available)
        self.assertIn("schema validation", exp_e.error_message.lower())

    # -------------------------------------------------------------------------
    # 6. Invalid model response schema
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_06_invalid_model_response_schema(self, mock_post):
        """Test Pydantic schema rejection when model output lacks required fields."""
        # Valid JSON syntax, but missing required 'business_impact_summary' and 'priority_justification'
        incomplete_json = json.dumps({"unknown_field": "test", "notes": []})
        mock_post.return_value = _make_mock_response(
            200, json_data={"choices": [{"message": {"content": incomplete_json}}]}
        )

        provider = AMDvLLMProvider(endpoint_url="http://amd-cloud.local:8000/v1")
        explanation = provider.explain(self.finding, self.assessment)

        self.assertFalse(explanation.is_llm_available)
        self.assertEqual(explanation.provider, "amd_vllm_fallback")
        self.assertIn("schema validation", explanation.error_message.lower())
        self.assertIsNotNone(explanation.recommended_action)

    # -------------------------------------------------------------------------
    # 7. Provider factory selection for amd_vllm
    # -------------------------------------------------------------------------
    def test_07_provider_factory_selection_for_amd_vllm(self):
        """Test get_inference_provider correctly selects AMDvLLMProvider when configured."""
        for provider_key in ("amd", "amd_vllm", "vllm", "openai"):
            with patch.dict(os.environ, {"INFERENCE_PROVIDER": provider_key}):
                provider = get_inference_provider()
                self.assertIsInstance(provider, AMDvLLMProvider)

    # -------------------------------------------------------------------------
    # 8. Fallback status accurately indicates that AMD inference was unavailable
    # -------------------------------------------------------------------------
    @patch("httpx.Client.post")
    def test_08_fallback_status_accurately_indicates_unavailable(self, mock_post):
        """Ensure fallback never masquerades as successful AMD inference."""
        mock_post.return_value = _make_mock_response(503, text="Service Unavailable")

        provider = AMDvLLMProvider(
            endpoint_url="http://amd-cloud.local:8000/v1",
            api_key="super-secret-key-12345",
        )
        explanation = provider.explain(self.finding, self.assessment)

        self.assertFalse(explanation.is_llm_available)
        self.assertEqual(explanation.provider, "amd_vllm_fallback")
        self.assertNotEqual(explanation.provider, "amd_vllm")
        # Ensure API key is NEVER leaked in error messages or logs
        self.assertNotIn("super-secret-key-12345", explanation.error_message)
        self.assertNotIn("super-secret-key-12345", explanation.priority_justification)

    # -------------------------------------------------------------------------
    # 9. Model-proposed valid-but-inappropriate action cannot override deterministic action
    # -------------------------------------------------------------------------
    def test_09_model_proposed_action_cannot_override_deterministic_action(self):
        """Ensure model-suggested action cannot override deterministic engine policy."""
        # Mock provider that attempts to suggest REVOKE_IAM_KEY for an S3 finding
        class SneakyModelProvider(BaseInferenceProvider):
            def explain(self, finding, assessment):
                rec = RemediationRecommendation(
                    action_id=PredefinedAction.REVOKE_IAM_KEY.value,  # Inappropriate for S3!
                    target_resource_id=finding.resources[0].id,
                    target_resource_type=finding.resources[0].type,
                    parameters={"access_key_id": "AKIA1111222233334444"},
                    rationale="Model hallucinated IAM key revocation for an S3 finding.",
                )
                return LLMExplanation(
                    priority_justification="Advisory justification",
                    business_impact_summary="High business impact",
                    missing_evidence_notes=[],
                    recommended_investigation_steps=[],
                    recommended_action=rec,
                    is_llm_available=True,
                    provider="sneaky_mock",
                )

        service = ThreatTriageService(provider=SneakyModelProvider())
        batch_result = service.triage(VERIFIED_HIGH_IMPACT_S3)

        self.assertEqual(batch_result.total_findings, 1)
        item = batch_result.findings[0]

        # Engine suggested action for S3 was RESTRICT_S3_PUBLIC_ACCESS
        self.assertEqual(item.assessment.suggested_action_id, PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value)
        # Service must enforce authoritative action
        self.assertEqual(item.explanation.recommended_action.action_id, PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value)
        # Remediation preview must be for fix_s3_bucket, NOT revoke_iam_key
        self.assertEqual(item.remediation_preview["action"], "fix_s3_bucket")

    # -------------------------------------------------------------------------
    # 10. Missing or mismatched target resource information blocks remediation preview
    # -------------------------------------------------------------------------
    def test_10_missing_or_mismatched_target_resource_blocks_preview(self):
        """Verify preview is blocked if target resource identifier or type is missing or mismatched."""
        # Subcase A: Missing resource ID
        rec_missing_id = RemediationRecommendation(
            action_id=PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value,
            target_resource_id="",
            target_resource_type="AwsS3Bucket",
            parameters={"bucket_name": "valid-bucket"},
            rationale="Test",
        )
        preview_a = RemediationBridge.preview(rec_missing_id)
        self.assertEqual(preview_a["status"], remediation.STATUS_BLOCKED)
        self.assertFalse(preview_a["executable"])

        # Subcase B: Resource type mismatched (fix_s3_bucket targeting an IAM User)
        rec_mismatched = RemediationRecommendation(
            action_id=PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value,
            target_resource_id="arn:aws:iam::111122223333:user/testuser",
            target_resource_type="AwsIamUser",
            parameters={"bucket_name": "testuser"},
            rationale="Test",
        )
        preview_b = RemediationBridge.preview(rec_mismatched)
        self.assertEqual(preview_b["status"], remediation.STATUS_BLOCKED)
        self.assertFalse(preview_b["executable"])

    # -------------------------------------------------------------------------
    # 11. Provider exception does not crash the whole batch or alter deterministic scores
    # -------------------------------------------------------------------------
    def test_11_provider_exception_does_not_crash_batch_or_alter_scores(self):
        """Verify unhandled provider exceptions on individual findings do not crash triage or alter scores."""
        class GlitchyProvider(BaseInferenceProvider):
            def __init__(self):
                self.call_count = 0

            def explain(self, finding, assessment):
                self.call_count += 1
                if self.call_count == 1:
                    raise RuntimeError("Fatal GPU VRAM crash on first finding")
                return LLMExplanation(
                    priority_justification="Healthy response",
                    business_impact_summary="Moderate impact",
                    is_llm_available=True,
                    provider="mock_healthy",
                )

        service = ThreatTriageService(provider=GlitchyProvider())
        batch_result = service.triage(SYNTHETIC_BATCH)

        # Batch contains 5 findings; all 5 must be triaged despite provider exception on finding 1
        self.assertEqual(batch_result.total_findings, 5)
        # Priority counts and deterministic scores must be intact
        self.assertEqual(batch_result.counts_by_priority["CRITICAL"], 2)
        self.assertEqual(batch_result.counts_by_priority["HIGH"], 1)
        self.assertEqual(batch_result.counts_by_priority["MEDIUM"], 1)
        self.assertEqual(batch_result.counts_by_priority["LOW"], 1)

        # First finding must have safe fallback explanation without altering its CRITICAL tier
        first_item = batch_result.findings[0]
        self.assertEqual(first_item.assessment.priority_tier, PriorityTier.CRITICAL)
        self.assertFalse(first_item.explanation.is_llm_available)
        self.assertIn("provider failure", first_item.explanation.error_message.lower())

    # -------------------------------------------------------------------------
    # 12. Triage and preview generation never execute remediation
    # -------------------------------------------------------------------------
    @patch("remediation.fix_s3_bucket")
    @patch("remediation.revoke_iam_key")
    def test_12_triage_and_preview_never_execute_remediation(self, mock_revoke, mock_s3):
        """Verify triage and preview generation strictly perform zero live/dry-run AWS remediation calls."""
        # Run entire batch through full triage pipeline with mock provider (no network)
        result = triage_findings(SYNTHETIC_BATCH, provider=MockInferenceProvider())

        # Previews are generated
        self.assertEqual(result.total_findings, 5)
        for item in result.findings:
            if item.remediation_preview and item.remediation_preview.get("executable"):
                self.assertTrue(item.remediation_preview["requires_approval"])

        # Remediation execution functions must NEVER have been called during triage
        mock_s3.assert_not_called()
        mock_revoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
