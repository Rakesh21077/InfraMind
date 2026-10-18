"""
InfraMind - Threat Triage Service & Orchestrator (Phase 6)

Provides a clean, reusable Python service and top-level function that
orchestrates the entire threat-triage pipeline:
1. Ingestion & ASFF Normalization (inframind.ingestion)
2. Deterministic Risk Assessment & Sorting (inframind.prioritization)
3. Structured LLM Explanation & Investigation Steps (inframind.inference)
4. Remediation Preview Contract Generation (inframind.remediation_bridge)

Outputs predictable, typed, JSON-serializable results for UI and API consumers.
Enforces per-finding error boundaries and deterministic policy authority.
"""

from __future__ import annotations
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from inframind.inference import (
    BaseInferenceProvider,
    build_authoritative_remediation_recommendation,
    create_deterministic_fallback_explanation,
    get_inference_provider,
)
from inframind.ingestion import ingest_findings
from inframind.models import (
    DeterministicAssessment,
    NormalizedFinding,
    PredefinedAction,
    TriageBatchResult,
    TriagedFinding,
)
from inframind.prioritization import (
    PrioritizationPolicy,
    assess_finding,
    sort_findings_by_priority,
)
from inframind.remediation_bridge import RemediationBridge
from remediation import sanitize_message

logger = logging.getLogger("inframind.service")


class ThreatTriageService:
    """
    Main reusable threat triage service.
    Designed for seamless consumption by UI developers, API frameworks,
    and agent workflows (e.g. Evolus).
    """

    def __init__(
        self,
        provider: Optional[BaseInferenceProvider] = None,
        policy: Optional[PrioritizationPolicy] = None,
    ):
        self.provider = provider or get_inference_provider()
        self.policy = policy or PrioritizationPolicy()

    def triage(
        self,
        raw_input: Union[str, bytes, Dict[str, Any], List[Any]],
    ) -> TriageBatchResult:
        """
        Execute full end-to-end triage on raw findings data.

        Parameters:
            raw_input: Raw JSON string, bytes, dict (with 'Findings'), or list of findings.

        Returns:
            TriageBatchResult containing sorted findings, priority counts, and metadata.
        """
        # Step 1: Ingest and Normalize
        normalized_list = ingest_findings(raw_input)
        logger.info("Ingested and normalized %d finding(s).", len(normalized_list))

        if not normalized_list:
            return TriageBatchResult(
                findings=[],
                total_findings=0,
                counts_by_priority={},
                provider_info={
                    "provider": type(self.provider).__name__,
                    "model": getattr(self.provider, "model_name", "unknown"),
                },
                generated_at=datetime.now(timezone.utc).isoformat(),
            )

        # Step 2: Deterministic Risk Prioritization
        scored_pairs: List[Tuple[NormalizedFinding, DeterministicAssessment]] = []
        for finding in normalized_list:
            assessment = assess_finding(finding, policy=self.policy)
            scored_pairs.append((finding, assessment))

        # Step 3: Deterministic Sorting (Highest priority first)
        sorted_pairs = sort_findings_by_priority(scored_pairs)

        # Step 4: LLM Explanation & Remediation Preview with Fault Isolation
        triaged_findings: List[TriagedFinding] = []
        counts: Dict[str, int] = {}

        for finding, assessment in sorted_pairs:
            tier_val = assessment.priority_tier.value
            counts[tier_val] = counts.get(tier_val, 0) + 1

            # Generate LLM explanation with per-finding error boundary
            try:
                explanation = self.provider.explain(finding, assessment)
            except Exception as exc:
                sanitized_err = sanitize_message(str(exc))
                logger.error(
                    "Unhandled provider exception for finding '%s': %s",
                    finding.id,
                    sanitized_err,
                )
                explanation = create_deterministic_fallback_explanation(
                    finding,
                    assessment,
                    f"Inference provider failure: {type(exc).__name__}",
                    provider_name=type(self.provider).__name__,
                    model_name=getattr(self.provider, "model_name", "unknown"),
                )

            # Generate remediation preview with trusted validation
            preview = None
            if explanation.recommended_action:
                rec = explanation.recommended_action
                # Ensure recommendation adheres strictly to deterministic policy
                if (
                    rec.action_id != assessment.suggested_action_id
                    and rec.action_id != PredefinedAction.MANUAL_INVESTIGATION_REQUIRED.value
                ):
                    logger.warning(
                        "Action '%s' proposed for finding '%s' does not match deterministic policy '%s'. Overriding.",
                        rec.action_id,
                        finding.id,
                        assessment.suggested_action_id,
                    )
                    rec = build_authoritative_remediation_recommendation(
                        finding,
                        assessment,
                        model_rationale=rec.rationale,
                    )
                    explanation.recommended_action = rec

                preview = RemediationBridge.preview(rec)

            triaged_findings.append(
                TriagedFinding(
                    finding=finding,
                    assessment=assessment,
                    explanation=explanation,
                    remediation_preview=preview,
                )
            )

        return TriageBatchResult(
            findings=triaged_findings,
            total_findings=len(triaged_findings),
            counts_by_priority=counts,
            provider_info={
                "provider": type(self.provider).__name__,
                "model": getattr(self.provider, "model_name", "unknown"),
            },
            generated_at=datetime.now(timezone.utc).isoformat(),
        )


def triage_findings(
    raw_input: Union[str, bytes, Dict[str, Any], List[Any]],
    *,
    provider: Optional[BaseInferenceProvider] = None,
    policy: Optional[PrioritizationPolicy] = None,
) -> TriageBatchResult:
    """
    Convenience function providing a one-line entry point to triage AWS findings.

    Example usage:
        from inframind import triage_findings

        with open("security_hub_findings.json") as f:
            result = triage_findings(f.read())

        for item in result.findings:
            print(f"[{item.assessment.priority_tier}] {item.finding.title} - Score: {item.assessment.score}")
            print(f"Explanation: {item.explanation.priority_justification}")
    """
    service = ThreatTriageService(provider=provider, policy=policy)
    return service.triage(raw_input)
