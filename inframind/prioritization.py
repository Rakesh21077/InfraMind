"""
InfraMind - Evidence-Based Threat Prioritization Engine (Phase 3)

Calculates deterministic risk prioritization based strictly on verifiable evidence,
source severity, and explicit resource configuration.

Guiding Principles:
- Epistemic clarity: Clearly separates observed facts, inferred risks, and unknown information.
- No hallucinations: Never infers public exposure, compromise, or production criticality from a title alone.
- Non-assumptive safety: Missing evidence is NEVER treated as proof of safety.
- Complete LLM independence: Prioritization runs deterministically without calling LLM endpoints.
- Explainability: Full breakdown of evidence factors affecting the score.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

from inframind.models import (
    DeterministicAssessment,
    EvidenceFactor,
    FactorCategory,
    NormalizedFinding,
    PredefinedAction,
    PriorityTier,
)


class PrioritizationPolicy:
    """Configurable scoring rules for deterministic finding prioritization."""

    SEVERITY_BASE_SCORES = {
        "CRITICAL": 75.0,
        "HIGH": 55.0,
        "MEDIUM": 35.0,
        "LOW": 15.0,
        "INFORMATIONAL": 5.0,
        "UNKNOWN": 25.0,  # Never treat unknown severity as 0 (not assumed safe)
    }

    # Weight adjustments for verified observed facts
    FACT_ACTIVE_COMPROMISE_WEIGHT = 20.0
    FACT_VERIFIED_EXPOSURE_WEIGHT = 15.0
    FACT_PROD_OR_CRITICAL_ASSET_WEIGHT = 10.0
    FACT_COMPENSATING_CONTROL_WEIGHT = -15.0

    # Weight adjustments for inferred contextual risks
    INFERENCE_DATA_EXFILTRATION_RISK_WEIGHT = 5.0
    INFERENCE_LATERAL_MOVEMENT_RISK_WEIGHT = 5.0

    # Tier cutoffs
    CRITICAL_CUTOFF = 70.0
    HIGH_CUTOFF = 50.0
    MEDIUM_CUTOFF = 30.0
    LOW_CUTOFF = 10.0


def assess_finding(
    finding: NormalizedFinding,
    policy: Optional[PrioritizationPolicy] = None,
) -> DeterministicAssessment:
    """
    Perform a deterministic, evidence-based risk assessment on a normalized finding.
    Returns a DeterministicAssessment detailing tier, score, basis, and facts/inferences/unknowns.
    """
    if policy is None:
        policy = PrioritizationPolicy()

    factors: List[EvidenceFactor] = []
    observed_facts: List[str] = []
    inferred_risks: List[str] = []
    unknown_information: List[str] = []

    # 1. Base Score from Source Severity
    sev = (finding.source_severity or "UNKNOWN").upper()
    base_score = policy.SEVERITY_BASE_SCORES.get(sev, policy.SEVERITY_BASE_SCORES["UNKNOWN"])
    factors.append(
        EvidenceFactor(
            category=FactorCategory.FACT,
            name="Source Severity Baseline",
            description=f"Initial baseline assigned from source reported severity '{sev}'",
            weight=base_score,
            source_field="source_severity",
        )
    )
    observed_facts.append(f"Source reporting system classified severity as '{sev}'.")

    current_score = base_score

    # Inspect Resources and Raw Evidence
    finding_types_str = " ".join(finding.finding_types).lower()
    raw_ev = finding.raw_evidence or {}

    # 2. Check for Confirmed Compromise / Active Exploit (Observed Fact)
    # Only if evidence specifically contains active breach/compromise tags or GuardDuty unauthorized access
    compromise_indicators = [
        "unauthorizedaccess",
        "credentialcompromise",
        "trojan",
        "exfiltration",
        "backdoor",
        "ransomware",
    ]
    has_active_compromise_evidence = any(ci in finding_types_str for ci in compromise_indicators) or (
        "compromised" in str(raw_ev.get("Workflow", {})).lower()
    )

    if has_active_compromise_evidence:
        w = policy.FACT_ACTIVE_COMPROMISE_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.FACT,
                name="Confirmed Active Compromise Evidence",
                description="Telemetry indicates unauthorized access or active compromise indicators.",
                weight=w,
                source_field="finding_types",
            )
        )
        observed_facts.append("Evidence contains confirmed active exploit or unauthorized credential usage.")

    # 3. Check for Verified Internet Exposure (Observed Fact)
    # Must be verified in configuration details, not just assumed from title
    has_verified_public_config = False
    for res in finding.resources:
        # Check S3 PublicAccessBlock configuration if present
        details = res.details or {}
        s3_pab = details.get("AwsS3Bucket", {}).get("PublicAccessBlockConfiguration", {})
        if not s3_pab and "PublicAccessBlockConfiguration" in details:
            s3_pab = details["PublicAccessBlockConfiguration"]

        if s3_pab:
            # If any public access flag is False, bucket allows public exposure
            flags = [
                s3_pab.get("BlockPublicAcls"),
                s3_pab.get("IgnorePublicAcls"),
                s3_pab.get("BlockPublicPolicy"),
                s3_pab.get("RestrictPublicBuckets"),
            ]
            if any(f is False for f in flags):
                has_verified_public_config = True
                break

        # Check for explicit internet-facing attributes
        if details.get("PubliclyAccessible") is True:
            has_verified_public_config = True
            break

    # Also check if ASFF compliance status explicitly failed a public exposure check
    if "public" in finding_types_str and finding.compliance_status == "FAILED":
        has_verified_public_config = True

    if has_verified_public_config:
        w = policy.FACT_VERIFIED_EXPOSURE_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.FACT,
                name="Verified Public Exposure Configuration",
                description="Resource configuration verified to allow public network ingress or lacks public access block.",
                weight=w,
                source_field="resources.details",
            )
        )
        observed_facts.append("Resource configuration explicitly confirms lack of public access blocks or internet reachability.")

    # 4. Check for Verified Production / Critical Asset Tags (Observed Fact)
    is_prod_asset = False
    for res in finding.resources:
        tags = res.details.get("Tags", {}) if isinstance(res.details, dict) else {}
        if isinstance(tags, dict):
            for k, v in tags.items():
                if str(k).lower() in ("env", "environment", "tier") and str(v).lower() in ("prod", "production"):
                    is_prod_asset = True
                    break
        elif isinstance(tags, list):
            for tag_entry in tags:
                if isinstance(tag_entry, dict) and tag_entry.get("Key", "").lower() in ("env", "environment"):
                    if tag_entry.get("Value", "").lower() in ("prod", "production"):
                        is_prod_asset = True
                        break

    if is_prod_asset:
        w = policy.FACT_PROD_OR_CRITICAL_ASSET_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.FACT,
                name="Production Environment Tag",
                description="Resource metadata explicitly tags asset as production environment.",
                weight=w,
                source_field="resources.details.Tags",
            )
        )
        observed_facts.append("Verified resource tag confirms production asset status.")
    else:
        unknown_information.append("Environment criticality (production vs staging/dev) is unknown from available resource tags.")

    # 5. Check for Verified Compensating Controls (Observed Fact)
    has_compensating_controls = False
    if finding.compliance_status == "PASSED":
        has_compensating_controls = True
    for res in finding.resources:
        if res.details.get("WafAttached") is True:
            has_compensating_controls = True

    if has_compensating_controls:
        w = policy.FACT_COMPENSATING_CONTROL_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.FACT,
                name="Compensating Controls Present",
                description="Verified safeguards or passing compliance checks mitigate impact.",
                weight=w,
                source_field="compliance_status",
            )
        )
        observed_facts.append("Compensating security controls or passing compliance status verified.")

    # 6. Contextual Risk Inferences (Clearly separated from facts)
    primary_res_type = finding.resources[0].type if finding.resources else "Unknown"

    if "s3" in primary_res_type.lower():
        w = policy.INFERENCE_DATA_EXFILTRATION_RISK_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.INFERENCE,
                name="S3 Data Exfiltration Potential",
                description="S3 buckets typically store company or customer data; exposure creates potential exfiltration risk.",
                weight=w,
                source_field="resources.type",
            )
        )
        inferred_risks.append("Storage service could contain sensitive business data vulnerable to unauthorized download if exposed.")
    elif "iam" in primary_res_type.lower() or "accesskey" in primary_res_type.lower():
        w = policy.INFERENCE_LATERAL_MOVEMENT_RISK_WEIGHT
        current_score += w
        factors.append(
            EvidenceFactor(
                category=FactorCategory.INFERENCE,
                name="IAM Privilege Abuse Potential",
                description="Compromised credentials permit API calls under assumed identity with lateral movement potential.",
                weight=w,
                source_field="resources.type",
            )
        )
        inferred_risks.append("Compromised identity credentials may allow adversaries to move laterally across AWS services.")

    # 7. Identify Unknown Information / Evidence Gaps
    if not has_verified_public_config and not has_active_compromise_evidence:
        unknown_information.append("Direct network ingress reachability not verified; finding lacks VPC network path analysis.")

    has_data_classification = any(
        "classification" in str(res.details).lower() for res in finding.resources
    )
    if not has_data_classification:
        unknown_information.append("Data sensitivity and payload classification are unknown (no DLP or inventory scan attached).")

    if not finding.resources:
        unknown_information.append("No specific target AWS resources were parsed from this finding.")

    # Clamp score to [0.0, 100.0]
    final_score = max(0.0, min(100.0, round(current_score, 1)))

    # Determine Priority Tier
    if final_score >= policy.CRITICAL_CUTOFF:
        tier = PriorityTier.CRITICAL
    elif final_score >= policy.HIGH_CUTOFF:
        tier = PriorityTier.HIGH
    elif final_score >= policy.MEDIUM_CUTOFF:
        tier = PriorityTier.MEDIUM
    elif final_score >= policy.LOW_CUTOFF:
        tier = PriorityTier.LOW
    else:
        tier = PriorityTier.INFORMATIONAL

    # Suggest Predefined Remediation Action
    suggested_action = None
    if any("s3" in r.type.lower() for r in finding.resources) or "s3" in finding_types_str:
        suggested_action = PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value
    elif any("iam" in r.type.lower() or "accesskey" in r.type.lower() for r in finding.resources) or "accesskey" in finding_types_str:
        suggested_action = PredefinedAction.REVOKE_IAM_KEY.value
    else:
        suggested_action = PredefinedAction.MANUAL_INVESTIGATION_REQUIRED.value

    basis = (
        f"Assigned priority {tier.value} (score {final_score}/100) based on source severity {sev} "
        f"with {len(observed_facts)} verified fact(s), {len(inferred_risks)} contextual risk inference(s), "
        f"and {len(unknown_information)} unknown information gap(s)."
    )

    return DeterministicAssessment(
        priority_tier=tier,
        score=final_score,
        basis=basis,
        factors=factors,
        observed_facts=observed_facts,
        inferred_risks=inferred_risks,
        unknown_information=unknown_information,
        suggested_action_id=suggested_action,
    )


def sort_findings_by_priority(
    triaged_list: List[Tuple[NormalizedFinding, DeterministicAssessment]],
) -> List[Tuple[NormalizedFinding, DeterministicAssessment]]:
    """
    Sort triaged findings deterministically:
    1. Priority Tier ranking (CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL)
    2. Score descending
    3. Finding ID ascending (strict deterministic tie-breaking for identical scores)
    """
    tier_order = {
        PriorityTier.CRITICAL: 0,
        PriorityTier.HIGH: 1,
        PriorityTier.MEDIUM: 2,
        PriorityTier.LOW: 3,
        PriorityTier.INFORMATIONAL: 4,
    }

    return sorted(
        triaged_list,
        key=lambda item: (
            tier_order.get(item[1].priority_tier, 99),
            -item[1].score,
            item[0].id,
        ),
    )
