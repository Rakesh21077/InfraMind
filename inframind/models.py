"""
InfraMind - Core Domain Models & Schemas

Defines Pydantic models for AWS Security Hub ASFF normalization,
deterministic risk prioritization, LLM explanation schemas,
and remediation interface contracts.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PredefinedAction(str, Enum):
    """Recognized safe remediation action identifiers."""
    RESTRICT_S3_PUBLIC_ACCESS = "RESTRICT_S3_PUBLIC_ACCESS"
    REVOKE_IAM_KEY = "REVOKE_IAM_KEY"
    FIX_S3_BUCKET = "fix_s3_bucket"
    REVOKE_IAM_ACCESS_KEY = "revoke_iam_key"
    MANUAL_INVESTIGATION_REQUIRED = "MANUAL_INVESTIGATION_REQUIRED"
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"


class PriorityTier(str, Enum):
    """Normalized priority tiers for triaged findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class FactorCategory(str, Enum):
    """Clear epistemic separation of evidence types."""
    FACT = "OBSERVED_FACT"
    INFERENCE = "INFERRED_RISK"
    UNKNOWN = "UNKNOWN_INFORMATION"


class FindingResource(BaseModel):
    """Extracted resource from an ASFF finding."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Resource ARN or identifier")
    type: str = Field(..., description="AWS resource type, e.g. AwsS3Bucket or AwsIamAccessKey")
    region: Optional[str] = Field(None, description="AWS Region")
    partition: Optional[str] = Field("aws", description="AWS partition")
    details: Dict[str, Any] = Field(default_factory=dict, description="Raw resource details block")


class RemediationRecommendation(BaseModel):
    """A recommended remediation action proposed by the system or LLM."""
    model_config = ConfigDict(extra="ignore")

    action_id: str = Field(..., description="Predefined action identifier, e.g. RESTRICT_S3_PUBLIC_ACCESS")
    target_resource_id: str = Field(..., description="Identifier of target resource")
    target_resource_type: str = Field(..., description="AWS resource type")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters required for remediation execution")
    rationale: str = Field(..., description="Technical and operational rationale for this recommendation")
    requires_approval: bool = Field(True, description="Always requires explicit human operator approval")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence score in the recommendation")


class NormalizedFinding(BaseModel):
    """
    Standardized internal representation of an ingested security finding.
    Source-agnostic schema with preserved raw evidence.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Finding title or headline")
    description: str = Field(..., description="Finding description (untrusted text)")
    source: str = Field(default="AWS_SECURITY_HUB", description="Ingestion source")
    source_severity: str = Field(default="UNKNOWN", description="Original severity reported by source")
    finding_types: List[str] = Field(default_factory=list, description="ASFF Types list")
    created_at: Optional[str] = Field(None, description="Timestamp finding was first observed")
    updated_at: Optional[str] = Field(None, description="Timestamp finding was last updated")
    resources: List[FindingResource] = Field(default_factory=list, description="Affected resources")
    compliance_status: Optional[str] = Field(None, description="PASSED, FAILED, WARNING, NOT_AVAILABLE")
    source_remediation: Optional[Dict[str, Any]] = Field(None, description="Original remediation guidance from finding")
    raw_evidence: Dict[str, Any] = Field(default_factory=dict, description="Preserved raw finding payload for auditing")


class EvidenceFactor(BaseModel):
    """An individual factor influencing the deterministic risk assessment."""
    model_config = ConfigDict(extra="ignore")

    category: FactorCategory
    name: str
    description: str
    weight: float = 0.0
    source_field: Optional[str] = None


class DeterministicAssessment(BaseModel):
    """
    Deterministic, rule-based risk assessment independent of the LLM.
    Strictly separates facts, inferences, and unknowns.
    """
    model_config = ConfigDict(extra="ignore")

    priority_tier: PriorityTier
    score: float = Field(..., ge=0.0, le=100.0, description="Calculated priority score (0-100)")
    basis: str = Field(..., description="Deterministic explanation of how the score/tier was determined")
    factors: List[EvidenceFactor] = Field(default_factory=list, description="All individual evidence factors")
    observed_facts: List[str] = Field(default_factory=list, description="Verified facts from configuration or evidence")
    inferred_risks: List[str] = Field(default_factory=list, description="Potential risks inferred without direct proof")
    unknown_information: List[str] = Field(default_factory=list, description="Critical missing data points")
    suggested_action_id: Optional[str] = Field(None, description="Predefined action ID suggested by deterministic rules")


class LLMExplanation(BaseModel):
    """
    Validated structured explanation produced by the LLM.
    Does not override deterministic score or priority tier.
    """
    model_config = ConfigDict(extra="ignore")

    priority_justification: str = Field(..., description="Explanation of why the finding deserves its assigned tier")
    business_impact_summary: str = Field(..., description="Assessment of potential operational or financial fallout")
    missing_evidence_notes: List[str] = Field(default_factory=list, description="Evidence gaps identified by the model")
    recommended_investigation_steps: List[str] = Field(default_factory=list, description="Actions operator should take to verify")
    recommended_action: Optional[RemediationRecommendation] = Field(None, description="Predefined remediation recommendation")
    action_rationale: Optional[str] = Field(None, description="Reasoning supporting the recommended action")
    is_llm_available: bool = Field(True, description="False if LLM failed, timed out, or returned malformed output")
    model_name: Optional[str] = Field(None, description="Model identifier used for inference")
    provider: Optional[str] = Field(None, description="Inference provider used")
    error_message: Optional[str] = Field(None, description="Details if inference failed or fell back")


class TriagedFinding(BaseModel):
    """Complete triage outcome for a single finding combining normalization, scoring, and explanation."""
    model_config = ConfigDict(extra="ignore")

    finding: NormalizedFinding
    assessment: DeterministicAssessment
    explanation: LLMExplanation
    remediation_preview: Optional[Dict[str, Any]] = Field(
        None, description="Preview of action payload ready for teammate's remediation engine"
    )


class TriageBatchResult(BaseModel):
    """Result of running triage across a batch of findings."""
    model_config = ConfigDict(extra="ignore")

    findings: List[TriagedFinding] = Field(default_factory=list)
    total_findings: int = 0
    counts_by_priority: Dict[str, int] = Field(default_factory=dict)
    provider_info: Dict[str, Any] = Field(default_factory=dict)
    generated_at: str = ""

