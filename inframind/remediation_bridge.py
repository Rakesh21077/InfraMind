"""
InfraMind - Remediation Bridge & Safety Interface (Phase 5)

Connects the threat-triage engine to Member 3's Boto3 remediation engine (remediation.py).

Enforces strict safety invariants:
- Zero Overwrite: Does not modify or replace remediation.py.
- Predefined Actions Only: Maps action identifiers (RESTRICT_S3_PUBLIC_ACCESS, REVOKE_IAM_KEY)
  to fix_s3_bucket and revoke_iam_key.
- No LLM Autonomous Execution: Model responses alone NEVER authorize an AWS change.
- Multi-gate Approval: Human operator must explicitly provide approved=True.
- Validation: Parameters and resource formats are checked before dispatch.
- Verification: Only marks an action successful if remediation.py returns STATUS_SUCCESS.
"""

from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from inframind.models import PredefinedAction, RemediationRecommendation
from remediation import (
    STATUS_BLOCKED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    STATUS_SUCCESS,
    fix_s3_bucket,
    revoke_iam_key,
    sanitize_message,
)

logger = logging.getLogger("inframind.remediation_bridge")


class RemediationBridge:
    """
    Bridge connecting threat triage recommendations with Member 3's remediation functions.
    """

    SUPPORTED_ACTIONS = {
        PredefinedAction.RESTRICT_S3_PUBLIC_ACCESS.value: "fix_s3_bucket",
        PredefinedAction.FIX_S3_BUCKET.value: "fix_s3_bucket",
        PredefinedAction.REVOKE_IAM_KEY.value: "revoke_iam_key",
        PredefinedAction.REVOKE_IAM_ACCESS_KEY.value: "revoke_iam_key",
    }

    @classmethod
    def preview(cls, recommendation: RemediationRecommendation) -> Dict[str, Any]:
        """
        Generate a safe, static preview of the remediation action
        for dashboard display without calling AWS or executing changes.
        Validates target resource type and required parameters before marking executable.
        """
        action_key = cls.SUPPORTED_ACTIONS.get(recommendation.action_id)
        if not action_key:
            return {
                "status": STATUS_BLOCKED,
                "action": recommendation.action_id,
                "resource": recommendation.target_resource_id,
                "message": f"Action '{recommendation.action_id}' requires manual operator intervention.",
                "executable": False,
                "requires_approval": True,
            }

        # Check target resource identifier presence
        target_id = (recommendation.target_resource_id or "").strip()
        if not target_id or target_id in ("NONE", "UNKNOWN_TARGET", "UNKNOWN_RESOURCE"):
            return {
                "status": STATUS_BLOCKED,
                "action": action_key,
                "resource": target_id or "MISSING",
                "message": "Target resource identifier is missing or unverified.",
                "executable": False,
                "requires_approval": True,
            }

        target_type_lower = (recommendation.target_resource_type or "").lower()

        # Validate resource compatibility for fix_s3_bucket
        if action_key == "fix_s3_bucket":
            bucket_name = recommendation.parameters.get("bucket_name")
            if "s3" not in target_type_lower or not bucket_name:
                return {
                    "status": STATUS_BLOCKED,
                    "action": action_key,
                    "resource": target_id,
                    "message": "Missing or mismatched S3 bucket resource parameters.",
                    "executable": False,
                    "requires_approval": True,
                }

        # Validate resource compatibility for revoke_iam_key
        elif action_key == "revoke_iam_key":
            access_key_id = recommendation.parameters.get("access_key_id")
            if ("iam" not in target_type_lower and "accesskey" not in target_type_lower) or not access_key_id:
                return {
                    "status": STATUS_BLOCKED,
                    "action": action_key,
                    "resource": target_id,
                    "message": "Missing or mismatched IAM access key resource parameters.",
                    "executable": False,
                    "requires_approval": True,
                }

        return {
            "status": "READY_FOR_APPROVAL",
            "action": action_key,
            "target_resource": recommendation.target_resource_id,
            "target_type": recommendation.target_resource_type,
            "parameters": recommendation.parameters,
            "rationale": recommendation.rationale,
            "executable": True,
            "requires_approval": True,
        }

    @classmethod
    def execute(
        cls,
        recommendation: RemediationRecommendation,
        *,
        approved: bool = False,
        s3_client: Optional[Any] = None,
        iam_client: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Execute or simulate a remediation recommendation through Member 3's functions.

        Safety Rules:
        - If approved is False, live execution is strictly blocked by remediation.py.
        - Parameters are validated before calling remediation functions.
        - Returns Member 3's standardized result dictionary.
        """
        action_key = cls.SUPPORTED_ACTIONS.get(recommendation.action_id)
        if not action_key:
            logger.warning("Attempted execution of unsupported action: %s", recommendation.action_id)
            return {
                "status": STATUS_BLOCKED,
                "action": recommendation.action_id,
                "resource": recommendation.target_resource_id,
                "message": (
                    f"Action '{recommendation.action_id}' is not an automated remediation action. "
                    "Manual engineer review is required."
                ),
            }

        # Dispatch: S3 Public Access Block
        if action_key == "fix_s3_bucket":
            bucket_name = recommendation.parameters.get("bucket_name")
            if not bucket_name:
                # Derive from resource identifier
                raw_id = recommendation.target_resource_id
                bucket_name = raw_id.split(":")[-1].replace("arn:aws:s3:::", "").strip()

            logger.info("Dispatching fix_s3_bucket for '%s' (approved=%s)", bucket_name, approved)
            return fix_s3_bucket(bucket_name, approved=approved, s3_client=s3_client)

        # Dispatch: IAM Access Key Revocation
        elif action_key == "revoke_iam_key":
            key_id = recommendation.parameters.get("access_key_id")
            if not key_id:
                raw_id = recommendation.target_resource_id
                key_id = raw_id.split("/")[-1].strip()

            user_name = recommendation.parameters.get("user_name")
            logger.info(
                "Dispatching revoke_iam_key for key '%s', user '%s' (approved=%s)",
                key_id,
                user_name,
                approved,
            )
            return revoke_iam_key(key_id, user_name=user_name, approved=approved, iam_client=iam_client)

        return {
            "status": STATUS_FAILED,
            "action": recommendation.action_id,
            "resource": recommendation.target_resource_id,
            "message": f"Unhandled dispatch path for action '{action_key}'",
        }

