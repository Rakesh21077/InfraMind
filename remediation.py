"""
InfraMind - AI Cloud Security Guardrail for Startups & IT
Member 3: Auto-Patch & Remediation Scripts

This module implements safe, production-grade, and auditable remediation functions
for critical cloud security incidents:
1. S3 Public Bucket Exposure (fix_s3_bucket)
2. Compromised IAM Access Keys (revoke_iam_key)

Safe Execution Guarantees:
- Default Execution Mode: DRY_RUN=True, LIVE_EXECUTION_ENABLED=False.
- No AWS calls occur in dry-run mode.
- Live AWS execution strictly requires all three safety gates:
    1. DRY_RUN explicitly disabled (DRY_RUN=False)
    2. LIVE_EXECUTION_ENABLED explicitly enabled (LIVE_EXECUTION_ENABLED=True)
    3. Explicit human operator approval passed at call time (approved=True)
- All inputs are strictly validated prior to client initialization or API dispatch.
- Client injection is supported across all functions for mock-based unit testing.
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional, Union

from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Load environment configurations from local .env without overwriting existing runtime vars
load_dotenv(override=False)

# Configure logger
logger = logging.getLogger("inframind.remediation")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [InfraMind-Remediation] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Structured Status Constants
STATUS_SIMULATED = "SIMULATED"
STATUS_SUCCESS = "SUCCESS"
STATUS_FAILED = "FAILED"
STATUS_BLOCKED = "BLOCKED"

# Regex for sensitive token sanitization in log messages and return payloads
SENSITIVE_PATTERNS = [
    (re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}"), r"\1****************"),
    (
        re.compile(
            r"(?i)(aws_secret_access_key|secret_key|secretaccesskey|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)(authorization\s*:\s*Bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
        r"\1[REDACTED]",
    ),
]


def sanitize_message(message: str) -> str:
    """
    Remove or mask sensitive information (such as secret keys, tokens, or credentials)
    from log entries or error messages before returning them to callers or dashboards.
    """
    if not isinstance(message, str):
        message = str(message)
    sanitized = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _parse_bool(val: Optional[Union[str, bool]], default: bool = False) -> bool:
    """
    Parse a boolean environment or configuration value safely.
    Interprets 'true', '1', and 'yes' as True (case-insensitively).
    Interprets 'false', '0', and 'no' as False (case-insensitively).
    Returns default for invalid, missing, or unrecognized values.
    """
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return bool(val)
    if isinstance(val, str):
        cleaned = val.strip().lower()
        if cleaned in ("true", "1", "yes", "t", "y"):
            return True
        if cleaned in ("false", "0", "no", "f", "n"):
            return False
    return default


def is_dry_run() -> bool:
    """
    Check if dry-run simulation mode is active.
    Defaults to True for maximum safety.
    """
    raw = os.getenv("DRY_RUN", "True")
    return _parse_bool(raw, default=True)


def is_live_execution_enabled() -> bool:
    """
    Check if live AWS execution is explicitly permitted by environment configuration.
    Defaults to False for safety.
    """
    raw = os.getenv("LIVE_EXECUTION_ENABLED", "False")
    return _parse_bool(raw, default=False)


def _validate_bucket_name(bucket_name: Any) -> Optional[str]:
    """
    Validate that the S3 bucket name is a valid non-empty string adhering to AWS naming guidelines.
    Returns None if valid, or an error description string if invalid.
    """
    if bucket_name is None:
        return "S3 bucket name cannot be None or missing."
    if not isinstance(bucket_name, str):
        return f"S3 bucket name must be a string, got {type(bucket_name).__name__}."
    cleaned = bucket_name.strip()
    if not cleaned:
        return "S3 bucket name cannot be empty or blank."
    if len(cleaned) < 3 or len(cleaned) > 63:
        return f"S3 bucket name length must be between 3 and 63 characters (got {len(cleaned)})."
    if any(c.isspace() for c in cleaned):
        return "S3 bucket name cannot contain whitespace."
    if not re.match(r"^[a-zA-Z0-9.-]+$", cleaned):
        return "S3 bucket name contains illegal characters (allowed: alphanumeric, '.', '-')."
    return None


def _validate_access_key_id(access_key_id: Any) -> Optional[str]:
    """
    Validate that the IAM access key ID is a valid non-empty string.
    Returns None if valid, or an error description string if invalid.
    """
    if access_key_id is None:
        return "IAM access key ID cannot be None or missing."
    if not isinstance(access_key_id, str):
        return f"IAM access key ID must be a string, got {type(access_key_id).__name__}."
    cleaned = access_key_id.strip()
    if not cleaned:
        return "IAM access key ID cannot be empty or blank."
    if any(c.isspace() for c in cleaned):
        return "IAM access key ID cannot contain whitespace."
    if len(cleaned) < 16 or len(cleaned) > 128:
        return f"IAM access key ID length must be between 16 and 128 characters (got {len(cleaned)})."
    if not re.match(r"^[A-Z0-9]+$", cleaned):
        return "IAM access key ID must consist only of uppercase alphanumeric characters."
    return None


def fix_s3_bucket(
    bucket_name: str,
    *,
    approved: bool = False,
    s3_client: Optional[Any] = None,
) -> Dict[str, str]:
    """
    Apply S3 Public Access Block to a specified Amazon S3 bucket to prevent public exposure.

    Configures all 4 bucket-level public access block settings to True:
      - BlockPublicAcls: True
      - IgnorePublicAcls: True
      - BlockPublicPolicy: True
      - RestrictPublicBuckets: True

    Safety Rules:
      - If DRY_RUN is True: Returns SIMULATED without calling AWS.
      - If LIVE_EXECUTION_ENABLED is False or approved is False: Returns BLOCKED.
      - If inputs are invalid: Returns FAILED.
      - If AWS API call succeeds: Returns SUCCESS.
      - If AWS API call raises ClientError/BotoCoreError: Returns FAILED with sanitized details.

    Parameters:
      bucket_name (str): The S3 bucket to secure.
      approved (bool): Explicit human authorization from dashboard operator.
      s3_client (Optional[Any]): Injected Boto3 S3 client (primarily used for unit testing).

    Returns:
      Dict[str, str]: Structured result containing 'status', 'action', 'resource', and 'message'.
    """
    action_name = "fix_s3_bucket"
    resource_id = str(bucket_name) if bucket_name is not None else "UNKNOWN"

    # Step 1: Input Validation
    val_err = _validate_bucket_name(bucket_name)
    if val_err:
        logger.warning("S3 remediation validation failed: %s", val_err)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": f"Input validation failed: {val_err}",
        }

    clean_bucket = bucket_name.strip()
    resource_id = clean_bucket

    # Step 2: Check Dry Run
    if is_dry_run():
        logger.info(
            "SIMULATION: fix_s3_bucket on '%s' (DRY_RUN=True). No AWS changes made.",
            clean_bucket,
        )
        return {
            "status": STATUS_SIMULATED,
            "action": action_name,
            "resource": resource_id,
            "message": "Dry run only. No AWS changes were made.",
        }

    # Step 3: Check Live Execution Flag
    if not is_live_execution_enabled():
        logger.warning(
            "BLOCKED: fix_s3_bucket on '%s' blocked because LIVE_EXECUTION_ENABLED is not enabled.",
            clean_bucket,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: LIVE_EXECUTION_ENABLED is not set to true in environment."
            ),
        }

    # Step 4: Check Explicit Human Operator Approval
    if not approved:
        logger.warning(
            "BLOCKED: fix_s3_bucket on '%s' blocked due to missing explicit human approval (approved=True).",
            clean_bucket,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: Explicit human operator approval (approved=True) is required."
            ),
        }

    # Step 5: Acquire S3 Client (Only reached if live execution is approved and enabled)
    if s3_client is None:
        try:
            region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            s3_client = boto3.client("s3", region_name=region)
        except Exception as exc:
            sanitized_err = sanitize_message(str(exc))
            logger.error(
                "Failed to initialize AWS S3 client for '%s': %s",
                clean_bucket,
                sanitized_err,
            )
            return {
                "status": STATUS_FAILED,
                "action": action_name,
                "resource": resource_id,
                "message": f"Failed to initialize AWS S3 client: {sanitized_err}",
            }

    # Step 6: Execute AWS put_public_access_block API
    try:
        s3_client.put_public_access_block(
            Bucket=clean_bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info(
            "SUCCESS: S3 Public Access Block applied successfully to '%s'.",
            clean_bucket,
        )
        return {
            "status": STATUS_SUCCESS,
            "action": action_name,
            "resource": resource_id,
            "message": (
                f"Public access block applied successfully to bucket '{clean_bucket}'. "
                "All four public access restriction flags are now enabled."
            ),
        }
    except ClientError as exc:
        err_code = exc.response.get("Error", {}).get("Code", "ClientError")
        err_msg = exc.response.get("Error", {}).get("Message", str(exc))
        sanitized = sanitize_message(f"AWS S3 ClientError [{err_code}]: {err_msg}")
        logger.error("AWS S3 ClientError on '%s': %s", clean_bucket, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }
    except BotoCoreError as exc:
        sanitized = sanitize_message(f"AWS S3 BotoCore connection error: {str(exc)}")
        logger.error("AWS S3 BotoCoreError on '%s': %s", clean_bucket, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }
    except Exception as exc:
        sanitized = sanitize_message(f"Unexpected error executing S3 remediation: {str(exc)}")
        logger.error("Unexpected error on '%s': %s", clean_bucket, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }


def revoke_iam_key(
    access_key_id: str,
    user_name: Optional[str] = None,
    *,
    approved: bool = False,
    iam_client: Optional[Any] = None,
) -> Dict[str, str]:
    """
    Deactivate a compromised AWS IAM access key by setting its status to 'Inactive'.

    This function safely modifies the access key status without deleting the key,
    allowing subsequent forensics or controlled key retirement.

    Safety Rules:
      - If DRY_RUN is True: Returns SIMULATED without calling AWS.
      - If LIVE_EXECUTION_ENABLED is False or approved is False: Returns BLOCKED.
      - If user_name is absent, empty, or targets root account during live execution: Returns BLOCKED.
      - If access_key_id is invalid: Returns FAILED.
      - If AWS API call succeeds: Returns SUCCESS.
      - If AWS API call raises ClientError/BotoCoreError: Returns FAILED with sanitized details.

    Parameters:
      access_key_id (str): The AWS IAM Access Key ID to deactivate.
      user_name (Optional[str]): The IAM username associated with the access key.
                                 Optional in dry-run mode; strictly required for live execution.
      approved (bool): Explicit human authorization from dashboard operator.
      iam_client (Optional[Any]): Injected Boto3 IAM client (primarily used for unit testing).

    Returns:
      Dict[str, str]: Structured result containing 'status', 'action', 'resource', and 'message'.
    """
    action_name = "revoke_iam_key"
    resource_id = str(access_key_id) if access_key_id is not None else "UNKNOWN"

    # Step 1: Input Validation for Access Key ID
    val_err = _validate_access_key_id(access_key_id)
    if val_err:
        logger.warning("IAM remediation validation failed: %s", val_err)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": f"Input validation failed: {val_err}",
        }

    clean_key = access_key_id.strip()
    resource_id = clean_key

    # Step 2: Check Dry Run
    if is_dry_run():
        logger.info(
            "SIMULATION: revoke_iam_key on '%s' (DRY_RUN=True). No AWS changes made.",
            clean_key,
        )
        return {
            "status": STATUS_SIMULATED,
            "action": action_name,
            "resource": resource_id,
            "message": "Dry run only. No AWS changes were made.",
        }

    # Step 3: Check Live Execution Flag
    if not is_live_execution_enabled():
        logger.warning(
            "BLOCKED: revoke_iam_key on '%s' blocked because LIVE_EXECUTION_ENABLED is not enabled.",
            clean_key,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: LIVE_EXECUTION_ENABLED is not set to true in environment."
            ),
        }

    # Step 4: Check Explicit Human Operator Approval
    if not approved:
        logger.warning(
            "BLOCKED: revoke_iam_key on '%s' blocked due to missing explicit human approval (approved=True).",
            clean_key,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: Explicit human operator approval (approved=True) is required."
            ),
        }

    # Step 5: Validate Target IAM Username for Live Execution
    if not user_name or not isinstance(user_name, str) or not user_name.strip():
        logger.warning(
            "BLOCKED: revoke_iam_key on '%s' blocked because IAM user_name is missing or invalid.",
            clean_key,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: A specific, validated IAM username is required for live deactivation. "
                "Target username cannot be omitted or guessed."
            ),
        }

    clean_user = user_name.strip()

    # Safeguard against root account keys (which cannot and should not be modified via update_access_key)
    if clean_user.lower() in ("root", "<root_account>", "root_account", "<root>"):
        logger.warning(
            "BLOCKED: revoke_iam_key on '%s' targeted root account. Refusing automated deactivation.",
            clean_key,
        )
        return {
            "status": STATUS_BLOCKED,
            "action": action_name,
            "resource": resource_id,
            "message": (
                "Live execution blocked: Root account access keys cannot be deactivated via IAM user APIs. "
                "Manual root account console intervention is required."
            ),
        }

    # Step 6: Acquire IAM Client (Only reached if live execution is approved and enabled)
    if iam_client is None:
        try:
            region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            iam_client = boto3.client("iam", region_name=region)
        except Exception as exc:
            sanitized_err = sanitize_message(str(exc))
            logger.error(
                "Failed to initialize AWS IAM client for '%s': %s",
                clean_key,
                sanitized_err,
            )
            return {
                "status": STATUS_FAILED,
                "action": action_name,
                "resource": resource_id,
                "message": f"Failed to initialize AWS IAM client: {sanitized_err}",
            }

    # Step 7: Execute AWS update_access_key API to set key status to 'Inactive'
    try:
        iam_client.update_access_key(
            UserName=clean_user,
            AccessKeyId=clean_key,
            Status="Inactive",
        )
        logger.info(
            "SUCCESS: Access key '%s' for user '%s' deactivated successfully.",
            clean_key,
            clean_user,
        )
        return {
            "status": STATUS_SUCCESS,
            "action": action_name,
            "resource": resource_id,
            "message": (
                f"IAM access key '{clean_key}' for user '{clean_user}' "
                "was successfully set to 'Inactive'. The key is preserved for auditing."
            ),
        }
    except ClientError as exc:
        err_code = exc.response.get("Error", {}).get("Code", "ClientError")
        err_msg = exc.response.get("Error", {}).get("Message", str(exc))
        sanitized = sanitize_message(f"AWS IAM ClientError [{err_code}]: {err_msg}")
        logger.error("AWS IAM ClientError on '%s': %s", clean_key, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }
    except BotoCoreError as exc:
        sanitized = sanitize_message(f"AWS IAM BotoCore connection error: {str(exc)}")
        logger.error("AWS IAM BotoCoreError on '%s': %s", clean_key, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }
    except Exception as exc:
        sanitized = sanitize_message(f"Unexpected error executing IAM remediation: {str(exc)}")
        logger.error("Unexpected error on '%s': %s", clean_key, sanitized)
        return {
            "status": STATUS_FAILED,
            "action": action_name,
            "resource": resource_id,
            "message": sanitized,
        }


# =====================================================================
# Safe Local Demonstration
# =====================================================================
if __name__ == "__main__":
    print("==================================================")
    print("InfraMind Member 3 - Remediation Demo")
    mode_label = "DRY RUN" if is_dry_run() else "LIVE EXECUTION (ACTIVE)"
    print(f"Execution mode: {mode_label}")
    print("==================================================")

    # Fake sample inputs for demonstration
    sample_bucket = "demo-public-bucket"
    sample_key = "AKIAIOSFODNN7EXAMPLE"
    sample_user = "developer-alice"

    print("\n--- S3 Public Bucket Remediation ---")
    s3_result = fix_s3_bucket(sample_bucket)
    print(f"Status:  {s3_result['status']}")
    print(f"Action:  {s3_result['action']}")
    print(f"Target:  {s3_result['resource']}")
    print(f"Message: {s3_result['message']}")
    print(f"Full payload: {json.dumps(s3_result, indent=2)}")

    print("\n--- IAM Access Key Deactivation ---")
    iam_result = revoke_iam_key(sample_key, user_name=sample_user)
    print(f"Status:  {iam_result['status']}")
    print(f"Action:  {iam_result['action']}")
    print(f"Target:  {iam_result['resource']}")
    print(f"Message: {iam_result['message']}")
    print(f"Full payload: {json.dumps(iam_result, indent=2)}")

    print("\n==================================================")
    print("Demo completed safely.")
    print("No AWS credentials were required and no cloud changes were made.")
    print("==================================================")
