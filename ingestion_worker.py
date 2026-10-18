"""
InfraMind — AWS Real-Time Security Event Ingestion Worker
EventBridge / Amazon SQS Long-Polling Ingestion Engine

Monitors the primary SQS security queue for AWS CloudTrail API calls,
Amazon GuardDuty threat findings, and cloud security events.
Normalizes incoming events, performs idempotent deduplication, validates
resource identifiers, checks live S3 security posture (read-only), and persists
incidents into the SQLite database.
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

load_dotenv(override=False)

from agent import analyze_security_log
from database import (
    get_incident_by_event_id,
    init_db,
    insert_or_get_incident,
    set_system_status,
    update_analysis,
)
from remediation import sanitize_message

logger = logging.getLogger("inframind.ingestion")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [InfraMind-Ingestion] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Global shutdown flag for graceful termination
_SHUTDOWN_REQUESTED = False


def _signal_handler(signum, frame):
    global _SHUTDOWN_REQUESTED
    logger.info("Shutdown signal (%s) received. Completing in-flight batch and terminating...", signum)
    _SHUTDOWN_REQUESTED = True


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


def normalize_aws_event(raw_body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Validate and normalize incoming event payloads from:
    1. EventBridge envelope wrapping CloudTrail management events
    2. Direct CloudTrail JSON records
    3. Amazon GuardDuty threat finding events

    Returns normalized incident dictionary or None if unparseable/unsupported.
    """
    if not isinstance(raw_body, dict):
        return None

    # Handle EventBridge envelope
    detail = raw_body.get("detail", raw_body)
    detail_type = str(raw_body.get("detail-type", "")).lower()
    source = str(raw_body.get("source", detail.get("eventSource", ""))).lower()

    # -------------------------------------------------------------
    # Case A: GuardDuty Finding Event
    # -------------------------------------------------------------
    if "guardduty" in source or "guardduty finding" in detail_type:
        finding_id = str(detail.get("id") or raw_body.get("id", f"gd-{int(time.time())}"))
        finding_type = str(detail.get("type", "GuardDuty Security Finding"))
        severity = float(detail.get("severity", 5.0))
        account_id = str(detail.get("accountId") or raw_body.get("account", "unknown-account"))
        region = str(detail.get("region") or raw_body.get("region", "us-east-1"))
        timestamp = detail.get("updatedAt") or detail.get("createdAt") or raw_body.get("time") or datetime.now(timezone.utc).isoformat()
        description = detail.get("description", f"Amazon GuardDuty threat finding: {finding_type}")

        # Extract target resource
        res_info = detail.get("resource", {})
        resource_id = "unknown-guardduty-target"
        resource_type = "AWS::Resource"
        user_name = None

        if res_info.get("resourceType") == "AccessKey":
            key_details = res_info.get("accessKeyDetails", {})
            resource_id = key_details.get("accessKeyId", resource_id)
            user_name = key_details.get("userName")
            resource_type = "AWS::IAM::AccessKey"
        elif res_info.get("resourceType") == "S3Bucket":
            s3_details = res_info.get("s3BucketDetails", [{}])[0]
            resource_id = s3_details.get("name", resource_id)
            resource_type = "AWS::S3::Bucket"
        elif res_info.get("instanceDetails"):
            resource_id = res_info.get("instanceDetails", {}).get("instanceId", resource_id)
            resource_type = "AWS::EC2::Instance"

        return {
            "event_id": finding_id,
            "source_event_id": finding_id,
            "event_source": "aws.guardduty",
            "event_name": finding_type,
            "aws_account_id": account_id,
            "aws_region": region,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "user_name": user_name,
            "timestamp": timestamp,
            "details": f"[GuardDuty Severity {severity}] {description}",
            "threat_priority": "CRITICAL" if severity >= 7.0 else ("HIGH" if severity >= 4.0 else "MEDIUM"),
            "threat_score": min(10, int(severity)),
            "blast_radius_score": min(10, int(severity * 0.9)),
            "vulnerability_type": finding_type,
            "raw_event": raw_body,
        }

    # -------------------------------------------------------------
    # Case B: CloudTrail API Management Event
    # -------------------------------------------------------------
    event_id = str(detail.get("eventID") or raw_body.get("id", "")).strip()
    if not event_id:
        # Fallback generate unique ID from timestamp and eventName if absent
        event_id = f"ct-{int(time.time() * 1000)}"

    event_name = str(detail.get("eventName", raw_body.get("event_name", "UnknownAPI")))
    event_source = str(detail.get("eventSource", source))
    account_id = str(detail.get("recipientAccountId") or raw_body.get("account", "unknown-account"))
    region = str(detail.get("awsRegion") or raw_body.get("region", "us-east-1"))
    timestamp = detail.get("eventTime") or raw_body.get("time") or datetime.now(timezone.utc).isoformat()
    req_params = detail.get("requestParameters") or {}
    resp_elements = detail.get("responseElements") or {}
    user_identity = detail.get("userIdentity") or {}

    actor_user = user_identity.get("userName") or user_identity.get("principalId", "UnknownActor")
    target_user = req_params.get("userName") or actor_user
    resource_id = "unknown-resource"
    resource_type = "AWS::Resource"
    details = f"AWS CloudTrail API call '{event_name}' executed by principal '{actor_user}'."

    # Sub-case: S3 Bucket Security Events
    if "s3" in event_source or event_name.startswith("PutBucket") or "PublicAccessBlock" in event_name:
        resource_type = "AWS::S3::Bucket"
        resource_id = req_params.get("bucketName") or req_params.get("Bucket") or "unspecified-bucket"
        if event_name == "PutBucketAcl":
            details = f"PutBucketAcl modified on bucket '{resource_id}'. Investigating for public-read or AllUsers permissions."
        elif event_name == "PutBucketPolicy":
            details = f"PutBucketPolicy updated on bucket '{resource_id}'. Investigating for wildcard principal exposure."
        elif event_name == "PutPublicAccessBlock":
            details = f"PutPublicAccessBlock modified on bucket '{resource_id}'."

    # Sub-case: IAM Access Key & Policy Events
    elif "iam" in event_source or "AccessKey" in event_name or "Policy" in event_name:
        if "AccessKey" in event_name:
            resource_type = "AWS::IAM::AccessKey"
            resource_id = (
                req_params.get("accessKeyId")
                or resp_elements.get("accessKey", {}).get("accessKeyId")
                or "AKIA-PENDING-EXTRACTION"
            )
            details = f"IAM event '{event_name}' on access key '{resource_id}' for user '{target_user}'."
        elif "Policy" in event_name:
            resource_type = "AWS::IAM::Policy"
            resource_id = req_params.get("policyArn") or req_params.get("policyName") or f"policy-{target_user}"
            details = f"IAM policy event '{event_name}' modifying permissions on '{resource_id}'."

    return {
        "event_id": event_id,
        "source_event_id": event_id,
        "event_source": event_source,
        "event_name": event_name,
        "aws_account_id": account_id,
        "aws_region": region,
        "resource_id": resource_id,
        "resource_type": resource_type,
        "user_name": target_user,
        "timestamp": timestamp,
        "details": details,
        "raw_event": raw_body,
    }


def check_s3_bucket_posture(bucket_name: str, s3_client: Optional[Any] = None) -> Dict[str, Any]:
    """
    Read-only inspection of current live AWS S3 security posture.
    Distinguishes between a historical CloudTrail event and verified current exposure.
    Safe read-only call: does not modify any AWS resources.
    """
    if not bucket_name or not isinstance(bucket_name, str):
        return {"status": "ERROR", "message": "Invalid bucket name."}

    if s3_client is None:
        try:
            region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            s3_client = boto3.client("s3", region_name=region)
        except Exception as exc:
            return {"status": "UNAVAILABLE", "message": f"Could not initialize S3 client: {sanitize_message(str(exc))}"}

    posture: Dict[str, Any] = {
        "bucket_name": bucket_name,
        "public_access_block_enforced": False,
        "policy_is_public": False,
        "status": "VERIFIED",
    }

    # Check 1: Public Access Block Configuration
    try:
        pab = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        posture["public_access_block_enforced"] = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
        posture["pab_details"] = cfg
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchPublicAccessBlockConfiguration":
            posture["public_access_block_enforced"] = False
        else:
            posture["pab_error"] = code

    # Check 2: Bucket Policy Status (AWS Policy Status API)
    try:
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        posture["policy_is_public"] = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code != "NoSuchBucketPolicy":
            posture["policy_error"] = code

    return posture


def process_sqs_message(msg: Dict[str, Any], sqs_client: Any, queue_url: str) -> bool:
    """
    Process a single SQS message: parse JSON, normalize, persist to SQLite,
    run background AI threat evaluation, and delete from queue on success.
    """
    receipt_handle = msg.get("ReceiptHandle")
    body_str = msg.get("Body", "")

    try:
        raw_body = json.loads(body_str)
    except json.JSONDecodeError as exc:
        logger.error("Poison pill detected: Unparseable message body. Deleting from queue to avoid block: %s", exc)
        try:
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        except Exception:
            pass
        return False

    # Normalize Event
    incident = normalize_aws_event(raw_body)
    if not incident:
        logger.warning("Unrecognized message schema. Discarding from queue.")
        try:
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        except Exception:
            pass
        return False

    # Persist into Persistent Database
    try:
        record, is_new = insert_or_get_incident(incident)
        eid = incident["event_id"]

        if is_new:
            logger.info("New live incident persisted: [%s] %s on %s", eid, incident["event_name"], incident["resource_id"])
            # Perform asynchronous/inline AI threat analysis
            try:
                analysis = analyze_security_log(incident)
                update_analysis(eid, analysis)
                logger.info("Threat analysis completed for %s: Priority=%s Score=%s/10", eid, analysis.get("priority"), analysis.get("threat_score"))
            except Exception as a_exc:
                logger.warning("AI analysis failed for %s (will remain pending): %s", eid, a_exc)
        else:
            logger.info("Duplicate event [%s] received; skipped redundant insert.", eid)

        # Update heartbeat and operational counters
        set_system_status("last_event_received_at", datetime.now(timezone.utc).isoformat())

        # CRITICAL: Delete from SQS only AFTER successful persistence
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        return True

    except Exception as db_exc:
        # DO NOT delete message on database failure. Allow visibility timeout to expire so SQS retries.
        logger.error("Database persistence failure for event [%s]. Message retained in SQS: %s", incident.get("event_id"), db_exc)
        return False


def run_worker_loop(
    queue_url: Optional[str] = None,
    sqs_client: Optional[Any] = None,
    max_batches: Optional[int] = None,
    poll_wait_seconds: int = 20,
) -> None:
    """
    Main long-polling loop for the ingestion worker.
    Continuously polls SQS queue, updates system status, and processes batches.
    """
    global _SHUTDOWN_REQUESTED

    # Ensure DB is ready
    init_db()

    target_queue = queue_url or os.getenv("SQS_QUEUE_URL", "").strip()
    if not target_queue:
        logger.error("SQS_QUEUE_URL is not configured in environment or arguments. Cannot start live ingestion worker.")
        set_system_status("ingestion_status", "NOT_CONFIGURED")
        return

    if sqs_client is None:
        try:
            region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            sqs_client = boto3.client("sqs", region_name=region)
        except Exception as exc:
            logger.error("Failed to initialize AWS SQS client: %s", sanitize_message(str(exc)))
            set_system_status("ingestion_status", "CLIENT_ERROR")
            return

    logger.info("Starting InfraMind Ingestion Worker...")
    logger.info("Monitoring SQS Queue: %s (Long Poll Timeout: %ss)", target_queue, poll_wait_seconds)
    set_system_status("ingestion_status", "RUNNING")
    set_system_status("sqs_queue_url", target_queue)

    batches_processed = 0

    while not _SHUTDOWN_REQUESTED:
        if max_batches is not None and batches_processed >= max_batches:
            logger.info("Reached maximum batch limit (%s). Terminating loop.", max_batches)
            break

        set_system_status("ingestion_worker_heartbeat", datetime.now(timezone.utc).isoformat())

        try:
            response = sqs_client.receive_message(
                QueueUrl=target_queue,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=poll_wait_seconds,
                VisibilityTimeout=60,
                AttributeNames=["All"],
            )

            messages = response.get("Messages", [])
            if messages:
                logger.info("Received batch of %d message(s) from SQS.", len(messages))
                for msg in messages:
                    if _SHUTDOWN_REQUESTED:
                        break
                    process_sqs_message(msg, sqs_client, target_queue)
            else:
                logger.debug("Long poll returned 0 messages. Waiting for next batch...")

            batches_processed += 1

        except ClientError as c_err:
            code = c_err.response.get("Error", {}).get("Code", "ClientError")
            msg = c_err.response.get("Error", {}).get("Message", str(c_err))
            logger.error("AWS SQS ClientError [%s]: %s. Backing off 10s...", code, sanitize_message(msg))
            set_system_status("ingestion_status", f"ERROR_{code}")
            time.sleep(10.0)
        except BotoCoreError as b_err:
            logger.error("AWS SQS BotoCore connection error: %s. Backing off 10s...", sanitize_message(str(b_err)))
            set_system_status("ingestion_status", "NETWORK_ERROR")
            time.sleep(10.0)
        except Exception as exc:
            logger.error("Unexpected worker exception: %s. Backing off 5s...", sanitize_message(str(exc)))
            time.sleep(5.0)

    logger.info("InfraMind Ingestion Worker terminated cleanly.")
    set_system_status("ingestion_status", "STOPPED")


if __name__ == "__main__":
    run_worker_loop()
