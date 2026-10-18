"""
Unit Test Suite for ingestion_worker.py
Tests event normalization, SQS long-polling processing, deduplication, and S3 posture inspection.

All tests run completely offline using mocked Boto3 clients.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from database import clear_all_data, get_all_incidents, init_db
from ingestion_worker import (
    check_s3_bucket_posture,
    normalize_aws_event,
    process_sqs_message,
    run_worker_loop,
)


class TestIngestionWorker(unittest.TestCase):
    """Test AWS security event ingestion, message lifecycle, and queue processing."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.test_db_path = self.temp_file.name
        init_db(self.test_db_path)

        # Mock SQS client
        self.mock_sqs = MagicMock()
        self.queue_url = "https://sqs.us-east-1.amazonaws.com/123456789012/InfraMindSecurityEventsQueue"

    def tearDown(self):
        try:
            if os.path.exists(self.test_db_path):
                os.remove(self.test_db_path)
            wal = self.test_db_path + "-wal"
            if os.path.exists(wal):
                os.remove(wal)
        except OSError:
            pass

    def test_normalize_cloudtrail_s3_eventbridge(self):
        """Verify normalization of CloudTrail S3 PutBucketAcl delivered via EventBridge."""
        eb_event = {
            "version": "0",
            "id": "eb-evt-12345",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.s3",
            "account": "123456789012",
            "time": "2026-10-18T10:00:00Z",
            "region": "us-east-1",
            "detail": {
                "eventID": "ct-s3-9999",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketAcl",
                "recipientAccountId": "123456789012",
                "awsRegion": "us-east-1",
                "eventTime": "2026-10-18T10:00:00Z",
                "requestParameters": {
                    "bucketName": "company-financial-backups-2026"
                },
                "userIdentity": {
                    "userName": "cloud-ops-john"
                }
            }
        }
        normalized = normalize_aws_event(eb_event)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["event_id"], "ct-s3-9999")
        self.assertEqual(normalized["event_source"], "s3.amazonaws.com")
        self.assertEqual(normalized["event_name"], "PutBucketAcl")
        self.assertEqual(normalized["resource_id"], "company-financial-backups-2026")
        self.assertEqual(normalized["resource_type"], "AWS::S3::Bucket")
        self.assertEqual(normalized["user_name"], "cloud-ops-john")

    def test_normalize_cloudtrail_iam_event(self):
        """Verify normalization of CloudTrail IAM CreateAccessKey event."""
        iam_event = {
            "version": "0",
            "id": "eb-iam-54321",
            "detail-type": "AWS API Call via CloudTrail",
            "source": "aws.iam",
            "detail": {
                "eventID": "ct-iam-8888",
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateAccessKey",
                "requestParameters": {
                    "userName": "developer-sarah"
                },
                "responseElements": {
                    "accessKey": {
                        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                        "status": "Active"
                    }
                }
            }
        }
        normalized = normalize_aws_event(iam_event)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["event_id"], "ct-iam-8888")
        self.assertEqual(normalized["resource_id"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(normalized["resource_type"], "AWS::IAM::AccessKey")
        self.assertEqual(normalized["user_name"], "developer-sarah")

    def test_normalize_guardduty_finding(self):
        """Verify normalization of Amazon GuardDuty finding event."""
        gd_event = {
            "version": "0",
            "id": "gd-finding-001",
            "detail-type": "GuardDuty Finding",
            "source": "aws.guardduty",
            "account": "123456789012",
            "time": "2026-10-18T11:30:00Z",
            "detail": {
                "id": "gd-finding-001",
                "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
                "severity": 8.0,
                "description": "Credentials were used from an unusual IP address.",
                "resource": {
                    "resourceType": "AccessKey",
                    "accessKeyDetails": {
                        "accessKeyId": "AKIAEXFILTRATEDKEY99",
                        "userName": "compromised-dev"
                    }
                }
            }
        }
        normalized = normalize_aws_event(gd_event)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["event_id"], "gd-finding-001")
        self.assertEqual(normalized["event_source"], "aws.guardduty")
        self.assertEqual(normalized["threat_priority"], "CRITICAL")
        self.assertEqual(normalized["threat_score"], 8)
        self.assertEqual(normalized["resource_id"], "AKIAEXFILTRATEDKEY99")
        self.assertEqual(normalized["user_name"], "compromised-dev")

    def test_process_sqs_message_success_and_delete(self):
        """Verify successful message processing persists incident and deletes from SQS."""
        raw_payload = {
            "version": "0",
            "detail": {
                "eventID": "ct-evt-success-01",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketAcl",
                "requestParameters": {"bucketName": "customer-reports"}
            }
        }
        msg = {
            "ReceiptHandle": "rh-receipt-handle-12345",
            "Body": json.dumps(raw_payload)
        }

        with patch("ingestion_worker.insert_or_get_incident") as mock_insert, \
             patch("ingestion_worker.analyze_security_log") as mock_ai, \
             patch("ingestion_worker.update_analysis"):
            mock_insert.return_value = ({"id": 1, "event_id": "ct-evt-success-01"}, True)
            mock_ai.return_value = {"priority": "CRITICAL", "threat_score": 9}

            success = process_sqs_message(msg, self.mock_sqs, self.queue_url)

            self.assertTrue(success)
            self.mock_sqs.delete_message.assert_called_once_with(
                QueueUrl=self.queue_url,
                ReceiptHandle="rh-receipt-handle-12345"
            )

    def test_process_sqs_message_db_failure_retains_in_queue(self):
        """Verify that on database write failure, message is NOT deleted from SQS (retry/DLQ)."""
        raw_payload = {
            "version": "0",
            "detail": {
                "eventID": "ct-evt-failure-01",
                "eventSource": "s3.amazonaws.com",
                "eventName": "PutBucketAcl",
                "requestParameters": {"bucketName": "customer-reports"}
            }
        }
        msg = {
            "ReceiptHandle": "rh-receipt-handle-retry",
            "Body": json.dumps(raw_payload)
        }

        with patch("ingestion_worker.insert_or_get_incident", side_effect=RuntimeError("Disk I/O Error")):
            success = process_sqs_message(msg, self.mock_sqs, self.queue_url)

            self.assertFalse(success)
            # CRITICAL: Must not delete message on DB error!
            self.mock_sqs.delete_message.assert_not_called()

    def test_poison_pill_unparseable_json_deleted_to_prevent_deadlock(self):
        """Verify invalid non-JSON body is discarded to prevent infinite poison-pill queue block."""
        msg = {
            "ReceiptHandle": "rh-poison-pill",
            "Body": "<<<MALFORMED_NON_JSON_CORRUPT_PAYLOAD>>>"
        }
        success = process_sqs_message(msg, self.mock_sqs, self.queue_url)
        self.assertFalse(success)
        self.mock_sqs.delete_message.assert_called_once()

    def test_check_s3_bucket_posture(self):
        """Verify read-only inspection of S3 bucket posture using mocked client."""
        mock_s3 = MagicMock()
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_policy_status.return_value = {
            "PolicyStatus": {"IsPublic": False}
        }

        posture = check_s3_bucket_posture("safe-production-bucket", mock_s3)
        self.assertEqual(posture["status"], "VERIFIED")
        self.assertTrue(posture["public_access_block_enforced"])
        self.assertFalse(posture["policy_is_public"])


if __name__ == "__main__":
    unittest.main()
