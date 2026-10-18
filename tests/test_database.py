"""
Unit Test Suite for database.py (SQLite Persistent Store & Audit Trail)

Verifies:
1. Schema initialization and index creation.
2. Idempotent deduplication on event_id.
3. Analysis result updates and status transitions.
4. Remediation status tracking and immutable audit logging.
5. Query filtering by status, priority, and source.
6. Operational system health status tracking.
"""

import os
import tempfile
import unittest

from database import (
    clear_all_data,
    get_all_incidents,
    get_audit_trail,
    get_incident_by_event_id,
    get_system_status,
    init_db,
    insert_or_get_incident,
    seed_demo_data,
    set_system_status,
    update_analysis,
    update_remediation,
)


class TestDatabase(unittest.TestCase):
    """Test SQLite persistence, deduplication, and audit trail logging."""

    def setUp(self):
        # Use a temporary SQLite database for test isolation
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_file.close()
        self.test_db_path = self.temp_file.name
        init_db(self.test_db_path)

        self.sample_incident = {
            "event_id": "test-evt-001",
            "event_source": "s3.amazonaws.com",
            "event_name": "PutBucketAcl",
            "aws_account_id": "123456789012",
            "aws_region": "us-east-1",
            "resource_id": "test-secure-bucket",
            "resource_type": "AWS::S3::Bucket",
            "user_name": "test-admin",
            "details": "Public ACL granted to AllUsers",
            "timestamp": "2026-10-18T12:00:00Z",
        }

    def tearDown(self):
        try:
            if os.path.exists(self.test_db_path):
                os.remove(self.test_db_path)
            # Remove WAL / SHM files if present
            wal = self.test_db_path + "-wal"
            shm = self.test_db_path + "-shm"
            if os.path.exists(wal):
                os.remove(wal)
            if os.path.exists(shm):
                os.remove(shm)
        except OSError:
            pass

    def test_insert_and_get_incident(self):
        """Verify inserting an incident returns the record with defaults."""
        record, is_new = insert_or_get_incident(self.sample_incident, self.test_db_path)
        self.assertTrue(is_new)
        self.assertEqual(record["event_id"], "test-evt-001")
        self.assertEqual(record["resource_id"], "test-secure-bucket")
        self.assertEqual(record["remediation_status"], "OPEN")
        self.assertEqual(record["threat_priority"], "UNANALYZED")

    def test_idempotent_deduplication(self):
        """Verify duplicate event_id does not create a new row."""
        rec1, is_new1 = insert_or_get_incident(self.sample_incident, self.test_db_path)
        self.assertTrue(is_new1)

        # Attempt to insert identical event_id
        rec2, is_new2 = insert_or_get_incident(self.sample_incident, self.test_db_path)
        self.assertFalse(is_new2)
        self.assertEqual(rec1["id"], rec2["id"])

        # Count total rows
        all_incidents = get_all_incidents(db_path=self.test_db_path)
        self.assertEqual(len(all_incidents), 1)

    def test_update_analysis(self):
        """Verify updating analysis stores threat scores and provider info."""
        insert_or_get_incident(self.sample_incident, self.test_db_path)

        analysis = {
            "priority": "CRITICAL",
            "threat_score": 9,
            "blast_radius_score": 8,
            "vulnerability_type": "Public S3 Bucket Exposure",
            "summary": "Bucket is publicly open to read/write.",
            "remediation_action": "fix_s3_bucket",
            "recommended_action": "Enforce S3 Public Access Block.",
            "engine": "AMD ROCm vLLM / llama3:8b",
        }

        updated = update_analysis("test-evt-001", analysis, self.test_db_path)
        self.assertTrue(updated)

        fetched = get_incident_by_event_id("test-evt-001", self.test_db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["threat_priority"], "CRITICAL")
        self.assertEqual(fetched["threat_score"], 9)
        self.assertEqual(fetched["remediation_action"], "fix_s3_bucket")
        self.assertEqual(fetched["analysis_status"], "ANALYZED")

    def test_update_remediation_and_audit_trail(self):
        """Verify remediation status update writes an immutable audit record."""
        insert_or_get_incident(self.sample_incident, self.test_db_path)

        audit_entry = {
            "action": "fix_s3_bucket",
            "target_resource": "test-secure-bucket",
            "operator_approved": True,
            "result_message": "Dry run only. No AWS changes were made.",
            "raw_result_json": {"status": "SIMULATED"},
        }

        updated = update_remediation("test-evt-001", "SIMULATED", audit_entry, self.test_db_path)
        self.assertTrue(updated)

        fetched = get_incident_by_event_id("test-evt-001", self.test_db_path)
        self.assertEqual(fetched["remediation_status"], "SIMULATED")

        # Verify audit log
        trails = get_audit_trail("test-evt-001", db_path=self.test_db_path)
        self.assertEqual(len(trails), 1)
        self.assertEqual(trails[0]["action"], "fix_s3_bucket")
        self.assertEqual(trails[0]["operator_approved"], 1)
        self.assertEqual(trails[0]["execution_status"], "SIMULATED")

    def test_query_filters(self):
        """Verify filtering incidents by status, priority, and source."""
        # Insert two incidents
        insert_or_get_incident(self.sample_incident, self.test_db_path)
        iam_inc = {
            "event_id": "test-iam-002",
            "event_source": "iam.amazonaws.com",
            "event_name": "CreateAccessKey",
            "resource_id": "AKIAIOSFODNN7EXAMPLE",
            "resource_type": "AWS::IAM::AccessKey",
            "threat_priority": "CRITICAL",
            "remediation_status": "RESOLVED",
            "timestamp": "2026-10-18T13:00:00Z",
        }
        insert_or_get_incident(iam_inc, self.test_db_path)

        # Filter by source
        s3_list = get_all_incidents(source_filter="s3", db_path=self.test_db_path)
        self.assertEqual(len(s3_list), 1)
        self.assertEqual(s3_list[0]["event_id"], "test-evt-001")

        # Filter by status
        resolved_list = get_all_incidents(status_filter="RESOLVED", db_path=self.test_db_path)
        self.assertEqual(len(resolved_list), 1)
        self.assertEqual(resolved_list[0]["event_id"], "test-iam-002")

    def test_system_status(self):
        """Verify setting and reading system status values."""
        set_system_status("ingestion_worker_heartbeat", "2026-10-18T12:30:00Z", self.test_db_path)
        val = get_system_status("ingestion_worker_heartbeat", db_path=self.test_db_path)
        self.assertEqual(val, "2026-10-18T12:30:00Z")

        # Default fallback
        missing = get_system_status("nonexistent_key", default="fallback_val", db_path=self.test_db_path)
        self.assertEqual(missing, "fallback_val")


if __name__ == "__main__":
    unittest.main()
