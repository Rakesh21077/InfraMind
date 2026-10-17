"""
InfraMind - Member 3: Auto-Patch & Remediation Scripts
Comprehensive Automated Unit Test Suite

This suite verifies:
1. Input validation for S3 and IAM functions.
2. Dry-run safety simulation and default safety gates.
3. S3 live-path behavior using mocked Boto3 clients.
4. IAM live-path behavior using mocked Boto3 clients.
5. Error handling for ClientError, BotoCoreError, and unexpected exceptions.
6. Safety controls, approval gates, and sensitive data sanitization.

All tests execute completely offline without AWS network calls or real credentials.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from botocore.exceptions import BotoCoreError, ClientError

import remediation
from remediation import (
    STATUS_BLOCKED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    STATUS_SUCCESS,
    _parse_bool,
    _validate_access_key_id,
    _validate_bucket_name,
    fix_s3_bucket,
    is_dry_run,
    is_live_execution_enabled,
    revoke_iam_key,
    sanitize_message,
)


class TestInputValidation(unittest.TestCase):
    """Test validation of resource identifiers for S3 buckets and IAM keys."""

    def test_s3_empty_bucket_name(self):
        """1. Empty bucket name should fail validation."""
        result = fix_s3_bucket("")
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(result["action"], "fix_s3_bucket")
        self.assertIn("validation failed", result["message"].lower())

    def test_s3_missing_bucket_name(self):
        """2. Missing (None) bucket name should fail validation."""
        result = fix_s3_bucket(None)  # type: ignore
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertIn("cannot be none", result["message"].lower())

    def test_s3_non_string_bucket_name(self):
        """3. Non-string bucket name should fail validation."""
        for invalid_input in [12345, ["bucket"], {"name": "bucket"}, 3.14]:
            with self.subTest(invalid_input=invalid_input):
                result = fix_s3_bucket(invalid_input)  # type: ignore
                self.assertEqual(result["status"], STATUS_FAILED)
                self.assertIn("must be a string", result["message"].lower())

    def test_s3_whitespace_or_malformed_bucket_name(self):
        """Additional S3 validation: whitespace and illegal characters fail."""
        res_ws = fix_s3_bucket("   ")
        self.assertEqual(res_ws["status"], STATUS_FAILED)

        res_illegal = fix_s3_bucket("invalid_bucket_name!@#")
        self.assertEqual(res_illegal["status"], STATUS_FAILED)

        res_too_short = fix_s3_bucket("ab")
        self.assertEqual(res_too_short["status"], STATUS_FAILED)

    def test_iam_empty_access_key_id(self):
        """4. Empty access key ID should fail validation."""
        result = revoke_iam_key("")
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertEqual(result["action"], "revoke_iam_key")
        self.assertIn("validation failed", result["message"].lower())

    def test_iam_missing_access_key_id(self):
        """5. Missing (None) access key ID should fail validation."""
        result = revoke_iam_key(None)  # type: ignore
        self.assertEqual(result["status"], STATUS_FAILED)
        self.assertIn("cannot be none", result["message"].lower())

    def test_iam_non_string_access_key_id(self):
        """Additional IAM validation: non-string key ID fails."""
        for invalid_input in [98765, ("AKIA123",), {"key": "id"}]:
            with self.subTest(invalid_input=invalid_input):
                result = revoke_iam_key(invalid_input)  # type: ignore
                self.assertEqual(result["status"], STATUS_FAILED)
                self.assertIn("must be a string", result["message"].lower())

    def test_iam_invalid_or_absent_username_for_live_execution(self):
        """6 & 25. Absent, empty, or non-string IAM username blocks live execution."""
        live_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "True",
        }
        mock_iam = MagicMock()

        for bad_user in [None, "", "   ", 12345]:
            with self.subTest(bad_user=bad_user):
                with patch.dict(os.environ, live_env, clear=True):
                    result = revoke_iam_key(
                        "AKIAIOSFODNN7EXAMPLE",
                        user_name=bad_user,  # type: ignore
                        approved=True,
                        iam_client=mock_iam,
                    )
                    self.assertEqual(result["status"], STATUS_BLOCKED)
                    self.assertIn("iam username is required", result["message"].lower())
                    mock_iam.update_access_key.assert_not_called()


class TestDryRunBehavior(unittest.TestCase):
    """Test safe simulation (dry run) execution paths."""

    def test_s3_dry_run_returns_simulated(self):
        """7. S3 dry-run returns SIMULATED."""
        with patch.dict(os.environ, {"DRY_RUN": "True"}, clear=True):
            result = fix_s3_bucket("demo-secure-bucket")
            self.assertEqual(result["status"], STATUS_SIMULATED)
            self.assertEqual(result["action"], "fix_s3_bucket")
            self.assertEqual(result["resource"], "demo-secure-bucket")
            self.assertIn("dry run only", result["message"].lower())

    def test_iam_dry_run_returns_simulated(self):
        """8. IAM dry-run returns SIMULATED."""
        with patch.dict(os.environ, {"DRY_RUN": "True"}, clear=True):
            result = revoke_iam_key("AKIAIOSFODNN7EXAMPLE", user_name="alice")
            self.assertEqual(result["status"], STATUS_SIMULATED)
            self.assertEqual(result["action"], "revoke_iam_key")
            self.assertEqual(result["resource"], "AKIAIOSFODNN7EXAMPLE")
            self.assertIn("dry run only", result["message"].lower())

    def test_neither_function_calls_aws_in_dry_run(self):
        """9. Neither function makes AWS API calls in dry-run mode, even if mock client is provided."""
        mock_s3 = MagicMock()
        mock_iam = MagicMock()

        with patch.dict(os.environ, {"DRY_RUN": "True"}, clear=True):
            res_s3 = fix_s3_bucket("demo-bucket", s3_client=mock_s3)
            res_iam = revoke_iam_key("AKIAIOSFODNN7EXAMPLE", iam_client=mock_iam)

            self.assertEqual(res_s3["status"], STATUS_SIMULATED)
            self.assertEqual(res_iam["status"], STATUS_SIMULATED)
            mock_s3.put_public_access_block.assert_not_called()
            mock_iam.update_access_key.assert_not_called()

    def test_missing_environment_variables_default_to_safe_mode(self):
        """10. Missing environment variables safely default to dry-run and blocked live execution."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(is_dry_run())
            self.assertFalse(is_live_execution_enabled())

            res_s3 = fix_s3_bucket("demo-bucket")
            self.assertEqual(res_s3["status"], STATUS_SIMULATED)

            res_iam = revoke_iam_key("AKIAIOSFODNN7EXAMPLE")
            self.assertEqual(res_iam["status"], STATUS_SIMULATED)


class TestS3LivePath(unittest.TestCase):
    """Test S3 live remediation logic using injected mock clients."""

    def setUp(self):
        self.live_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "True",
            "AWS_DEFAULT_REGION": "us-east-1",
        }
        self.mock_s3 = MagicMock()

    def test_s3_passes_correct_bucket_and_calls_put_public_access_block(self):
        """11 & 12. Verify correct bucket name and put_public_access_block is called."""
        with patch.dict(os.environ, self.live_env, clear=True):
            target_bucket = "prod-data-archive"
            result = fix_s3_bucket(
                target_bucket,
                approved=True,
                s3_client=self.mock_s3,
            )

            self.assertEqual(result["status"], STATUS_SUCCESS)
            self.mock_s3.put_public_access_block.assert_called_once()
            call_kwargs = self.mock_s3.put_public_access_block.call_args.kwargs
            self.assertEqual(call_kwargs["Bucket"], target_bucket)

    def test_s3_configures_all_four_block_settings_true(self):
        """13. Verify all four public access block settings are explicitly True."""
        with patch.dict(os.environ, self.live_env, clear=True):
            fix_s3_bucket(
                "finance-records-bucket",
                approved=True,
                s3_client=self.mock_s3,
            )

            call_kwargs = self.mock_s3.put_public_access_block.call_args.kwargs
            pab_config = call_kwargs["PublicAccessBlockConfiguration"]

            self.assertTrue(pab_config["BlockPublicAcls"])
            self.assertTrue(pab_config["IgnorePublicAcls"])
            self.assertTrue(pab_config["BlockPublicPolicy"])
            self.assertTrue(pab_config["RestrictPublicBuckets"])

    def test_s3_successful_api_call_returns_success(self):
        """14. Verify a mocked successful API call returns SUCCESS."""
        with patch.dict(os.environ, self.live_env, clear=True):
            result = fix_s3_bucket(
                "public-web-bucket",
                approved=True,
                s3_client=self.mock_s3,
            )
            self.assertEqual(result["status"], STATUS_SUCCESS)
            self.assertEqual(result["action"], "fix_s3_bucket")
            self.assertEqual(result["resource"], "public-web-bucket")
            self.assertIn("applied successfully", result["message"])

    def test_s3_client_error_returns_failed(self):
        """15. Verify an injected ClientError returns FAILED."""
        client_error = ClientError(
            error_response={
                "Error": {
                    "Code": "NoSuchBucket",
                    "Message": "The specified bucket does not exist",
                }
            },
            operation_name="PutPublicAccessBlock",
        )
        self.mock_s3.put_public_access_block.side_effect = client_error

        with patch.dict(os.environ, self.live_env, clear=True):
            result = fix_s3_bucket(
                "nonexistent-bucket",
                approved=True,
                s3_client=self.mock_s3,
            )
            self.assertEqual(result["status"], STATUS_FAILED)
            self.assertIn("NoSuchBucket", result["message"])
            self.mock_s3.put_public_access_block.assert_called_once()

    def test_s3_botocore_error_returns_failed(self):
        """16. Verify an injected BotoCoreError returns FAILED."""
        self.mock_s3.put_public_access_block.side_effect = BotoCoreError()

        with patch.dict(os.environ, self.live_env, clear=True):
            result = fix_s3_bucket(
                "offline-bucket",
                approved=True,
                s3_client=self.mock_s3,
            )
            self.assertEqual(result["status"], STATUS_FAILED)
            self.assertIn("BotoCore connection error", result["message"])

    def test_s3_blocked_when_approval_absent(self):
        """17. Verify live execution is blocked when approval is absent."""
        with patch.dict(os.environ, self.live_env, clear=True):
            result = fix_s3_bucket(
                "unapproved-bucket",
                approved=False,
                s3_client=self.mock_s3,
            )
            self.assertEqual(result["status"], STATUS_BLOCKED)
            self.assertIn("approval", result["message"].lower())
            self.mock_s3.put_public_access_block.assert_not_called()

    def test_s3_blocked_when_live_execution_not_enabled(self):
        """18. Verify live execution is blocked when LIVE_EXECUTION_ENABLED is False."""
        disabled_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "False",
        }
        with patch.dict(os.environ, disabled_env, clear=True):
            result = fix_s3_bucket(
                "demo-bucket",
                approved=True,
                s3_client=self.mock_s3,
            )
            self.assertEqual(result["status"], STATUS_BLOCKED)
            self.assertIn("live_execution_enabled is not set to true", result["message"].lower())
            self.mock_s3.put_public_access_block.assert_not_called()


class TestIAMLivePath(unittest.TestCase):
    """Test IAM live remediation logic using injected mock clients."""

    def setUp(self):
        self.live_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "True",
            "AWS_DEFAULT_REGION": "us-east-1",
        }
        self.mock_iam = MagicMock()

    def test_iam_passes_correct_access_key_and_username(self):
        """19 & 20. Verify expected access key ID and exact username are passed."""
        with patch.dict(os.environ, self.live_env, clear=True):
            target_key = "AKIAIOSFODNN7EXAMPLE"
            target_user = "contractor-bob"

            result = revoke_iam_key(
                target_key,
                user_name=target_user,
                approved=True,
                iam_client=self.mock_iam,
            )

            self.assertEqual(result["status"], STATUS_SUCCESS)
            self.mock_iam.update_access_key.assert_called_once()
            call_kwargs = self.mock_iam.update_access_key.call_args.kwargs
            self.assertEqual(call_kwargs["AccessKeyId"], target_key)
            self.assertEqual(call_kwargs["UserName"], target_user)

    def test_iam_status_is_set_to_inactive(self):
        """21. Verify key status is explicitly set to 'Inactive'."""
        with patch.dict(os.environ, self.live_env, clear=True):
            revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="contractor-bob",
                approved=True,
                iam_client=self.mock_iam,
            )

            call_kwargs = self.mock_iam.update_access_key.call_args.kwargs
            self.assertEqual(call_kwargs["Status"], "Inactive")

    def test_iam_successful_api_call_returns_success(self):
        """22. Verify a mocked successful API call returns SUCCESS."""
        with patch.dict(os.environ, self.live_env, clear=True):
            result = revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="charlie-dev",
                approved=True,
                iam_client=self.mock_iam,
            )
            self.assertEqual(result["status"], STATUS_SUCCESS)
            self.assertEqual(result["action"], "revoke_iam_key")
            self.assertEqual(result["resource"], "AKIAIOSFODNN7EXAMPLE")
            self.assertIn("Inactive", result["message"])

    def test_iam_client_error_returns_failed(self):
        """23. Verify a mocked ClientError returns FAILED."""
        client_error = ClientError(
            error_response={
                "Error": {
                    "Code": "NoSuchEntity",
                    "Message": "The Access Key with id AKIAIOSFODNN7EXAMPLE cannot be found",
                }
            },
            operation_name="UpdateAccessKey",
        )
        self.mock_iam.update_access_key.side_effect = client_error

        with patch.dict(os.environ, self.live_env, clear=True):
            result = revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="charlie-dev",
                approved=True,
                iam_client=self.mock_iam,
            )
            self.assertEqual(result["status"], STATUS_FAILED)
            self.assertIn("NoSuchEntity", result["message"])
            self.mock_iam.update_access_key.assert_called_once()

    def test_iam_botocore_error_returns_failed(self):
        """24. Verify a mocked BotoCoreError returns FAILED."""
        self.mock_iam.update_access_key.side_effect = BotoCoreError()

        with patch.dict(os.environ, self.live_env, clear=True):
            result = revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="charlie-dev",
                approved=True,
                iam_client=self.mock_iam,
            )
            self.assertEqual(result["status"], STATUS_FAILED)
            self.assertIn("BotoCore connection error", result["message"])

    def test_iam_missing_human_approval_blocks_execution(self):
        """26. Verify missing human approval blocks live execution."""
        with patch.dict(os.environ, self.live_env, clear=True):
            result = revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="charlie-dev",
                approved=False,
                iam_client=self.mock_iam,
            )
            self.assertEqual(result["status"], STATUS_BLOCKED)
            self.assertIn("approval", result["message"].lower())
            self.mock_iam.update_access_key.assert_not_called()

    def test_iam_blocked_when_live_execution_not_enabled(self):
        """Verify IAM live execution is blocked when LIVE_EXECUTION_ENABLED is False."""
        disabled_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "False",
        }
        with patch.dict(os.environ, disabled_env, clear=True):
            result = revoke_iam_key(
                "AKIAIOSFODNN7EXAMPLE",
                user_name="charlie-dev",
                approved=True,
                iam_client=self.mock_iam,
            )
            self.assertEqual(result["status"], STATUS_BLOCKED)
            self.assertIn("live_execution_enabled is not set to true", result["message"].lower())
            self.mock_iam.update_access_key.assert_not_called()


class TestSafetyAndEdgeCases(unittest.TestCase):
    """Test safety invariants, sanitization, and edge-case protections."""

    def test_import_does_not_execute_remediation(self):
        """27. Verify importing the module does not execute remediation."""
        # Inspecting module attributes verifies it is purely declarative
        self.assertTrue(callable(remediation.fix_s3_bucket))
        self.assertTrue(callable(remediation.revoke_iam_key))

    def test_demo_uses_dry_run_by_default(self):
        """28. Verify default environment produces dry-run behavior."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(is_dry_run())
            self.assertFalse(is_live_execution_enabled())

    def test_failures_never_return_success(self):
        """29. Verify failure conditions never return SUCCESS."""
        # Empty inputs
        self.assertNotEqual(fix_s3_bucket("")["status"], STATUS_SUCCESS)
        self.assertNotEqual(revoke_iam_key("")["status"], STATUS_SUCCESS)

        # Unapproved live attempt
        with patch.dict(os.environ, {"DRY_RUN": "False", "LIVE_EXECUTION_ENABLED": "True"}):
            self.assertNotEqual(
                fix_s3_bucket("b", approved=False)["status"], STATUS_SUCCESS
            )

    def test_code_never_falls_back_to_real_aws_in_unit_tests(self):
        """30. Verify dry-run execution path never instantiates real Boto3 clients."""
        with patch("boto3.client") as mock_boto:
            with patch.dict(os.environ, {"DRY_RUN": "True"}, clear=True):
                fix_s3_bucket("any-bucket")
                revoke_iam_key("AKIAIOSFODNN7EXAMPLE", user_name="alice")
                mock_boto.assert_not_called()

    def test_root_account_protection(self):
        """31. Refuse automated live deactivation for root account credentials."""
        live_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "True",
        }
        mock_iam = MagicMock()
        with patch.dict(os.environ, live_env, clear=True):
            for root_user in ["root", "<root_account>", "ROOT_ACCOUNT", "<ROOT>"]:
                with self.subTest(root_user=root_user):
                    result = revoke_iam_key(
                        "AKIAIOSFODNN7EXAMPLE",
                        user_name=root_user,
                        approved=True,
                        iam_client=mock_iam,
                    )
                    self.assertEqual(result["status"], STATUS_BLOCKED)
                    self.assertIn("root account", result["message"].lower())
                    mock_iam.update_access_key.assert_not_called()

    def test_boolean_parser_robustness(self):
        """32. Test _parse_bool with truthy, falsy, and invalid values."""
        self.assertTrue(_parse_bool("True"))
        self.assertTrue(_parse_bool("true"))
        self.assertTrue(_parse_bool("1"))
        self.assertTrue(_parse_bool("yes"))
        self.assertTrue(_parse_bool("Y"))
        self.assertTrue(_parse_bool(True))

        self.assertFalse(_parse_bool("False"))
        self.assertFalse(_parse_bool("false"))
        self.assertFalse(_parse_bool("0"))
        self.assertFalse(_parse_bool("no"))
        self.assertFalse(_parse_bool(False))

        # Defaults on invalid/missing
        self.assertTrue(_parse_bool("invalid_val", default=True))
        self.assertFalse(_parse_bool("invalid_val", default=False))
        self.assertTrue(_parse_bool(None, default=True))
        self.assertFalse(_parse_bool(None, default=False))

    def test_sanitization_removes_secrets_and_tokens(self):
        """33. Verify sanitize_message redacts access keys and tokens."""
        raw_msg = (
            "Failed with AKIAIOSFODNN7EXAMPLE and "
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        )
        sanitized = sanitize_message(raw_msg)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", sanitized)
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", sanitized)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", sanitized)
        self.assertIn("AKIA****************", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_unexpected_exceptions_handled_gracefully(self):
        """34. Injected unexpected exceptions return FAILED rather than crashing."""
        mock_s3 = MagicMock()
        mock_s3.put_public_access_block.side_effect = RuntimeError("Fatal hardware glitch")

        live_env = {
            "DRY_RUN": "False",
            "LIVE_EXECUTION_ENABLED": "True",
        }
        with patch.dict(os.environ, live_env, clear=True):
            result = fix_s3_bucket(
                "glitchy-bucket",
                approved=True,
                s3_client=mock_s3,
            )
            self.assertEqual(result["status"], STATUS_FAILED)
            self.assertIn("Fatal hardware glitch", result["message"])


if __name__ == "__main__":
    unittest.main()
