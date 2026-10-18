"""
InfraMind - AI Threat Triage Agent & CLI Runner (agent.py)

Command-line runner and Evolus business-agent interface for the AI Threat Triage Engine.
Enables testing against synthetic fixtures, live Ollama inference, or AMD endpoints.

Usage:
  python agent.py                                 # Run against synthetic test findings
  python agent.py --file path/to/findings.json   # Triage specific ASFF JSON file
  python agent.py --mock-llm                      # Offline mode (no Ollama required)
  python agent.py --json                          # Print structured JSON output only
  python agent.py --simulate-remediation          # Preview simulated Boto3 remediation
"""

from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# Ensure inframind package is discoverable
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from inframind import (
    MockInferenceProvider,
    OllamaProvider,
    RemediationBridge,
    ThreatTriageService,
    get_inference_provider,
    triage_findings,
)

load_dotenv(override=False)

# Configure stdout for safe UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logger = logging.getLogger("inframind.agent")


def format_console_report(batch_result: Any, simulate_remediation: bool = False) -> str:
    """Format triage results into an executive terminal summary."""
    lines = []
    lines.append("=" * 80)
    lines.append("[*] InfraMind - AI Cloud Threat Triage & Prioritization Engine")
    lines.append("=" * 80)
    lines.append(f"Total Findings Processed: {batch_result.total_findings}")
    lines.append(f"Priority Breakdown:       {dict(batch_result.counts_by_priority)}")
    lines.append(f"Inference Engine:         {batch_result.provider_info.get('provider')} ({batch_result.provider_info.get('model', 'default')})")
    lines.append(f"Timestamp:                {batch_result.generated_at}")
    lines.append("-" * 80)

    for idx, item in enumerate(batch_result.findings, 1):
        f = item.finding
        a = item.assessment
        e = item.explanation
        res_str = ", ".join(f"{r.type}: {r.id}" for r in f.resources) or "No resources specified"

        lines.append(f"\n[{idx}] PRIORITY: [{a.priority_tier.value}] (Score: {a.score}/100)")
        lines.append(f"    Title:        {f.title}")
        lines.append(f"    Finding ID:   {f.id}")
        lines.append(f"    Source Sev:   {f.source_severity} | Source: {f.source}")
        lines.append(f"    Resources:    {res_str}")
        lines.append(f"    Basis:        {a.basis}")

        if a.observed_facts:
            lines.append("    Observed Facts:")
            for fact in a.observed_facts:
                lines.append(f"      [FACT] {fact}")

        if a.inferred_risks:
            lines.append("    Inferred Risks:")
            for inf in a.inferred_risks:
                lines.append(f"      [RISK] {inf}")

        if a.unknown_information:
            lines.append("    Evidence Gaps (Unknowns):")
            for unk in a.unknown_information:
                lines.append(f"      [GAP]  {unk}")

        lines.append(f"    AI Explanation (LLM Available: {e.is_llm_available}):")
        lines.append(f"      Justification:   {e.priority_justification}")
        lines.append(f"      Business Impact: {e.business_impact_summary}")

        if e.recommended_investigation_steps:
            lines.append("      Investigation Steps:")
            for step in e.recommended_investigation_steps:
                lines.append(f"        -> {step}")

        if e.recommended_action:
            act = e.recommended_action
            lines.append(f"    Recommended Remediation Action:")
            lines.append(f"      Action ID:     {act.action_id}")
            lines.append(f"      Target:        {act.target_resource_id} ({act.target_resource_type})")
            lines.append(f"      Parameters:    {act.parameters}")
            lines.append(f"      Rationale:     {act.rationale}")
            lines.append(f"      Requires Auth: {act.requires_approval}")

            if simulate_remediation:
                sim_res = RemediationBridge.execute(act, approved=False)
                lines.append(f"      [Simulation Result]: {sim_res['status']} -> {sim_res['message']}")

        lines.append("-" * 80)

    lines.append("=" * 80)
    return "\n".join(lines)


def get_default_synthetic_payload() -> Dict[str, Any]:
    """Default synthetic findings payload covering primary scenarios."""
    return {
        "Findings": [
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/s3-public-bucket-001",
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                "GeneratorId": "aws-foundational-security-best-practices/v/1.0.0/S3.1",
                "AwsAccountId": "123456789012",
                "Types": ["Software and Configuration Checks/AWS Security Best Practices/Public"],
                "CreatedAt": "2026-10-18T10:00:00Z",
                "UpdatedAt": "2026-10-18T10:05:00Z",
                "Severity": {"Label": "CRITICAL", "Normalized": 90},
                "Title": "S3.1 S3 Block Public Access setting should be enabled",
                "Description": "Amazon S3 bucket customer-data-archive does not have S3 Block Public Access enabled at the bucket level.",
                "Compliance": {"Status": "FAILED"},
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": "arn:aws:s3:::customer-data-archive",
                        "Region": "us-east-1",
                        "Details": {
                            "AwsS3Bucket": {
                                "PublicAccessBlockConfiguration": {
                                    "BlockPublicAcls": False,
                                    "IgnorePublicAcls": False,
                                    "BlockPublicPolicy": False,
                                    "RestrictPublicBuckets": False,
                                }
                            },
                            "Tags": {"Environment": "production", "Owner": "DataPlatform"},
                        },
                    }
                ],
            },
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/iam-compromised-key-002",
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/guardduty",
                "GeneratorId": "GuardDuty/UnauthorizedAccess:IAMUser/CredentialCompromise",
                "AwsAccountId": "123456789012",
                "Types": ["UnauthorizedAccess:IAMUser/CredentialCompromise"],
                "CreatedAt": "2026-10-18T11:00:00Z",
                "UpdatedAt": "2026-10-18T11:02:00Z",
                "Severity": {"Label": "CRITICAL", "Normalized": 95},
                "Title": "Credentials compromised on public code repository",
                "Description": "AWS IAM Access Key AKIAIOSFODNN7EXAMPLE belonging to user developer-alice was found exposed publicly.",
                "Compliance": {"Status": "FAILED"},
                "Resources": [
                    {
                        "Type": "AwsIamAccessKey",
                        "Id": "arn:aws:iam::123456789012:user/developer-alice/accesskey/AKIAIOSFODNN7EXAMPLE",
                        "Details": {
                            "AwsIamAccessKey": {
                                "UserName": "developer-alice",
                                "Status": "Active",
                            },
                            "UserName": "developer-alice",
                        },
                    }
                ],
            },
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/config-rule-medium-003",
                "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/config",
                "GeneratorId": "config/cloud-trail-encryption-check",
                "AwsAccountId": "123456789012",
                "Types": ["Software and Configuration Checks/Industry Standards/Encryption"],
                "CreatedAt": "2026-10-18T12:00:00Z",
                "Severity": {"Label": "MEDIUM", "Normalized": 40},
                "Title": "CloudTrail log files should be encrypted with KMS CMK",
                "Description": "CloudTrail trail audit-trail is encrypted with default S3-managed keys rather than customer KMS CMK.",
                "Compliance": {"Status": "WARNING"},
                "Resources": [
                    {
                        "Type": "AwsCloudTrailTrail",
                        "Id": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit-trail",
                        "Details": {},
                    }
                ],
            },
        ]
    }


def main():
    parser = argparse.ArgumentParser(
        description="InfraMind AI Threat Triage Engine - CLI Runner & Evolus Interface"
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        help="Path to JSON file containing AWS findings (ASFF format)",
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use offline mock inference provider (no Ollama required)",
    )
    parser.add_argument(
        "--provider",
        type=str,
        choices=["ollama", "amd", "mock"],
        default=None,
        help="Explicitly select inference provider",
    )
    parser.add_argument(
        "--simulate-remediation",
        action="store_true",
        help="Run dry-run remediation simulation for recommended actions",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON result to stdout",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Path to write JSON output result",
    )

    args = parser.parse_args()

    # Determine input payload
    if args.file:
        if not os.path.exists(args.file):
            print(f"Error: Finding file '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            raw_input = f.read()
    else:
        # Check if sample_incidents.json exists or use default synthetic payload
        if os.path.exists("sample_incidents.json") and os.path.getsize("sample_incidents.json") > 0:
            with open("sample_incidents.json", "r", encoding="utf-8") as f:
                raw_input = f.read()
        else:
            raw_input = get_default_synthetic_payload()

    # Determine Provider
    if args.mock_llm or args.provider == "mock":
        provider = MockInferenceProvider()
    elif args.provider == "ollama":
        provider = OllamaProvider()
    elif args.provider == "amd":
        from inframind.inference import AMDvLLMProvider
        provider = AMDvLLMProvider()
    else:
        provider = get_inference_provider()

    # Execute Triage
    service = ThreatTriageService(provider=provider)
    result = service.triage(raw_input)

    # Output Handling
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(format_console_report(result, simulate_remediation=args.simulate_remediation))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))
        print(f"\n[+] Full triage results saved to: {args.output}")


if __name__ == "__main__":
    main()
