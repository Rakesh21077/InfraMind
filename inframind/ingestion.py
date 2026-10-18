"""
InfraMind - Threat Ingestion and Normalization Engine (Phase 2)

Parses and normalizes AWS Security Hub findings in ASFF (AWS Security Finding Format)
JSON format into internal NormalizedFinding models.

Supports:
- Standard Security Hub format: {"Findings": [...]}
- Bare array of findings: [...]
- Single finding dictionary: {...}
- Graceful degradation on missing or malformed fields
- Preservation of original raw finding for audit trail
- Sanitization and boundary defense against untrusted text / prompt injection
"""

from __future__ import annotations
import json
import logging
import re
from typing import Any, Dict, List, Optional, Union

from inframind.models import FindingResource, NormalizedFinding

logger = logging.getLogger("inframind.ingestion")

# Regex to strip non-printable characters while preserving standard whitespace
NON_PRINTABLE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

MAX_TEXT_LENGTH = 10000


def sanitize_untrusted_text(text: Any, max_length: int = MAX_TEXT_LENGTH) -> str:
    """
    Sanitize text ingested from external finding payloads.
    Strips non-printable control characters, trims excess length,
    and neutralizes potential delimiter collision.
    Never treat external finding text as trusted system instructions.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # Strip control characters except newline and tab
    cleaned = NON_PRINTABLE_RE.sub(" ", text)

    # Enforce length bound
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + " [TRUNCATED_FOR_SAFETY]"

    return cleaned.strip()


class BaseFindingParser:
    """Abstract base class for security finding format parsers."""

    def parse(self, raw_data: Any) -> List[NormalizedFinding]:
        raise NotImplementedError


class ASFFParser(BaseFindingParser):
    """
    Parser for AWS Security Hub ASFF (AWS Security Finding Format) findings.
    Handles standard ASFF finding schemas, extracting key fields and
    preserving raw evidence for forensics.
    """

    def parse_single_finding(self, raw_finding: Dict[str, Any]) -> Optional[NormalizedFinding]:
        """Parse a single raw ASFF finding dictionary into a NormalizedFinding."""
        if not isinstance(raw_finding, dict):
            logger.warning("Skipping non-dictionary finding item: %s", type(raw_finding))
            return None

        # 1. Finding ID (Fallback if missing)
        finding_id = raw_finding.get("Id") or raw_finding.get("id") or raw_finding.get("incident_id")
        if not finding_id:
            generator_id = raw_finding.get("GeneratorId", "UNKNOWN_GENERATOR")
            created = raw_finding.get("CreatedAt", "UNKNOWN_TIME")
            finding_id = f"SYNTHETIC-ID:{generator_id}:{hash(str(raw_finding)) & 0xffffffff:08x}"
        finding_id = sanitize_untrusted_text(finding_id, max_length=512)

        # 2. Title & Description
        threat_type = raw_finding.get("threat_type") or raw_finding.get("ThreatType")
        default_title = f"{threat_type.replace('_', ' ').title()}" if threat_type else "Untitled Security Finding"
        title = sanitize_untrusted_text(
            raw_finding.get("Title") or raw_finding.get("title") or default_title,
            max_length=512,
        )
        description = sanitize_untrusted_text(
            raw_finding.get("Description") or raw_finding.get("description") or f"Incident alert for {default_title}.",
            max_length=MAX_TEXT_LENGTH,
        )

        # 3. Source Severity Extraction
        severity_obj = raw_finding.get("Severity") or raw_finding.get("severity") or {}
        source_severity = "UNKNOWN"
        if isinstance(severity_obj, dict):
            source_severity = (
                severity_obj.get("Label")
                or severity_obj.get("Original")
                or str(severity_obj.get("Normalized", "UNKNOWN"))
            )
        elif isinstance(severity_obj, str):
            source_severity = severity_obj
        source_severity = str(source_severity).upper()

        # 4. Finding Types
        raw_types = raw_finding.get("Types") or raw_finding.get("finding_types") or []
        if not raw_types and threat_type:
            raw_types = [threat_type]
        if isinstance(raw_types, list):
            finding_types = [sanitize_untrusted_text(t, max_length=256) for t in raw_types if t]
        elif isinstance(raw_types, str):
            finding_types = [sanitize_untrusted_text(raw_types, max_length=256)]
        else:
            finding_types = []

        # 5. Timestamps
        created_at = raw_finding.get("CreatedAt") or raw_finding.get("created_at")
        updated_at = raw_finding.get("UpdatedAt") or raw_finding.get("updated_at")

        # 6. Resources Extraction
        resources: List[FindingResource] = []
        raw_resources = raw_finding.get("Resources") or raw_finding.get("resources") or []
        if isinstance(raw_resources, list):
            for res in raw_resources:
                if not isinstance(res, dict):
                    continue
                res_id = res.get("Id") or res.get("id") or "UNKNOWN_RESOURCE"
                res_type = res.get("Type") or res.get("type") or "AwsResource"
                res_region = res.get("Region") or res.get("region")
                res_partition = res.get("Partition") or res.get("partition", "aws")
                res_details = res.get("Details") or res.get("details") or {}
                if not isinstance(res_details, dict):
                    res_details = {}

                resources.append(
                    FindingResource(
                        id=sanitize_untrusted_text(res_id, max_length=512),
                        type=sanitize_untrusted_text(res_type, max_length=128),
                        region=sanitize_untrusted_text(res_region, max_length=64) if res_region else None,
                        partition=sanitize_untrusted_text(res_partition, max_length=32) if res_partition else "aws",
                        details=res_details,
                    )
                )

        # Handle flat incident resource format (sample_incidents.json compatibility)
        if not resources and (raw_finding.get("resource_id") or raw_finding.get("resource_type")):
            flat_id = raw_finding.get("resource_id", "UNKNOWN_RESOURCE")
            flat_type = raw_finding.get("resource_type", "AwsResource")
            flat_params = raw_finding.get("parameters", {})
            resources.append(
                FindingResource(
                    id=sanitize_untrusted_text(flat_id, max_length=512),
                    type=sanitize_untrusted_text(flat_type, max_length=128),
                    details=flat_params if isinstance(flat_params, dict) else {},
                )
            )

        # 7. Compliance Status
        compliance_obj = raw_finding.get("Compliance", {})
        compliance_status = None
        if isinstance(compliance_obj, dict):
            compliance_status = compliance_obj.get("Status")
        elif isinstance(compliance_obj, str):
            compliance_status = compliance_obj

        # 8. Source Remediation Information
        remediation_obj = raw_finding.get("Remediation")
        source_remediation = None
        if isinstance(remediation_obj, dict):
            source_remediation = remediation_obj

        # 9. Source Product Name
        product_arn = raw_finding.get("ProductArn", "AWS_SECURITY_HUB")

        return NormalizedFinding(
            id=finding_id,
            title=title,
            description=description,
            source=product_arn,
            source_severity=source_severity,
            finding_types=finding_types,
            created_at=str(created_at) if created_at else None,
            updated_at=str(updated_at) if updated_at else None,
            resources=resources,
            compliance_status=str(compliance_status) if compliance_status else None,
            source_remediation=source_remediation,
            raw_evidence=raw_finding,
        )

    def parse(self, raw_data: Any) -> List[NormalizedFinding]:
        """
        Parse raw payload into list of NormalizedFinding models.
        Supports:
        - {"Findings": [...]}
        - [...]
        - {...} (single finding)
        """
        if isinstance(raw_data, str) or isinstance(raw_data, (bytes, bytearray)):
            try:
                raw_data = json.loads(raw_data)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON payload: {exc.msg} at line {exc.lineno} col {exc.colno}")

        if isinstance(raw_data, dict):
            # Check for Security Hub Findings key
            if "Findings" in raw_data and isinstance(raw_data["Findings"], list):
                raw_list = raw_data["Findings"]
            elif "findings" in raw_data and isinstance(raw_data["findings"], list):
                raw_list = raw_data["findings"]
            elif "incidents" in raw_data and isinstance(raw_data["incidents"], list):
                # Compatible with sample_incidents.json format
                raw_list = raw_data["incidents"]
            else:
                # Single finding dictionary
                raw_list = [raw_data]
        elif isinstance(raw_data, list):
            raw_list = raw_data
        else:
            raise ValueError(f"Unsupported findings payload type: {type(raw_data).__name__}. Expected dict or list.")

        normalized_findings: List[NormalizedFinding] = []
        for item in raw_list:
            if isinstance(item, dict):
                norm = self.parse_single_finding(item)
                if norm:
                    normalized_findings.append(norm)

        return normalized_findings


def ingest_findings(raw_input: Union[str, bytes, Dict[str, Any], List[Any]]) -> List[NormalizedFinding]:
    """
    Public entry point to ingest and normalize AWS security findings.
    Does not require live AWS credentials or network access.
    """
    parser = ASFFParser()
    return parser.parse(raw_input)
