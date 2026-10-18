"""
InfraMind - AI Threat Detection & Analysis Engine (Member 2 Module)
AI Cloud Security Guardrail for Startups & IT

This module provides AI-driven log analysis and an incident history conversational assistant:
1. analyze_security_log(log_event): Ingests a raw cloud security event, evaluates threat severity,
   calculates blast radius estimates, and recommends targeted remediation actions.
2. ask_incident_history(question, logs, analyses): Answers natural-language operator questions
   concerning ingested logs, active incidents, remediation statuses, and threat metrics.

Hardware & Model Connectivity:
- Primary: AMD ROCm vLLM / OpenAI-compatible API endpoint (configured via AMD_ENDPOINT_URL & MODEL_NAME).
- Local Alternative: Local Ollama endpoint (e.g. http://localhost:11434/v1).
- Offline Resiliency: Deterministic rule-based fallback when model endpoints are unreachable or timeout.
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load local environment configuration without overwriting active runtime vars
load_dotenv(override=False)

logger = logging.getLogger("inframind.agent")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [InfraMind-Agent] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Validated Constants
VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_REMEDIATIONS = {"fix_s3_bucket", "revoke_iam_key", "none"}


def get_llm_config() -> Dict[str, str]:
    """Retrieve active LLM endpoint configuration from environment variables."""
    endpoint_url = os.getenv("AMD_ENDPOINT_URL", "http://localhost:11434/v1").strip()
    model_name = os.getenv("MODEL_NAME", "llama3:8b").strip()
    return {
        "endpoint_url": endpoint_url,
        "model_name": model_name,
    }


def _deterministic_analysis(log_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic rule-based analysis engine used as an instant offline fallback
    when LLM endpoints are unreachable, unconfigured, or timed out.
    """
    event_id = str(log_event.get("event_id", "evt-unknown"))
    event_source = str(log_event.get("event_source", "")).lower()
    event_name = str(log_event.get("event_name", "")).lower()
    resource_id = str(log_event.get("resource_id", "unknown-resource"))
    resource_type = str(log_event.get("resource_type", "")).lower()
    details = str(log_event.get("details", "")).lower()
    user_name = log_event.get("user_name") or log_event.get("user_identity", {}).get("user_name", "")

    # Scenario 1: S3 Public Bucket Exposure
    if (
        "s3" in event_source
        or "s3" in resource_type
        or "putbucketacl" in event_name
        or "putbucketpolicy" in event_name
        or "bucket" in details
    ):
        if any(term in details for term in ["public-read", "public-write", "allusers", "*", "wildcard", "unrestricted"]):
            return {
                "event_id": event_id,
                "priority": "CRITICAL",
                "threat_score": 9,
                "vulnerability_type": "Public S3 Bucket Exposure",
                "summary": (
                    f"Amazon S3 bucket '{resource_id}' was exposed with public access permissions. "
                    "Anonymous global read/write access enables immediate data exfiltration and tampering."
                ),
                "blast_radius_score": 8,
                "remediation_action": "fix_s3_bucket",
                "resource_id": resource_id,
                "recommended_action": f"Apply AWS S3 Public Access Block to bucket '{resource_id}'.",
                "engine": "Offline Fallback (Deterministic Rule-Based)",
                "status": "ANALYZED",
            }
        else:
            return {
                "event_id": event_id,
                "priority": "HIGH",
                "threat_score": 7,
                "vulnerability_type": "S3 Bucket Configuration Anomaly",
                "summary": f"S3 bucket '{resource_id}' access control settings were modified.",
                "blast_radius_score": 6,
                "remediation_action": "fix_s3_bucket",
                "resource_id": resource_id,
                "recommended_action": f"Verify public access block on bucket '{resource_id}'.",
                "engine": "Offline Fallback (Deterministic Rule-Based)",
                "status": "ANALYZED",
            }

    # Scenario 2: Compromised IAM Access Key
    if (
        "iam" in event_source
        or "iam" in resource_type
        or "accesskey" in event_name
        or "key" in details
        or resource_id.startswith("AKIA")
        or resource_id.startswith("ASIA")
    ):
        target_user = user_name if user_name else "associated-user"
        return {
            "event_id": event_id,
            "priority": "CRITICAL",
            "threat_score": 10,
            "vulnerability_type": "Compromised IAM Access Key",
            "summary": (
                f"Active IAM Access Key '{resource_id}' for user '{target_user}' was exposed in public telemetry "
                "or triggered anomalous usage. Immediate credential revocation required to prevent account takeover."
            ),
            "blast_radius_score": 9,
            "remediation_action": "revoke_iam_key",
            "resource_id": resource_id,
            "user_name": target_user,
            "recommended_action": f"Deactivate IAM access key '{resource_id}' for user '{target_user}'.",
            "engine": "Offline Fallback (Deterministic Rule-Based)",
            "status": "ANALYZED",
        }

    # Default / Generic Cloud Event
    return {
        "event_id": event_id,
        "priority": "MEDIUM",
        "threat_score": 5,
        "vulnerability_type": "Cloud Configuration Anomaly",
        "summary": f"Cloud security event '{event_name}' logged for resource '{resource_id}'.",
        "blast_radius_score": 4,
        "remediation_action": "none",
        "resource_id": resource_id,
        "recommended_action": "Review CloudTrail logs and audit affected resource permissions.",
        "engine": "Offline Fallback (Deterministic Rule-Based)",
        "status": "ANALYZED",
    }


def _validate_and_sanitize_analysis(raw: Dict[str, Any], log_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure the LLM response strictly satisfies schema constraints, valid types,
    and maps only to safe whitelisted remediation actions.
    """
    event_id = str(log_event.get("event_id", raw.get("event_id", "evt-unknown")))
    resource_id = str(log_event.get("resource_id", raw.get("resource_id", "unknown-resource")))
    user_name = log_event.get("user_name") or log_event.get("user_identity", {}).get("user_name", "")

    # Priority Validation
    priority = str(raw.get("priority", "MEDIUM")).upper().strip()
    if priority not in VALID_PRIORITIES:
        priority = "HIGH"

    # Threat Score Validation (0 to 10)
    try:
        threat_score = int(raw.get("threat_score", 5))
        threat_score = max(0, min(10, threat_score))
    except (ValueError, TypeError):
        threat_score = 7

    # Blast Radius Score Validation (0 to 10)
    try:
        blast_radius_score = int(raw.get("blast_radius_score", 5))
        blast_radius_score = max(0, min(10, blast_radius_score))
    except (ValueError, TypeError):
        blast_radius_score = 6

    # Remediation Action Validation (Whitelist)
    remediation_action = str(raw.get("remediation_action", "none")).strip().lower()
    if remediation_action not in VALID_REMEDIATIONS:
        # Fallback mapping based on source log
        if "s3" in str(log_event.get("event_source", "")).lower() or "bucket" in resource_id.lower():
            remediation_action = "fix_s3_bucket"
        elif "iam" in str(log_event.get("event_source", "")).lower() or resource_id.startswith("AKIA"):
            remediation_action = "revoke_iam_key"
        else:
            remediation_action = "none"

    summary = str(raw.get("summary", f"Security incident analyzed for resource {resource_id}.")).strip()
    vulnerability_type = str(raw.get("vulnerability_type", "Cloud Security Threat")).strip()
    recommended_action = str(raw.get("recommended_action", f"Execute {remediation_action} to mitigate threat.")).strip()

    result: Dict[str, Any] = {
        "event_id": event_id,
        "priority": priority,
        "threat_score": threat_score,
        "vulnerability_type": vulnerability_type,
        "summary": summary,
        "blast_radius_score": blast_radius_score,
        "remediation_action": remediation_action,
        "resource_id": resource_id,
        "recommended_action": recommended_action,
        "engine": raw.get("engine", "AMD ROCm vLLM / OpenAI API"),
        "status": "ANALYZED",
    }
    if user_name:
        result["user_name"] = str(user_name).strip()

    return result


def analyze_security_log(log_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze an ingested cloud security event to determine threat severity,
    blast radius impact, and recommended automated remediation.

    Attempts inference via the configured AMD GPU endpoint (or local Ollama).
    Falls back gracefully to a deterministic rule-based analysis if the model
    is unavailable, unresponsive, or returns malformed output.

    Parameters:
      log_event (dict): The cloud security event object.

    Returns:
      dict: Structured analysis containing priority, scores, summary, and action.
    """
    if not isinstance(log_event, dict) or not log_event:
        logger.warning("Invalid log_event passed to analyze_security_log: %s", type(log_event))
        return {
            "event_id": "evt-invalid",
            "priority": "LOW",
            "threat_score": 0,
            "vulnerability_type": "Invalid Event Data",
            "summary": "Log event payload was empty or not a valid dictionary.",
            "blast_radius_score": 0,
            "remediation_action": "none",
            "resource_id": "unknown",
            "recommended_action": "Verify log ingestion format.",
            "engine": "Validation Guard",
            "status": "FAILED",
        }

    config = get_llm_config()
    endpoint_url = config["endpoint_url"]
    model_name = config["model_name"]

    # System instruction prompting for strict JSON output
    system_prompt = (
        "You are InfraMind AI, an expert AWS cloud security engineer. "
        "Analyze the provided cloud security log event. "
        "Return a strictly valid JSON object with EXACTLY these keys:\n"
        "{\n"
        '  "event_id": "<event_id>",\n'
        '  "priority": "<CRITICAL|HIGH|MEDIUM|LOW>",\n'
        '  "threat_score": <integer 0-10>,\n'
        '  "vulnerability_type": "<concise title>",\n'
        '  "summary": "<clear 1-2 sentence risk explanation>",\n'
        '  "blast_radius_score": <integer 0-10>,\n'
        '  "remediation_action": "<fix_s3_bucket|revoke_iam_key|none>",\n'
        '  "resource_id": "<exact resource_id from event>",\n'
        '  "recommended_action": "<action description>"\n'
        "}\n"
        "Do NOT return markdown formatting or extra text. Only raw JSON."
    )

    user_prompt = f"Security Log Event:\n{json.dumps(log_event, indent=2)}"

    try:
        from openai import OpenAI

        client = OpenAI(
            base_url=endpoint_url,
            api_key=os.getenv("OPENAI_API_KEY", "dummy-amd-key"),
            timeout=3.0,  # Fast failover to prevent UI latency
        )

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=500,
        )

        content = response.choices[0].message.content or ""
        # Clean any markdown code blocks if the model enclosed JSON in ```json ... ```
        cleaned_content = re.sub(r"^```(?:json)?\s*", "", content.strip(), flags=re.MULTILINE)
        cleaned_content = re.sub(r"```\s*$", "", cleaned_content, flags=re.MULTILINE).strip()

        raw_json = json.loads(cleaned_content)
        raw_json["engine"] = f"AMD ROCm vLLM / {model_name}"
        logger.info("Successfully analyzed %s using %s", log_event.get("event_id"), raw_json["engine"])
        return _validate_and_sanitize_analysis(raw_json, log_event)

    except Exception as exc:
        logger.info(
            "Model endpoint (%s) unavailable or failed: %s. Using deterministic fallback.",
            endpoint_url,
            str(exc),
        )
        return _deterministic_analysis(log_event)


def ask_incident_history(
    question: str,
    logs: List[Dict[str, Any]],
    analyses: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
    """
    Interactive natural language Q&A assistant over loaded security logs and prior analyses.

    If an LLM endpoint is reachable, dispatches the prompt with incident context.
    Otherwise, executes a high-fidelity deterministic query processor capable of answering
    all standard operational audit queries.

    Parameters:
      question (str): Operator natural language inquiry.
      logs (list): Ingested log events.
      analyses (dict, optional): Map of event_id to analysis result dictionary.

    Returns:
      str: Formatted markdown answer.
    """
    if not question or not question.strip():
        return "Please ask a question about your security logs or incident history."

    q_lower = question.lower().strip()
    analyses = analyses or {}

    # Attempt LLM Assistant if reachable
    config = get_llm_config()
    try:
        from openai import OpenAI

        client = OpenAI(
            base_url=config["endpoint_url"],
            api_key=os.getenv("OPENAI_API_KEY", "dummy-amd-key"),
            timeout=4.0,
        )

        context_summary = []
        for log in logs:
            eid = log.get("event_id", "")
            analysis = analyses.get(eid, {})
            context_summary.append({
                "event_id": eid,
                "timestamp": log.get("timestamp"),
                "event_name": log.get("event_name"),
                "resource_id": log.get("resource_id"),
                "user_name": log.get("user_name") or log.get("user_identity", {}).get("user_name"),
                "priority": analysis.get("priority", "UNANALYZED"),
                "threat_score": analysis.get("threat_score"),
                "remediation_action": analysis.get("remediation_action"),
                "status": log.get("remediation_status", "OPEN"),
            })

        system_msg = (
            "You are InfraMind Incident Time-Machine, an AI security auditing assistant. "
            "Answer the operator question accurately based ONLY on the provided incident logs. "
            "Never fabricate incidents or credentials."
        )

        response = client.chat.completions.create(
            model=config["model_name"],
            messages=[
                {"role": "system", "content": system_msg},
                {
                    "role": "user",
                    "content": f"Incident Data:\n{json.dumps(context_summary, indent=2)}\n\nQuestion: {question}",
                },
            ],
            temperature=0.2,
            max_tokens=600,
        )
        return response.choices[0].message.content or "No response from AI assistant."

    except Exception:
        # Graceful Deterministic Fallback Assistant
        return _deterministic_chat_response(q_lower, logs, analyses)


def _deterministic_chat_response(
    q: str,
    logs: List[Dict[str, Any]],
    analyses: Dict[str, Dict[str, Any]],
) -> str:
    """
    Deterministic rule-based query solver for the Incident Time-Machine assistant.
    Guarantees accurate answers without requiring an active external LLM server.
    """
    if not logs:
        return "No security logs are currently loaded into InfraMind. Please load or upload incident logs."

    # Query 1: API keys / credentials flagged
    if any(k in q for k in ["api key", "access key", "keys flagged", "iam key", "credential"]):
        key_incidents = [
            log for log in logs
            if "iam" in str(log.get("event_source", "")).lower()
            or str(log.get("resource_id", "")).startswith("AKIA")
            or "accesskey" in str(log.get("event_name", "")).lower()
        ]
        if not key_incidents:
            return "No compromised IAM access keys were identified in the loaded logs."

        lines = ["### 🔑 Flagged IAM Access Keys\n"]
        for log in key_incidents:
            eid = log.get("event_id")
            key_id = log.get("resource_id")
            user = log.get("user_name") or log.get("user_identity", {}).get("user_name", "Unknown")
            status = log.get("remediation_status", "OPEN")
            lines.append(f"- **Event `{eid}`**: Access Key `{key_id}` (User: `{user}`) — Status: **{status}**")
            lines.append(f"  *Reason*: {log.get('details', 'Suspicious activity detected.')}")
        return "\n".join(lines)

    # Query 2: Critical / High priority incidents
    if any(k in q for k in ["critical", "high priority", "most dangerous", "highest risk"]):
        crit_lines = ["### 🚨 Critical & High Priority Incidents\n"]
        found = False
        for log in logs:
            eid = log.get("event_id")
            analysis = analyses.get(eid, _deterministic_analysis(log))
            if analysis.get("priority") in ("CRITICAL", "HIGH"):
                found = True
                crit_lines.append(
                    f"- **`{eid}`** [{analysis.get('priority')} | Score: {analysis.get('threat_score')}/10]: "
                    f"**{analysis.get('vulnerability_type')}** on `{analysis.get('resource_id')}`\n"
                    f"  *{analysis.get('summary')}*"
                )
        if not found:
            return "No critical or high-severity incidents are currently flagged in the records."
        return "\n".join(crit_lines)

    # Query 3: S3 bucket questions
    if any(k in q for k in ["s3", "bucket", "storage"]):
        s3_incidents = [
            log for log in logs
            if "s3" in str(log.get("event_source", "")).lower()
            or "bucket" in str(log.get("resource_type", "")).lower()
            or "bucket" in str(log.get("resource_id", "")).lower()
        ]
        if not s3_incidents:
            return "No S3 bucket incidents were identified in the loaded log records."

        lines = ["### 🪣 S3 Bucket Security Events\n"]
        for log in s3_incidents:
            eid = log.get("event_id")
            bname = log.get("resource_id")
            status = log.get("remediation_status", "OPEN")
            lines.append(f"- **Event `{eid}`**: Bucket `{bname}` — Status: **{status}**")
            lines.append(f"  *Details*: {log.get('details', 'Public exposure configuration.')}")
            lines.append(f"  *Recommended Fix*: `fix_s3_bucket('{bname}')` to enforce AWS Public Access Block.")
        return "\n".join(lines)

    # Query 4: Specific event inquiry (e.g. "evt-101", "evt-102")
    match_eid = re.search(r"\b(evt-\d+|incident-\d+)\b", q)
    if match_eid:
        target_eid = match_eid.group(1)
        target_log = next((l for l in logs if str(l.get("event_id")).lower() == target_eid), None)
        if target_log:
            analysis = analyses.get(target_log.get("event_id"), _deterministic_analysis(target_log))
            return (
                f"### 📋 Incident Report: `{target_log.get('event_id')}`\n"
                f"- **Resource:** `{analysis.get('resource_id')}`\n"
                f"- **Threat Type:** {analysis.get('vulnerability_type')}\n"
                f"- **Priority:** **{analysis.get('priority')}** (Threat Score: {analysis.get('threat_score')}/10)\n"
                f"- **Blast Radius:** {analysis.get('blast_radius_score')}/10 (Risk estimate)\n"
                f"- **Recommended Action:** `{analysis.get('remediation_action')}` ({analysis.get('recommended_action')})\n"
                f"- **Summary:** {analysis.get('summary')}\n"
                f"- **Remediation Status:** **{target_log.get('remediation_status', 'OPEN')}**"
            )
        else:
            return f"No incident record matching `{target_eid}` was found in the current security logs."

    # Query 5: Unresolved / Open incidents
    if any(k in q for k in ["unresolved", "open", "pending", "awaiting"]):
        open_logs = [l for l in logs if l.get("remediation_status", "OPEN") != "RESOLVED"]
        if not open_logs:
            return "All security incidents have been successfully remediated and verified!"
        lines = [f"### ⏳ Unresolved Incidents ({len(open_logs)} total)\n"]
        for log in open_logs:
            eid = log.get("event_id")
            res = log.get("resource_id")
            status = log.get("remediation_status", "OPEN")
            lines.append(f"- **`{eid}`**: `{res}` — Status: **{status}**")
        return "\n".join(lines)

    # Query 6: Analyzed "today" or time-based
    if any(k in q for k in ["today", "recent", "latest", "time"]):
        lines = ["### 🕒 Chronological Security Telemetry\n"]
        for log in logs:
            eid = log.get("event_id")
            ts = log.get("timestamp", "Timestamp unavailable")
            lines.append(f"- **`{eid}`** (`{ts}`): {log.get('event_name')} on `{log.get('resource_id')}`")
        lines.append("\n*Note: Timestamps are represented in UTC (ISO 8601).*")
        return "\n".join(lines)

    # Default overview summary
    total = len(logs)
    open_count = sum(1 for l in logs if l.get("remediation_status") != "RESOLVED")
    resolved_count = sum(1 for l in logs if l.get("remediation_status") == "RESOLVED")
    return (
        f"### 🛡️ InfraMind System Overview\n"
        f"- **Total Security Incidents Loaded:** {total}\n"
        f"- **Unresolved Incidents:** {open_count}\n"
        f"- **Successfully Remediated:** {resolved_count}\n\n"
        "You can ask me specific questions like:\n"
        "- *'What API keys were flagged?'*\n"
        "- *'Which incidents are critical?'*\n"
        "- *'What happened to the S3 bucket?'*\n"
        "- *'What remediation was recommended for evt-101?'*\n"
        "- *'Which incidents are still unresolved?'*"
    )
