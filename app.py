"""
InfraMind — AI Cloud Security Guardrail for Startups & IT
Streamlit Web Interface & Incident Management Console

Full-featured real-time security dashboard providing:
1. Executive metrics: total alerts, critical threats, unresolved incidents, remediated items.
2. Active Threat Dashboard: incident cards, AI log analysis via AMD GPU endpoint / fallback,
   blast-radius scoring, and human-in-the-loop explicit approval remediation workflow.
3. Incident Time-Machine (AI Assistant): conversational chat auditing past incidents,
   querying specific credentials, and summarizing risk postures.
4. Robust safety controls: default dry-run simulation mode, operator checkboxes, and
   strict resource identity binding.
"""

import json
import os
import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import streamlit as st
from dotenv import load_dotenv

# Load local environment configuration
load_dotenv(override=False)

from agent import analyze_security_log, ask_incident_history, get_llm_config
from remediation import (
    fix_s3_bucket,
    revoke_iam_key,
    is_dry_run,
    is_live_execution_enabled,
    STATUS_SIMULATED,
    STATUS_SUCCESS,
    STATUS_BLOCKED,
    STATUS_FAILED,
)

# ---------------------------------------------------------------------------
# Streamlit Page Configuration & Branding
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="InfraMind — AI Cloud Security Guardrail",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished cybersecurity UI
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .status-badge {
        padding: 4px 10px;
        border-radius: 12px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-critical { background-color: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
    .badge-high { background-color: #FFEDD5; color: #9A3412; border: 1px solid #FDBA74; }
    .badge-medium { background-color: #FEF3C7; color: #92400E; border: 1px solid #FCD34D; }
    .badge-low { background-color: #E0E7FF; color: #3730A3; border: 1px solid #A5B4FC; }
    .badge-success { background-color: #DCFCE7; color: #166534; border: 1px solid #86EFAC; }
    .badge-simulated { background-color: #E0F2FE; color: #075985; border: 1px solid #7DD3FC; }
    .badge-blocked { background-color: #FEF08A; color: #854D0E; border: 1px solid #FACC15; }
    .card-container {
        border: 1px solid #E5E7EB;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
        background-color: #FFFFFF;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
def load_default_incidents() -> List[Dict[str, Any]]:
    """Load default sample security events from mock_logs.json."""
    mock_file = os.path.join(os.path.dirname(__file__), "mock_logs.json")
    if os.path.exists(mock_file):
        try:
            with open(mock_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if "remediation_status" not in item:
                            item["remediation_status"] = "OPEN"
                    return data
        except Exception as exc:
            st.error(f"Error loading mock_logs.json: {exc}")
    return []


if "incidents" not in st.session_state:
    st.session_state.incidents = load_default_incidents()

if "analyses" not in st.session_state:
    st.session_state.analyses = {}

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = [
        {
            "role": "assistant",
            "content": (
                "👋 **Welcome to InfraMind Incident Time-Machine!**\n\n"
                "I am your conversational cloud security assistant. Ask me questions about active threats, "
                "flagged access keys, S3 buckets, or specific incident IDs (e.g., `evt-101`)."
            ),
        }
    ]

if "remediation_log" not in st.session_state:
    st.session_state.remediation_log = []


# ---------------------------------------------------------------------------
# Sidebar: System Health & Configuration
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image(
        "https://raw.githubusercontent.com/github/explore/main/topics/aws/aws.png",
        width=48,
    )
    st.title("System Guardrails")
    st.markdown("---")

    dry_run_active = is_dry_run()
    live_active = is_live_execution_enabled()
    llm_cfg = get_llm_config()

    st.subheader("🛡️ Safety Controls")
    if dry_run_active:
        st.markdown(
            '<span class="status-badge badge-simulated">🛡️ DRY_RUN: ACTIVE</span>',
            unsafe_allow_html=True,
        )
        st.caption("No real cloud changes will be made. All actions run in safe simulation mode.")
    else:
        st.markdown(
            '<span class="status-badge badge-critical">⚠️ LIVE EXECUTION MODE</span>',
            unsafe_allow_html=True,
        )

    if live_active:
        st.markdown(
            '<span class="status-badge badge-critical">⚡ LIVE CIRCUIT BREAKER: OPEN</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            '<span class="status-badge badge-success">🔒 LIVE CIRCUIT BREAKER: BLOCKED</span>',
            unsafe_allow_html=True,
        )

    st.markdown("---")
    st.subheader("🤖 AI Inference Engine")
    st.markdown(f"**Endpoint:** `{llm_cfg['endpoint_url']}`")
    st.markdown(f"**Target Model:** `{llm_cfg['model_name']}`")
    st.caption("Primary: AMD Instinct GPU (ROCm vLLM). Local alternative: Ollama. Auto-fails over to deterministic rule-based engine.")

    st.markdown("---")
    st.subheader("⚙️ Actions")
    if st.button("🔄 Reset to Default Logs", use_container_width=True):
        st.session_state.incidents = load_default_incidents()
        st.session_state.analyses = {}
        st.session_state.remediation_log = []
        st.success("Reset successfully to default mock logs.")
        st.rerun()

    # JSON export of audit trail
    if st.session_state.remediation_log:
        st.download_button(
            label="📥 Export Remediation Audit Log",
            data=json.dumps(st.session_state.remediation_log, indent=2),
            file_name=f"inframind_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )


# ---------------------------------------------------------------------------
# Main Header & High-Level Metrics
# ---------------------------------------------------------------------------
st.markdown('<div class="main-header">🛡️ InfraMind — AI Cloud Security Guardrail</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">AI-assisted cloud threat prioritization, blast-radius estimation, and controlled human-in-the-loop remediation</div>',
    unsafe_allow_html=True,
)

# Calculate high-level summary metrics
total_incidents = len(st.session_state.incidents)
critical_or_high = 0
for inc in st.session_state.incidents:
    eid = inc.get("event_id")
    if eid in st.session_state.analyses:
        p = st.session_state.analyses[eid].get("priority")
        if p in ("CRITICAL", "HIGH"):
            critical_or_high += 1
    else:
        # Pre-estimate from log type
        if "s3" in str(inc.get("event_source", "")).lower() or "iam" in str(inc.get("event_source", "")).lower():
            critical_or_high += 1

unresolved = sum(1 for inc in st.session_state.incidents if inc.get("remediation_status") != "RESOLVED")
remediated = sum(1 for inc in st.session_state.incidents if inc.get("remediation_status") == "RESOLVED")

col_m1, col_m2, col_m3, col_m4 = st.columns(4)
with col_m1:
    st.metric(label="Total Ingested Alerts", value=total_incidents)
with col_m2:
    st.metric(label="Critical / High Threats", value=critical_or_high)
with col_m3:
    st.metric(label="Awaiting Operator Review", value=unresolved)
with col_m4:
    st.metric(label="Successfully Remediated", value=remediated)

st.markdown("---")


# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab_dashboard, tab_chat = st.tabs([
    "🚨 Active Threat Dashboard",
    "🤖 Incident Time-Machine (AI Assistant)",
])


# ===========================================================================
# TAB 1: ACTIVE THREAT DASHBOARD
# ===========================================================================
with tab_dashboard:
    st.subheader("Cloud Security Alert Feed")
    st.caption("Ingested AWS CloudTrail & security event telemetry. Click 'Analyze Alert via AMD GPU' to compute risk scores.")

    # Upload Custom Log Option
    with st.expander("📤 Ingest Custom Security Event Log (JSON)", expanded=False):
        uploaded_file = st.file_uploader("Upload JSON File containing an array of security events", type=["json"])
        if uploaded_file is not None:
            try:
                uploaded_data = json.load(uploaded_file)
                if isinstance(uploaded_data, list) and len(uploaded_data) > 0:
                    valid_items = []
                    for item in uploaded_data:
                        if isinstance(item, dict) and "event_id" in item:
                            if "remediation_status" not in item:
                                item["remediation_status"] = "OPEN"
                            valid_items.append(item)
                    if valid_items:
                        st.session_state.incidents = valid_items
                        st.success(f"Successfully loaded {len(valid_items)} custom security events!")
                        st.rerun()
                    else:
                        st.error("Uploaded JSON must contain a list of objects with at least an 'event_id' property.")
                else:
                    st.error("Uploaded file must be a JSON array of event objects.")
            except Exception as e:
                st.error(f"Malformed JSON: {e}")

    # Render Incident Cards
    if not st.session_state.incidents:
        st.info("No security incidents currently loaded. Use the sidebar to reset to sample logs.")
    else:
        for idx, inc in enumerate(st.session_state.incidents):
            eid = inc.get("event_id", f"evt-{idx}")
            esource = inc.get("event_source", "aws")
            ename = inc.get("event_name", "UnknownAction")
            resource = inc.get("resource_id", "UnknownResource")
            ts = inc.get("timestamp", "Recent")
            status = inc.get("remediation_status", "OPEN")
            details = inc.get("details", "No event details provided.")
            user_name = inc.get("user_name") or inc.get("user_identity", {}).get("user_name", "")

            # Container Box
            with st.container():
                st.markdown(f"#### Alert: `{eid}` — `{ename}` on `{resource}`")

                # Metadata row
                col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
                with col1:
                    st.markdown(f"**Timestamp:** `{ts}`")
                with col2:
                    st.markdown(f"**Source:** `{esource}`")
                with col3:
                    st.markdown(f"**Resource Type:** `{inc.get('resource_type', 'Cloud Resource')}`")
                with col4:
                    if status == "RESOLVED":
                        st.markdown('<span class="status-badge badge-success">RESOLVED</span>', unsafe_allow_html=True)
                    elif status == "SIMULATED":
                        st.markdown('<span class="status-badge badge-simulated">SIMULATED (DRY RUN)</span>', unsafe_allow_html=True)
                    elif status == "BLOCKED":
                        st.markdown('<span class="status-badge badge-blocked">BLOCKED BY GUARDRAIL</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="status-badge badge-critical">AWAITING REVIEW</span>', unsafe_allow_html=True)

                st.write(f"**Telemetry Details:** {details}")

                # Analysis Section
                analysis = st.session_state.analyses.get(eid)

                btn_col, _ = st.columns([3, 7])
                with btn_col:
                    if st.button(f"🤖 Analyze Alert via AMD GPU", key=f"btn_analyze_{eid}"):
                        with st.spinner("Dispatching event to AI evaluation engine..."):
                            analysis_result = analyze_security_log(inc)
                            st.session_state.analyses[eid] = analysis_result
                            st.rerun()

                # If analysis exists, display card
                if analysis:
                    st.markdown("---")
                    priority = analysis.get("priority", "MEDIUM")
                    p_badge_class = {
                        "CRITICAL": "badge-critical",
                        "HIGH": "badge-high",
                        "MEDIUM": "badge-medium",
                        "LOW": "badge-low",
                    }.get(priority, "badge-medium")

                    acol1, acol2, acol3, acol4 = st.columns(4)
                    with acol1:
                        st.markdown(
                            f"**Threat Severity:** <span class='status-badge {p_badge_class}'>{priority}</span>",
                            unsafe_allow_html=True,
                        )
                    with acol2:
                        st.metric("Threat Score", f"{analysis.get('threat_score', 0)} / 10")
                    with acol3:
                        st.metric("Blast Radius", f"{analysis.get('blast_radius_score', 0)} / 10", help="Estimated blast-radius risk impact")
                    with acol4:
                        st.markdown(f"**AI Engine:**\n`{analysis.get('engine', 'vLLM / Fallback')}`")

                    st.markdown(f"**Vulnerability:** {analysis.get('vulnerability_type')}")
                    st.info(f"**AI Threat Summary:** {analysis.get('summary')}")
                    st.markdown(f"**Recommended Action:** `{analysis.get('recommended_action')}`")

                    # Remediation Action Section (Human-In-The-Loop)
                    remed_action = analysis.get("remediation_action", "none")

                    if remed_action in ("fix_s3_bucket", "revoke_iam_key"):
                        st.markdown("##### ⚡ Controlled Remediation Console")

                        if remed_action == "fix_s3_bucket":
                            st.markdown(f"Target Resource: Amazon S3 Bucket **`{resource}`**")
                            st.caption("Action: Applies AWS S3 Public Access Block (enables BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets).")
                        elif remed_action == "revoke_iam_key":
                            st.markdown(f"Target Resource: IAM Access Key **`{resource}`** (User: **`{user_name or 'Unspecified'}`**)")
                            st.caption("Action: Sets Access Key status to 'Inactive' via IAM update_access_key. Never deletes key to preserve audit history.")

                        # Explicit Human Approval Checkbox
                        approval = st.checkbox(
                            f"I authorize and approve executing '{remed_action}' on target resource '{resource}'.",
                            key=f"chk_approve_{eid}",
                        )

                        if st.button(f"⚡ Approve & Execute Patch", key=f"btn_remediate_{eid}"):
                            if not approval:
                                st.warning("⚠️ Operator Approval Required: Please check the authorization box above before executing.")
                            else:
                                with st.spinner("Executing remediation through Member 3 guardrail engine..."):
                                    if remed_action == "fix_s3_bucket":
                                        result = fix_s3_bucket(resource, approved=True)
                                    else:
                                        result = revoke_iam_key(resource, user_name=user_name, approved=True)

                                    # Record in session audit log
                                    st.session_state.remediation_log.append({
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "event_id": eid,
                                        "action": remed_action,
                                        "target": resource,
                                        "result": result,
                                    })

                                    # Update status based on strict contract
                                    res_status = result.get("status")
                                    if res_status == STATUS_SUCCESS:
                                        st.success(f"✅ Remediation Succeeded: {result.get('message')}")
                                        inc["remediation_status"] = "RESOLVED"
                                    elif res_status == STATUS_SIMULATED:
                                        st.info(f"🛡️ Simulation Complete: {result.get('message')}\n\n*(DRY_RUN mode is active. No real AWS changes were made.)*")
                                        inc["remediation_status"] = "SIMULATED"
                                    elif res_status == STATUS_BLOCKED:
                                        st.warning(f"🔒 Execution Blocked by Guardrail: {result.get('message')}")
                                        inc["remediation_status"] = "BLOCKED"
                                    else:
                                        st.error(f"❌ Remediation Failed: {result.get('message')}")
                                        inc["remediation_status"] = "FAILED"

                                    st.rerun()

                st.markdown("---")


# ===========================================================================
# TAB 2: INCIDENT TIME-MACHINE (AI ASSISTANT)
# ===========================================================================
with tab_chat:
    st.subheader("Incident Time-Machine (Conversational AI Assistant)")
    st.caption("Ask natural-language questions to audit historical incidents, check specific credentials, or query remediation status.")

    # Suggested Prompts
    st.markdown("**Quick Audit Questions:**")
    prompt_cols = st.columns(3)
    suggested_prompt = None
    with prompt_cols[0]:
        if st.button("🔑 What API keys were flagged?", key="prompt_btn_1", use_container_width=True):
            suggested_prompt = "What API keys were flagged?"
        if st.button("🪣 What happened to the S3 bucket?", key="prompt_btn_2", use_container_width=True):
            suggested_prompt = "What happened to the S3 bucket?"
    with prompt_cols[1]:
        if st.button("🚨 Which incidents are critical?", key="prompt_btn_3", use_container_width=True):
            suggested_prompt = "Which incidents are critical?"
        if st.button("⏳ Which incidents are still unresolved?", key="prompt_btn_4", use_container_width=True):
            suggested_prompt = "Which incidents are still unresolved?"
    with prompt_cols[2]:
        if st.button("📋 What was recommended for evt-101?", key="prompt_btn_5", use_container_width=True):
            suggested_prompt = "What remediation was recommended for evt-101?"
        if st.button("🕒 Which threats were analyzed today?", key="prompt_btn_6", use_container_width=True):
            suggested_prompt = "Which threats were analyzed today?"

    st.markdown("---")

    # Render Chat History
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat Input Box
    user_input = st.chat_input("Ask a question about your security incidents...") or suggested_prompt

    if user_input:
        # Display user message
        st.session_state.chat_messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        # Generate Assistant Response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing incident telemetry..."):
                response_text = ask_incident_history(
                    user_input,
                    st.session_state.incidents,
                    st.session_state.analyses,
                )
                st.markdown(response_text)
                st.session_state.chat_messages.append({"role": "assistant", "content": response_text})
