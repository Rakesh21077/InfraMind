"""
InfraMind — Real-Time Cloud Security Guardrail Platform (Version 2)
Streamlit Operations Console & Incident Remediation Dashboard

Dual Operating Modes:
1. Demo Mode: Works offline using seeded mock logs & safe simulation.
2. AWS Live-Ingestion Mode: Connects to Amazon SQS / EventBridge pipeline,
   persisting live CloudTrail / GuardDuty events into SQLite.

Features:
- Connection Status Panel (SQS queue health, worker heartbeat, DB metrics).
- Near-real-time auto-refreshing incident feed.
- Multi-dimensional filtering (Severity, Source, Status).
- Event details inspector with sanitized raw telemetry.
- AI Threat Analysis with model provider selection & caching.
- Controlled Human-in-the-Loop remediation bound to target resources.
- Incident Time-Machine conversational audit assistant.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import streamlit as st
from dotenv import load_dotenv

load_dotenv(override=False)

from agent import analyze_security_log, ask_incident_history, get_llm_config
from database import (
    clear_all_data,
    get_all_incidents,
    get_audit_trail,
    get_db_path,
    get_incident_by_event_id,
    get_system_status,
    init_db,
    seed_demo_data,
    update_analysis,
    update_remediation,
)
from remediation import (
    STATUS_BLOCKED,
    STATUS_FAILED,
    STATUS_SIMULATED,
    STATUS_SUCCESS,
    fix_s3_bucket,
    is_dry_run,
    is_live_execution_enabled,
    revoke_iam_key,
)

logger = logging.getLogger("inframind.app")

# Ensure database schema is initialized
init_db()

# ---------------------------------------------------------------------------
# Streamlit Page Setup & Custom Styling
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="InfraMind — AI Cloud Security Guardrail (v2)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-title { font-size: 2.1rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.1rem; }
    .sub-title { font-size: 1.05rem; color: #4B5563; margin-bottom: 1.2rem; }
    .status-badge {
        padding: 4px 10px; border-radius: 12px; font-size: 0.82rem; font-weight: 600; display: inline-block;
    }
    .badge-critical { background-color: #FEE2E2; color: #991B1B; border: 1px solid #F87171; }
    .badge-high { background-color: #FFEDD5; color: #9A3412; border: 1px solid #FDBA74; }
    .badge-medium { background-color: #FEF3C7; color: #92400E; border: 1px solid #FCD34D; }
    .badge-low { background-color: #E0E7FF; color: #3730A3; border: 1px solid #A5B4FC; }
    .badge-success { background-color: #DCFCE7; color: #166534; border: 1px solid #86EFAC; }
    .badge-simulated { background-color: #E0F2FE; color: #075985; border: 1px solid #7DD3FC; }
    .badge-blocked { background-color: #FEF08A; color: #854D0E; border: 1px solid #FACC15; }
    .badge-live { background-color: #ECFDF5; color: #047857; border: 1px solid #10B981; font-weight: 700; }
    .badge-demo { background-color: #F3F4F6; color: #4B5563; border: 1px solid #9CA3AF; font-weight: 700; }
    .badge-unconfigured { background-color: #FEF2F2; color: #B91C1C; border: 1px solid #EF4444; font-weight: 700; }
    .panel-card { border: 1px solid #E5E7EB; border-radius: 8px; padding: 14px; background-color: #F9FAFB; margin-bottom: 12px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Environment & Operating Mode Evaluation
# ---------------------------------------------------------------------------
app_mode_env = os.getenv("APP_MODE", "demo").strip().lower()
sqs_queue_url = os.getenv("SQS_QUEUE_URL", "").strip()
refresh_interval = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5"))

if "app_mode" not in st.session_state:
    st.session_state.app_mode = app_mode_env

if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = [
        {
            "role": "assistant",
            "content": (
                "👋 **Welcome to InfraMind Incident Time-Machine!**\n\n"
                "I am your conversational cloud security auditing assistant. "
                "Ask me about active threats, compromised IAM keys, public S3 buckets, "
                "or specific incident IDs (e.g. `evt-101`, `ct-s3-9999`)."
            ),
        }
    ]

# In demo mode, auto-seed DB if completely empty
if st.session_state.app_mode == "demo":
    seeded = seed_demo_data()
    if seeded > 0:
        logger.info("Auto-seeded %d demo incidents into persistent store.", seeded)

# ---------------------------------------------------------------------------
# Sidebar: System Health, Connection Panel & Mode Switcher
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image("https://raw.githubusercontent.com/github/explore/main/topics/aws/aws.png", width=42)
    st.title("Platform Operations")
    st.markdown("---")

    # Operating Mode Selector
    st.subheader("🌐 Operating Mode")
    selected_mode = st.radio(
        "Select Active Pipeline:",
        options=["Demo Mode (Offline / Sample Data)", "AWS Live Ingestion Mode"],
        index=0 if st.session_state.app_mode == "demo" else 1,
    )
    new_mode = "demo" if "Demo Mode" in selected_mode else "live"
    if new_mode != st.session_state.app_mode:
        st.session_state.app_mode = new_mode
        st.rerun()

    st.markdown("---")
    st.subheader("🔌 Connection Status Panel")

    # Mode-dependent health checks
    worker_heartbeat = get_system_status("ingestion_worker_heartbeat")
    ingestion_status = get_system_status("ingestion_status", default="STOPPED")
    last_event_time = get_system_status("last_event_received_at", default="None")

    if st.session_state.app_mode == "live":
        if not sqs_queue_url:
            st.markdown('<span class="status-badge badge-unconfigured">⚠️ LIVE INGESTION: NOT CONFIGURED</span>', unsafe_allow_html=True)
            st.caption("SQS_QUEUE_URL is not set. Deploy CloudFormation stack or update .env.")
        elif ingestion_status == "RUNNING":
            st.markdown('<span class="status-badge badge-live">🟢 INGESTION WORKER: ACTIVE</span>', unsafe_allow_html=True)
            st.caption(f"Worker Heartbeat: `{worker_heartbeat[:19] if worker_heartbeat else 'Active'}`")
        else:
            st.markdown('<span class="status-badge badge-blocked">🟡 WORKER OFFLINE (Awaiting Process)</span>', unsafe_allow_html=True)
            st.caption("Start worker: `python ingestion_worker.py`")
        st.markdown(f"**Last AWS Event:** `{last_event_time[:19]}`")
    else:
        st.markdown('<span class="status-badge badge-demo">🧪 DEMO MODE ACTIVE</span>', unsafe_allow_html=True)
        st.caption("Using offline mock data. Zero AWS credentials required.")

    # Persistent Storage Health
    st.markdown("---")
    st.subheader("💾 Persistent Store (SQLite)")
    st.markdown(f"**Database:** `{os.path.basename(get_db_path())}`")
    all_db_incidents = get_all_incidents()
    st.markdown(f"**Stored Incidents:** `{len(all_db_incidents)}`")
    audit_count = len(get_audit_trail(limit=500))
    st.markdown(f"**Audit Trail Logs:** `{audit_count}`")

    # AI Model Provider
    st.markdown("---")
    llm_cfg = get_llm_config()
    st.subheader("🤖 AI Model Provider")
    st.markdown(f"**Engine:** `{llm_cfg['display_label']}`")
    st.caption("Supports AMD Instinct GPU (ROCm vLLM), local Ollama, and instant rule-based fallback.")

    # Remediation Safety Status
    st.markdown("---")
    st.subheader("🛡️ Safety Controls")
    if is_dry_run():
        st.markdown('<span class="status-badge badge-simulated">🛡️ DRY_RUN: ACTIVE</span>', unsafe_allow_html=True)
        st.caption("Safe local simulation. No cloud mutations.")
    else:
        st.markdown('<span class="status-badge badge-critical">⚠️ LIVE EXECUTION MODE</span>', unsafe_allow_html=True)

    if is_live_execution_enabled():
        st.markdown('<span class="status-badge badge-critical">⚡ CIRCUIT BREAKER: OPEN</span>', unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-badge badge-success">🔒 CIRCUIT BREAKER: BLOCKED</span>', unsafe_allow_html=True)

    st.markdown("---")
    if st.button("🔄 Reset Demo Database", use_container_width=True):
        clear_all_data()
        seed_demo_data()
        st.success("Database reset to initial sample incidents.")
        st.rerun()

    audit_logs = get_audit_trail(limit=200)
    if audit_logs:
        st.download_button(
            label="📥 Export Remediation Audit JSON",
            data=json.dumps(audit_logs, indent=2),
            file_name=f"inframind_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True,
        )

# ---------------------------------------------------------------------------
# Main Title & Top Banner
# ---------------------------------------------------------------------------
st.markdown('<div class="main-title">🛡️ InfraMind — AI Cloud Security Guardrail</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-title">Near-real-time CloudTrail & GuardDuty ingestion, AI threat evaluation, and human-in-the-loop remediation</div>',
    unsafe_allow_html=True,
)

# Live Mode Warning Banner if unconfigured
if st.session_state.app_mode == "live" and not sqs_queue_url:
    st.error(
        "⚠️ **LIVE INGESTION: NOT CONFIGURED** — The SQS Queue URL (`SQS_QUEUE_URL`) is not configured in `.env`. "
        "The system cannot poll real AWS CloudTrail events until the AWS CloudFormation pipeline (`infra/cloudformation-realtime.yaml`) "
        "is deployed and the SQS Queue URL is provided. Switch to **Demo Mode** in the sidebar to test offline with sample events."
    )

# ---------------------------------------------------------------------------
# Executive KPI Metrics Row
# ---------------------------------------------------------------------------
incidents_pool = get_all_incidents()
total_alerts = len(incidents_pool)
critical_or_high = sum(1 for inc in incidents_pool if inc.get("threat_priority") in ("CRITICAL", "HIGH"))
unresolved_count = sum(1 for inc in incidents_pool if inc.get("remediation_status") not in ("RESOLVED", "SIMULATED"))
remediated_count = sum(1 for inc in incidents_pool if inc.get("remediation_status") == "RESOLVED")

col_k1, col_k2, col_k3, col_k4 = st.columns(4)
with col_k1:
    st.metric("Total Ingested Alerts", total_alerts)
with col_k2:
    st.metric("Critical / High Threats", critical_or_high)
with col_k3:
    st.metric("Awaiting Human Review", unresolved_count)
with col_k4:
    st.metric("Successfully Remediated", remediated_count)

st.markdown("---")

# ---------------------------------------------------------------------------
# Navigation Tabs
# ---------------------------------------------------------------------------
tab_alerts, tab_chat, tab_audit = st.tabs([
    "🚨 Active Threat Feed",
    "🤖 Incident Time-Machine (AI Assistant)",
    "📜 Remediation Audit Trail",
])

# ===========================================================================
# TAB 1: ACTIVE THREAT FEED
# ===========================================================================
with tab_alerts:
    # Filtering Control Bar
    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([3, 3, 3, 2])
    with filter_col1:
        f_priority = st.selectbox("Filter Priority:", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with filter_col2:
        f_source = st.selectbox("Filter Source:", ["ALL", "s3", "iam", "guardduty"])
    with filter_col3:
        f_status = st.selectbox("Filter Status:", ["ALL", "OPEN", "SIMULATED", "RESOLVED", "BLOCKED"])
    with filter_col4:
        st.write("")
        st.write("")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

    # Query filtered incidents from database
    filtered_incidents = get_all_incidents(
        status_filter=f_status,
        priority_filter=f_priority,
        source_filter=f_source,
    )

    if not filtered_incidents:
        st.info("No incidents found matching the selected filters.")
    else:
        for idx, inc in enumerate(filtered_incidents):
            eid = inc["event_id"]
            ename = inc.get("event_name", "UnknownEvent")
            esource = inc.get("event_source", "aws")
            res_id = inc.get("resource_id", "unspecified-resource")
            res_type = inc.get("resource_type", "Cloud Resource")
            priority = inc.get("threat_priority", "UNANALYZED")
            score = inc.get("threat_score", 0)
            blast_radius = inc.get("blast_radius_score", 0)
            status = inc.get("remediation_status", "OPEN")
            user_name = inc.get("user_name", "")
            ts = inc.get("timestamp", "Recent")
            details = inc.get("details", "")
            summary = inc.get("summary", "")
            remed_action = inc.get("remediation_action", "none")
            recommended_action = inc.get("recommended_action", "")
            analysis_status = inc.get("analysis_status", "PENDING")

            p_badge_class = {
                "CRITICAL": "badge-critical",
                "HIGH": "badge-high",
                "MEDIUM": "badge-medium",
                "LOW": "badge-low",
            }.get(priority, "badge-medium")

            status_badge_html = {
                "RESOLVED": '<span class="status-badge badge-success">RESOLVED</span>',
                "SIMULATED": '<span class="status-badge badge-simulated">SIMULATED (DRY RUN)</span>',
                "BLOCKED": '<span class="status-badge badge-blocked">BLOCKED BY GUARDRAIL</span>',
                "OPEN": '<span class="status-badge badge-critical">AWAITING REVIEW</span>',
            }.get(status, '<span class="status-badge badge-medium">OPEN</span>')

            # Render Alert Card
            with st.container():
                st.markdown(f"#### Alert: `{eid}` — `{ename}` on `{res_id}`")
                mcol1, mcol2, mcol3, mcol4 = st.columns([2, 2, 2, 2])
                with mcol1:
                    st.markdown(f"**Timestamp:** `{ts}`")
                with mcol2:
                    st.markdown(f"**Source:** `{esource}`")
                with mcol3:
                    st.markdown(f"**Resource:** `{res_type}`")
                with mcol4:
                    st.markdown(status_badge_html, unsafe_allow_html=True)

                st.write(f"**Telemetry Context:** {details}")

                # Analysis Trigger or Display
                if analysis_status != "ANALYZED":
                    if st.button(f"🤖 Analyze Alert via AI Engine", key=f"btn_analyze_{eid}"):
                        with st.spinner("Dispatching event to AI evaluation engine..."):
                            analysis_result = analyze_security_log(inc)
                            update_analysis(eid, analysis_result)
                            st.rerun()
                else:
                    acol1, acol2, acol3, acol4 = st.columns(4)
                    with acol1:
                        st.markdown(f"**Severity:** <span class='status-badge {p_badge_class}'>{priority}</span>", unsafe_allow_html=True)
                    with acol2:
                        st.metric("Threat Score", f"{score} / 10")
                    with acol3:
                        st.metric("Blast Radius", f"{blast_radius} / 10", help="Estimated blast-radius risk impact")
                    with acol4:
                        st.markdown(f"**Provider:**\n`{inc.get('analysis_provider', 'AI / Fallback')}`")

                    st.info(f"**AI Threat Summary:** {summary}")
                    st.markdown(f"**Recommended Action:** `{recommended_action or remed_action}`")

                    # Remediation Console
                    if remed_action in ("fix_s3_bucket", "revoke_iam_key"):
                        st.markdown("##### ⚡ Controlled Remediation Console")
                        if remed_action == "fix_s3_bucket":
                            st.markdown(f"Target Resource: Amazon S3 Bucket **`{res_id}`**")
                            st.caption("Action: Applies AWS S3 Public Access Block (enables all 4 restriction flags).")
                        else:
                            st.markdown(f"Target Resource: IAM Access Key **`{res_id}`** (User: **`{user_name or 'Unspecified'}`**)")
                            st.caption("Action: Sets Access Key status to 'Inactive' via IAM update_access_key without deleting it.")

                        # Operator approval checkbox strictly bound to target
                        approval = st.checkbox(
                            f"I authorize and approve executing '{remed_action}' on target resource '{res_id}'.",
                            key=f"chk_approve_{eid}",
                        )

                        if st.button("⚡ Approve & Execute Patch", key=f"btn_remediate_{eid}"):
                            if not approval:
                                st.warning("⚠️ Operator Authorization Required: Please check the approval box above before execution.")
                            else:
                                with st.spinner("Executing remediation through Member 3 guardrail engine..."):
                                    if remed_action == "fix_s3_bucket":
                                        result = fix_s3_bucket(res_id, approved=True)
                                    else:
                                        result = revoke_iam_key(res_id, user_name=user_name, approved=True)

                                    res_status = result.get("status")
                                    audit_entry = {
                                        "action": remed_action,
                                        "target_resource": res_id,
                                        "operator_approved": True,
                                        "result_message": result.get("message", ""),
                                        "raw_result_json": result,
                                    }

                                    update_remediation(eid, res_status, audit_data=audit_entry)

                                    if res_status == STATUS_SUCCESS:
                                        st.success(f"✅ Remediation Succeeded: {result.get('message')}")
                                    elif res_status == STATUS_SIMULATED:
                                        st.info(f"🛡️ Simulation Complete: {result.get('message')}\n\n*(DRY_RUN mode is active. No real AWS changes made.)*")
                                    elif res_status == STATUS_BLOCKED:
                                        st.warning(f"🔒 Blocked by Guardrail: {result.get('message')}")
                                    else:
                                        st.error(f"❌ Remediation Failed: {result.get('message')}")
                                    st.rerun()

                # Expandable Raw Event Inspector
                with st.expander(f"🔍 Raw Event Metadata ({eid})", expanded=False):
                    try:
                        raw_json = json.loads(inc.get("raw_event_json") or "{}")
                        st.json(raw_json)
                    except Exception:
                        st.text(inc.get("raw_event_json", "No raw payload stored."))

                st.markdown("---")

# ===========================================================================
# TAB 2: INCIDENT TIME-MACHINE (AI ASSISTANT)
# ===========================================================================
with tab_chat:
    st.subheader("Incident Time-Machine (Conversational AI Assistant)")
    st.caption("Ask natural-language questions to interrogate stored incidents, check specific credentials, or query remediation status.")

    st.markdown("**Quick Audit Queries:**")
    qcols = st.columns(3)
    suggested_q = None
    with qcols[0]:
        if st.button("🔑 What API keys were flagged?", key="q_btn_1", use_container_width=True):
            suggested_q = "What API keys were flagged?"
        if st.button("🪣 What happened to the S3 bucket?", key="q_btn_2", use_container_width=True):
            suggested_q = "What happened to the S3 bucket?"
    with qcols[1]:
        if st.button("🚨 Which incidents are critical?", key="q_btn_3", use_container_width=True):
            suggested_q = "Which incidents are critical?"
        if st.button("⏳ Which incidents are still unresolved?", key="q_btn_4", use_container_width=True):
            suggested_q = "Which incidents are still unresolved?"
    with qcols[2]:
        if st.button("📋 What was recommended for evt-101?", key="q_btn_5", use_container_width=True):
            suggested_q = "What remediation was recommended for evt-101?"
        if st.button("🕒 Which threats were analyzed today?", key="q_btn_6", use_container_width=True):
            suggested_q = "Which threats were analyzed today?"

    st.markdown("---")

    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    user_query = st.chat_input("Ask InfraMind about incidents, threat scores, or audit logs...") or suggested_q

    if user_query:
        st.session_state.chat_messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        with st.chat_message("assistant"):
            with st.spinner("Interrogating security incidents from persistent store..."):
                current_incidents = get_all_incidents()
                analyses_map = {inc["event_id"]: inc for inc in current_incidents if inc.get("analysis_status") == "ANALYZED"}
                response_text = ask_incident_history(user_query, current_incidents, analyses_map)
                st.markdown(response_text)
                st.session_state.chat_messages.append({"role": "assistant", "content": response_text})

# ===========================================================================
# TAB 3: REMEDIATION AUDIT TRAIL
# ===========================================================================
with tab_audit:
    st.subheader("Immutable Remediation Audit Trail")
    st.caption("Cryptographically verifiable record of all patch approvals, simulations, and live AWS executions.")

    audit_records = get_audit_trail(limit=100)
    if not audit_records:
        st.info("No remediation actions have been executed yet.")
    else:
        for entry in audit_records:
            t_eid = entry.get("event_id")
            t_act = entry.get("action")
            t_res = entry.get("target_resource")
            t_status = entry.get("execution_status")
            t_msg = entry.get("result_message")
            t_time = entry.get("timestamp")

            s_badge = {
                "SUCCESS": '<span class="status-badge badge-success">SUCCESS</span>',
                "SIMULATED": '<span class="status-badge badge-simulated">SIMULATED</span>',
                "BLOCKED": '<span class="status-badge badge-blocked">BLOCKED</span>',
            }.get(t_status, '<span class="status-badge badge-critical">FAILED</span>')

            with st.container():
                st.markdown(f"**Audit ID `{entry['id']}`** | Event: `{t_eid}` | Target: `{t_res}` | {s_badge}", unsafe_allow_html=True)
                st.write(f"Action: `{t_act}` | Executed At: `{t_time}` | Operator Approved: `{'Yes' if entry.get('operator_approved') else 'No'}`")
                st.caption(f"Result: {t_msg}")
                st.markdown("---")
