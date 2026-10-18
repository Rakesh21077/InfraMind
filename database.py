"""
InfraMind — Persistent Database & Audit Storage Engine
SQLite Storage Layer for Near-Real-Time Incident Telemetry & Audit Trails

Provides thread-safe persistence, idempotent event deduplication,
schema auto-initialization, analysis caching, and audit trail logging.
Designed with a modular storage interface for future seamless migration to
managed cloud databases (e.g. Amazon Aurora / DynamoDB).
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("inframind.database")

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "inframind.db")


def get_db_path() -> str:
    """Return the absolute path to the SQLite database file from configuration."""
    custom_path = os.getenv("DATABASE_PATH")
    if custom_path:
        if not os.path.isabs(custom_path):
            custom_path = os.path.join(os.path.dirname(__file__), custom_path)
        os.makedirs(os.path.dirname(custom_path), exist_ok=True)
        return custom_path
    os.makedirs(os.path.dirname(DEFAULT_DB_PATH), exist_ok=True)
    return DEFAULT_DB_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Acquire a SQLite connection configured with WAL (Write-Ahead Logging) mode
    for safe concurrent access between the ingestion worker and Streamlit dashboard.
    """
    path = db_path or get_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """Initialize database tables, schema constraints, and performance indexes."""
    conn = get_connection(db_path)
    try:
        with conn:
            # 1. Incidents Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    source_event_id TEXT,
                    event_source TEXT NOT NULL,
                    event_name TEXT NOT NULL,
                    aws_account_id TEXT,
                    aws_region TEXT,
                    resource_id TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    user_name TEXT,
                    timestamp TEXT NOT NULL,
                    details TEXT,
                    raw_event_json TEXT,
                    threat_priority TEXT DEFAULT 'UNANALYZED',
                    threat_score INTEGER DEFAULT 0,
                    blast_radius_score INTEGER DEFAULT 0,
                    vulnerability_type TEXT,
                    summary TEXT,
                    remediation_action TEXT DEFAULT 'none',
                    recommended_action TEXT,
                    analysis_provider TEXT,
                    analysis_status TEXT DEFAULT 'PENDING',
                    remediation_status TEXT DEFAULT 'OPEN',
                    first_seen_at TEXT NOT NULL,
                    last_updated_at TEXT NOT NULL,
                    error_message TEXT
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_event_id ON incidents(event_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(remediation_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_priority ON incidents(threat_priority);")

            # 2. Remediation Audit Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_resource TEXT NOT NULL,
                    operator_approved INTEGER NOT NULL,
                    execution_status TEXT NOT NULL,
                    result_message TEXT,
                    raw_result_json TEXT,
                    timestamp TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_id ON remediation_audit(event_id);")

            # 3. System Status & Health Metrics Table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_status (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
        logger.info("Database initialized successfully at: %s", db_path or get_db_path())
    finally:
        conn.close()


def insert_or_get_incident(incident: Dict[str, Any], db_path: Optional[str] = None) -> Tuple[Dict[str, Any], bool]:
    """
    Idempotent insert of an incident record.
    If event_id already exists in the database, returns the existing record.
    Returns: (incident_record_dict, is_new_record_bool)
    """
    event_id = str(incident.get("event_id", "")).strip()
    if not event_id:
        raise ValueError("Incident missing mandatory 'event_id'.")

    conn = get_connection(db_path)
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        with conn:
            # Check existing
            cur = conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,))
            row = cur.fetchone()
            if row:
                return dict(row), False

            # Extract fields
            event_source = incident.get("event_source", "aws")
            event_name = incident.get("event_name", "SecurityEvent")
            aws_account_id = incident.get("aws_account_id") or incident.get("recipientAccountId")
            aws_region = incident.get("aws_region") or os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            resource_id = str(incident.get("resource_id", "unknown-resource")).strip()
            resource_type = incident.get("resource_type", "AWS::Resource")
            user_name = incident.get("user_name") or incident.get("user_identity", {}).get("user_name")
            timestamp = incident.get("timestamp") or now_iso
            details = incident.get("details", "")
            raw_event_json = json.dumps(incident.get("raw_event") or incident)
            threat_priority = incident.get("threat_priority", "UNANALYZED")
            threat_score = int(incident.get("threat_score", 0))
            blast_radius_score = int(incident.get("blast_radius_score", 0))
            vulnerability_type = incident.get("vulnerability_type")
            summary = incident.get("summary")
            remediation_action = incident.get("remediation_action", "none")
            recommended_action = incident.get("recommended_action")
            analysis_provider = incident.get("analysis_provider")
            analysis_status = incident.get("analysis_status", "PENDING")
            remediation_status = incident.get("remediation_status", "OPEN")

            conn.execute(
                """
                INSERT INTO incidents (
                    event_id, source_event_id, event_source, event_name,
                    aws_account_id, aws_region, resource_id, resource_type,
                    user_name, timestamp, details, raw_event_json,
                    threat_priority, threat_score, blast_radius_score,
                    vulnerability_type, summary, remediation_action,
                    recommended_action, analysis_provider, analysis_status,
                    remediation_status, first_seen_at, last_updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    incident.get("source_event_id", event_id),
                    event_source,
                    event_name,
                    aws_account_id,
                    aws_region,
                    resource_id,
                    resource_type,
                    user_name,
                    timestamp,
                    details,
                    raw_event_json,
                    threat_priority,
                    threat_score,
                    blast_radius_score,
                    vulnerability_type,
                    summary,
                    remediation_action,
                    recommended_action,
                    analysis_provider,
                    analysis_status,
                    remediation_status,
                    now_iso,
                    now_iso,
                ),
            )
            # Re-fetch
            cur = conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,))
            new_row = cur.fetchone()
            return dict(new_row), True
    finally:
        conn.close()


def update_analysis(event_id: str, analysis: Dict[str, Any], db_path: Optional[str] = None) -> bool:
    """Update incident record with AI or deterministic threat evaluation results."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cur = conn.execute(
                """
                UPDATE incidents SET
                    threat_priority = ?,
                    threat_score = ?,
                    blast_radius_score = ?,
                    vulnerability_type = ?,
                    summary = ?,
                    remediation_action = ?,
                    recommended_action = ?,
                    analysis_provider = ?,
                    analysis_status = 'ANALYZED',
                    last_updated_at = ?
                WHERE event_id = ?
                """,
                (
                    analysis.get("priority", "MEDIUM"),
                    int(analysis.get("threat_score", 5)),
                    int(analysis.get("blast_radius_score", 5)),
                    analysis.get("vulnerability_type", "Threat Detected"),
                    analysis.get("summary", ""),
                    analysis.get("remediation_action", "none"),
                    analysis.get("recommended_action", ""),
                    analysis.get("engine") or analysis.get("analysis_provider", "Fallback"),
                    now_iso,
                    event_id,
                ),
            )
            return cur.rowcount > 0
    finally:
        conn.close()


def update_remediation(
    event_id: str,
    status: str,
    audit_data: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None,
) -> bool:
    """Update incident remediation status and record an immutable entry in the audit trail."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cur = conn.execute(
                "UPDATE incidents SET remediation_status = ?, last_updated_at = ? WHERE event_id = ?",
                (status, now_iso, event_id),
            )
            if audit_data:
                conn.execute(
                    """
                    INSERT INTO remediation_audit (
                        event_id, action, target_resource, operator_approved,
                        execution_status, result_message, raw_result_json, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        audit_data.get("action", "unknown"),
                        audit_data.get("target_resource", ""),
                        1 if audit_data.get("operator_approved") else 0,
                        status,
                        audit_data.get("result_message", ""),
                        json.dumps(audit_data.get("raw_result_json") or {}),
                        now_iso,
                    ),
                )
            return cur.rowcount > 0
    finally:
        conn.close()


def get_all_incidents(
    status_filter: Optional[str] = None,
    priority_filter: Optional[str] = None,
    source_filter: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all stored incidents matching optional query filters."""
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status_filter and status_filter.upper() != "ALL":
            query += " AND remediation_status = ?"
            params.append(status_filter.upper())

        if priority_filter and priority_filter.upper() != "ALL":
            query += " AND threat_priority = ?"
            params.append(priority_filter.upper())

        if source_filter and source_filter.upper() != "ALL":
            query += " AND event_source LIKE ?"
            params.append(f"%{source_filter.lower()}%")

        query += " ORDER BY timestamp DESC"
        cur = conn.execute(query, tuple(params))
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_incident_by_event_id(event_id: str, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve a single incident by its unique event ID."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT * FROM incidents WHERE event_id = ?", (event_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_audit_trail(event_id: Optional[str] = None, limit: int = 50, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve immutable remediation audit entries."""
    conn = get_connection(db_path)
    try:
        if event_id:
            cur = conn.execute(
                "SELECT * FROM remediation_audit WHERE event_id = ? ORDER BY timestamp DESC LIMIT ?",
                (event_id, limit),
            )
        else:
            cur = conn.execute(
                "SELECT * FROM remediation_audit ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def set_system_status(key: str, value: str, db_path: Optional[str] = None) -> None:
    """Store operational heartbeat or health status."""
    conn = get_connection(db_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO system_status (key, value, updated_at) VALUES (?, ?, ?)",
                (key, str(value), now_iso),
            )
    finally:
        conn.close()


def get_system_status(key: str, default: Optional[str] = None, db_path: Optional[str] = None) -> Optional[str]:
    """Retrieve operational status value."""
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT value FROM system_status WHERE key = ?", (key,))
        row = cur.fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def seed_demo_data(mock_logs_path: Optional[str] = None, db_path: Optional[str] = None) -> int:
    """
    Populate database with default demonstration logs if the database is currently empty.
    Returns count of newly seeded incidents.
    """
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cur = conn.execute("SELECT COUNT(*) as count FROM incidents")
        count = cur.fetchone()["count"]
        if count > 0:
            return 0  # Already has data

        path = mock_logs_path or os.path.join(os.path.dirname(__file__), "mock_logs.json")
        if not os.path.exists(path):
            return 0

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        seeded = 0
        for item in data:
            if isinstance(item, dict):
                insert_or_get_incident(item, db_path)
                seeded += 1
        return seeded
    finally:
        conn.close()


def clear_all_data(db_path: Optional[str] = None) -> None:
    """Clear all data from tables (intended for testing and development resets)."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM remediation_audit")
            conn.execute("DELETE FROM system_status")
    finally:
        conn.close()


# Auto-initialize DB schema on module import
init_db()
