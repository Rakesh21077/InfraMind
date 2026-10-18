# InfraMind — Real-Time Pipeline Architecture (Version 2)

## 1. Architectural Overview

InfraMind Version 2 elevates the system from an offline static prototype into an event-driven, near-real-time cloud security posture and incident response platform.

The system supports two distinct, isolated operating modes:
- **Demo Mode (`APP_MODE=demo`):** Loads simulated security events from `mock_logs.json`. Runs 100% locally with zero cloud dependencies, safe dry-run simulation, and deterministic fallback support.
- **AWS Live-Ingestion Mode (`APP_MODE=live`):** Streams genuine cloud telemetry directly from an authorized AWS account via Amazon CloudTrail / Amazon GuardDuty, routed through Amazon EventBridge, buffered by Amazon SQS with a Dead-Letter Queue (DLQ), ingested by a background Python worker into an ACID SQLite persistent store, and displayed on an auto-refreshing operator console.

---

## 2. End-to-End Event Pipeline

```mermaid
flowchart TD
    subgraph AWSCloud ["AWS Account Security Telemetry"]
        CT["AWS CloudTrail<br/>(Management Events)"]
        GD["Amazon GuardDuty<br/>(Threat Intelligence)"]
    end

    subgraph EventRouting ["Event Routing & Buffering"]
        EB["Amazon EventBridge<br/>(Event Pattern Matching)"]
        SQS["Amazon SQS Primary Queue<br/>(InfraMindSecurityEventsQueue)"]
        DLQ["Amazon SQS Dead-Letter Queue<br/>(InfraMindSecurityEventsDLQ)"]
    end

    subgraph IngestionTier ["Local Ingestion & Persistence Tier"]
        IW["ingestion_worker.py<br/>(Long-Polling Worker)"]
        DB[("database.py<br/>SQLite WAL Mode<br/>data/inframind.db")]
    end

    subgraph AnalysisAndUI ["Analysis & Operator Console"]
        APP["app.py<br/>Streamlit Console"]
        AGENT["agent.py<br/>AI / Fallback Engine"]
        REM["remediation.py<br/>Guardrail Remediation Engine"]
    end

    CT -->|API Calls: S3 / IAM| EB
    GD -->|Findings| EB
    EB -->|Buffered Ingestion| SQS
    SQS -.->|Poison Pills (5x Fail)| DLQ
    SQS ==>|Long Poll: 20s| IW
    IW -->|Normalize & Validate| DB
    IW -.->|Delete Message| SQS
    DB <==>|Auto-Refresh: 10s| APP
    APP <==>|Inference & Cache| AGENT
    APP ==>|Human-in-the-Loop Approval| REM
```

---

## 3. Data Pipeline Stages

### Stage 1: Telemetry Capture & Filtering (EventBridge)
- CloudTrail captures API calls matching security-critical actions:
  - **S3 Events:** `PutBucketAcl`, `PutBucketPolicy`, `DeletePublicAccessBlock`, `PutBucketPublicAccessBlock`
  - **IAM Events:** `CreateAccessKey`, `UpdateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`
- GuardDuty findings for anomalous credential activity or unauthorized public access are matched simultaneously.
- An EventBridge rule filters these events and dispatches JSON payloads to the SQS queue.

### Stage 2: Resilient Queue Buffering (Amazon SQS + DLQ)
- **Primary Queue:** `InfraMindSecurityEventsQueue` (Standard SQS queue).
  - Server-Side Encryption (SSE-SQS) enabled.
  - Message retention period: 14 days (1,209,600 seconds).
  - Visibility timeout: 60 seconds (worker renewal threshold).
- **Dead-Letter Queue (DLQ):** `InfraMindSecurityEventsDLQ`.
  - Max Receive Count: 5.
  - Unprocessable or poisoned messages that fail consecutive worker attempts are isolated for administrative triage without blocking the main event stream.

### Stage 3: Normalization & Ingestion Worker (`ingestion_worker.py`)
- Executes continuous long-polling (`WaitTimeSeconds=20`) to eliminate empty-poll API costs and minimize latency.
- Extracts and normalizes divergent schemas (CloudTrail vs. GuardDuty) into a unified internal format:
  ```json
  {
    "event_id": "ct-abc12345",
    "event_source": "s3.amazonaws.com",
    "event_name": "PutBucketAcl",
    "resource_id": "customer-data-backup",
    "resource_type": "AWS::S3::Bucket",
    "user_name": "deploy-service-role",
    "details": "Public access granted via PutBucketAcl.",
    "raw_event": {...},
    "timestamp": "2026-10-18T10:15:30Z"
  }
  ```
- **Read-Only Posture Verification:** For S3 bucket events, the worker queries `get_public_access_block` to determine current live posture before persisting.
- **SQS Deletion Safety Invariant:** Messages are deleted from SQS *strictly after* successful database commitment. On database failure, the message is retained in SQS for automatic retry.

### Stage 4: Persistent Incident Store (`database.py`)
- Thread-safe SQLite database located at `data/inframind.db` (customizable via `DATABASE_PATH`).
- **Write-Ahead Logging (WAL Mode):** Allows concurrent readers (Streamlit UI) and writer (`ingestion_worker.py`) without lock contention.
- **Idempotent Deduplication:** Unique constraint on `event_id`. Duplicate CloudTrail deliveries are gracefully ignored (`inserted=False`), updating existing records without creating phantom duplicate alerts.
- **Analysis Caching:** Stores AI threat priority, scores, and recommendations directly within the incident record, eliminating redundant inference costs on dashboard reruns.
- **Remediation Audit Trail:** Appends timestamped execution logs, human approval status, execution mode (SIMULATED vs. LIVE), and raw AWS responses to the `remediation_audit` table.

### Stage 5: Operator Console & Live Refresh (`app.py`)
- Real-time connection status monitoring:
  - Validates SQS queue availability and reports active message counts (`ApproximateNumberOfMessages`).
  - Tracks background worker heartbeat and database health.
  - Prominently displays `LIVE INGESTION: NOT CONFIGURED` when live mode is selected without valid queue credentials.
- Configurable auto-refresh interval (`DASHBOARD_REFRESH_SECONDS=10`) with manual pause/resume controls.
- Dynamic filtering by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), Event Source (`S3`, `IAM`, `GuardDuty`), and Status (`OPEN`, `RESOLVED`).
- Raw telemetry inspector providing full JSON visibility for security analysts.

---

## 4. Failure Modes & Fault Tolerance

| Component Failure | Impact | Recovery Mechanism |
| :--- | :--- | :--- |
| **Worker Process Dies** | Queue accumulates messages. | Systemd / Process Supervisor restarts worker; SQS retains messages up to 14 days. |
| **Database Disk Full / Lock** | Worker cannot write incident. | Worker logs error and skips SQS deletion; SQS visibility timeout expires; event retried automatically. |
| **Poison-Pill Message** | Unparseable or corrupt JSON. | Worker logs warning and drops malformed payload immediately to prevent infinite retry loops. |
| **AI Endpoint Offline** | AI threat assessment fails. | Automatic failover to `Deterministic Rule-Based Offline Fallback Engine` within 2 seconds. Zero UI crash. |
| **AWS API Rate Limit** | Worker receives `429 Too Many Requests`. | Worker applies exponential backoff with jitter before the next poll. |

---

## 5. Security & Isolation Guarantees

1. **Least-Privilege Cloud Roles:** Worker requires read/delete permissions only on the SQS queue. Remediation engine operates with fine-grained action boundaries.
2. **Controlled Dry-Run Default:** Even in `APP_MODE=live`, `DRY_RUN=True` remains active by default unless explicitly overridden by `LIVE_EXECUTION_ENABLED=True` and confirmed by a human operator.
3. **Audit Immutability:** Remediation actions generate indelible audit records linked to the specific operator session and CloudTrail event ID.
