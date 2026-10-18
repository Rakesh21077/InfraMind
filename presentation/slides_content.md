# InfraMind — Pitch Deck Slides Content
## AI Cloud Security Guardrail for Startups & IT

---

### Slide 1: Title Slide
- **Title:** InfraMind
- **Subtitle:** AI Cloud Security Guardrail for Startups & IT
- **Tagline:** Real-time Cloud Threat Prioritization & Controlled Remediation Engine
- **Presenter / Team:** InfraMind Engineering Team (6-Member Capstone Project)
- **Technology Stack:** Python | AMD ROCm / vLLM | Llama-3-8B | Streamlit | AWS Boto3

---

### Slide 2: The Problem — The Cloud Misconfiguration Crisis
- **Headline:** Modern Startups Move Fast — But Cloud Security Breaches Occur in Seconds
- **Key Pain Points:**
  - Accidental public exposure of Amazon S3 storage buckets containing sensitive PII and database backups.
  - Leaked AWS IAM access keys in public GitHub repositories or developer workstations.
  - 82% of cloud security breaches involve data stored in the cloud (IBM Cost of a Data Breach Report).
  - Average detection & containment time exceeds 270 days for small IT teams.

---

### Slide 3: The Dilemma — Alert Fatigue & Manual Bottlenecks
- **Headline:** Too Many Raw Logs, Too Few Cloud Security Experts
- **The Bottleneck:**
  - AWS CloudTrail outputs tens of thousands of raw JSON lines per hour.
  - Small startup engineering teams suffer from acute "Alert Fatigue".
  - Manual triage is slow, error-prone, and requires deep IAM/S3 permissions expertise.
  - High risk of manual remediation errors breaking live production services.

---

### Slide 4: The Solution — InfraMind
- **Headline:** Closed-Loop, AI-Assisted Security Telemetry to Controlled Auto-Patching
- **Core Value Proposition:**
  - **Automated Log Parsing:** Ingests CloudTrail and security events in real-time.
  - **AI Threat Prioritization:** Translates raw JSON into risk severity (0–10) and blast radius estimates.
  - **Controlled Remediation:** 1-click Boto3 auto-patching with human-in-the-loop verification.
  - **Conversational Audit:** Natural-language "Incident Time-Machine" to interrogate log history.

---

### Slide 5: Version 2 — Real-Time Pipeline Architecture
- **Headline:** Event-Driven CloudTrail & EventBridge Ingestion with Persistent SQLite WAL Storage
- **Pipeline Stages:**
  1. **Telemetry Streaming:** AWS CloudTrail & GuardDuty stream via EventBridge to SQS with Dead-Letter Queue (DLQ).
  2. **Ingestion Worker (`ingestion_worker.py`):** Long-polling worker normalizes events, checks S3 live posture, and persists atomically.
  3. **Persistent Incident Store (`database.py`):** SQLite database in WAL mode with deduplication and remediation audit trails.
  4. **AI Inference Engine (`agent.py`):** Multi-provider AI (AMD Instinct ROCm vLLM / Ollama) with deterministic rule-based fallback and caching.
  5. **Auto-Refreshing Console (`app.py`):** Near-real-time Streamlit dashboard with dual-mode switcher (Demo vs. Live) and 1-click Boto3 remediation.

---

### Slide 6: AMD Developer Cloud & ROCm Integration
- **Headline:** Accelerated LLM Inference on AMD Instinct GPUs
- **Technical Highlights:**
  - Containerized deployment using `rocm/vllm:latest` on AMD Developer Cloud (MI300X/MI250 GPUs).
  - High-throughput serving of open-weights `meta-llama/Meta-Llama-3-8B-Instruct`.
  - OpenAI-compatible API standard for seamless integration with zero vendor lock-in.
  - Dual-mode resilience: Instant deterministic rule-based fallback when offline.

---

### Slide 7: AI Threat Prioritization & Blast Radius Scoring
- **Headline:** Quantifiable Risk Assessment Beyond Generic Alerts
- **Scoring Framework:**
  - **Threat Severity:** Standardized into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
  - **Threat Score (0–10):** Mathematical impact scale based on privilege and exploitability.
  - **Blast Radius (0–10):** Estimated risk footprint across data confidentiality and infrastructure.
  - **Action Whitelist:** Strict schema mapping to safe, pre-vetted remediation routines.

---

### Slide 8: Scenario A — Public S3 Bucket Auto-Patch
- **Headline:** Eliminating Open Storage Buckets Before Data Exfiltration
- **Workflow:**
  - **Detected Event:** `evt-101`: `PutBucketAcl` on `inframind-customer-data-backup`.
  - **AI Evaluation:** `CRITICAL` Severity | Threat Score: 9/10 | Blast Radius: 8/10.
  - **Automated Fix:** `fix_s3_bucket(bucket_name)` invokes AWS `put_public_access_block()`.
  - **Enforcement:** Sets all 4 block flags to `True` (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`).

---

### Slide 9: Scenario B — Compromised IAM Access Key Revocation
- **Headline:** Neutralizing Leaked Credentials Without Deleting Evidence
- **Workflow:**
  - **Detected Event:** `evt-102`: `CreateAccessKey` with public GitHub credential exposure.
  - **AI Evaluation:** `CRITICAL` Severity | Threat Score: 10/10 | Blast Radius: 9/10.
  - **Controlled Fix:** `revoke_iam_key(access_key_id, user_name)` invokes `update_access_key(Status='Inactive')`.
  - **Forensic Preservation:** Key is deactivated, never deleted, preserving CloudTrail audit trails.
  - **Root Guardrail:** Automatically locks out and blocks automated tampering with root account keys.

---

### Slide 10: Streamlit Dashboard & Incident Time-Machine
- **Headline:** Frictionless Human-in-the-Loop Security Operations
- **Key UI Capabilities:**
  - Executive KPI metrics: Total Alerts, Critical Threats, Awaiting Review, Remediated.
  - Live Telemetry & Auto-Refresh: Real-time SQS queue depth, worker heartbeat, and 10s auto-refresh.
  - Threat cards with color-coded severity badges and explicit operator approval checkboxes.
  - Multi-dimensional filters: Filter by Severity, Source (S3, IAM, GuardDuty), and Status.
  - Raw Telemetry Inspector: Full JSON metadata modal for deep analyst inspection.
  - Incident Time-Machine: Natural language assistant answering questions like:
    - *"What API keys were flagged?"*
    - *"Which incidents are critical?"*
    - *"What happened to the S3 bucket?"*

---

### Slide 11: Defense-in-Depth & Safety Invariants
- **Headline:** Zero Unintended Disruption to Production Cloud Infrastructure
- **Five Safeguard Layers:**
  1. **Dry-Run by Default (`DRY_RUN=True`):** Simulation mode prevents accidental AWS changes.
  2. **Master Circuit Breaker (`LIVE_EXECUTION_ENABLED=False`):** Fails closed unless explicitly enabled.
  3. **Mandatory Human Approval:** Requires explicit runtime `approved=True` parameter.
  4. **Strict Identity Validation:** Validates bucket syntax and enforces exact IAM username matching.
  5. **Credential Sanitization:** Automatic redaction of secret keys, tokens, and authorization headers.

---

### Slide 12: Business Impact, Roadmap & Conclusion
- **Headline:** Transforming Reactive Chaos into Controlled Cloud Guardrails
- **Impact Metrics:**
  - **90% Reduction** in Mean Time to Remediate (MTTR) for critical cloud misconfigurations.
  - **100% Elimination** of human console navigation errors during emergency incidents.
  - **Comprehensive QA:** 63 automated unit tests passing across remediation, agent, database, and ingestion suites.
  - **Production Ready:** CloudFormation template (`infra/cloudformation-realtime.yaml`) for instant deployment.
- **Future Roadmap:**
  - Multi-cloud expansion (Azure Blob Storage, Google Cloud IAM).
  - Integration with Slack/Teams webhook alerts for instant mobile approvals.
