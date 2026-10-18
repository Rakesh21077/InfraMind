# InfraMind — 5-Minute Demonstration Script & Storyboard

**Project:** InfraMind — AI Cloud Security Guardrail for Startups & IT  
**Format:** Live Video Walkthrough & Presentation  
**Target Duration:** Exactly 5:00 minutes  
**Presenter:** Engineering Lead / Presenter  

---

## 🎬 Video Storyboard & Timeline

| Timestamp | Phase | Visual / On-Screen Focus | Key Talking Points |
|---|---|---|---|
| **0:00 – 1:00** | Problem Statement & Background | Slide Deck / Cloud Breaches | The rapid pace of cloud adoption leaves startups vulnerable to alert fatigue, exposed S3 buckets, and leaked IAM keys. |
| **1:00 – 1:30** | System Architecture | Architecture Diagram | InfraMind combines AMD Instinct GPU LLM inference (ROCm vLLM), a Streamlit console, and Boto3 auto-patching with human approval. |
| **1:30 – 3:00** | Scenario A: Public S3 Bucket | Streamlit Dashboard (`Active Threat Dashboard`) | Ingesting `evt-101`, running AI analysis, evaluating blast radius (8/10), reviewing `fix_s3_bucket`, and executing safe dry-run patch. |
| **3:00 – 4:00** | Scenario B: Compromised IAM Key | Streamlit Dashboard | Ingesting `evt-102`, AI threat score (10/10), target user validation, and executing non-destructive `revoke_iam_key` deactivation. |
| **4:00 – 4:30** | Incident Time-Machine | Streamlit Chat Tab | Querying natural-language audit questions ("What API keys were flagged?"). |
| **4:30 – 5:00** | Safety Controls & Conclusion | Metric Cards & Architecture Summary | Defense-in-depth: default dry-run simulation, human-in-the-loop approval, and production impact. |

---

## 🎙️ Verbatim Presenter Script

### [0:00 – 1:00] The Cloud Security Dilemma
*(Screen: Slide 2 & 3 or InfraMind Header)*
> "Hello everyone. Welcome to **InfraMind** — an AI-driven cloud security guardrail built for startups and IT engineering teams.
>
> Today, cloud breaches happen in seconds. A single developer accidentally committing an AWS access key to a public GitHub repository, or an admin creating an S3 bucket with public read-write permissions, can cost a startup millions in data loss or ransom.
>
> But the core problem isn't lack of alerts—it's **alert fatigue**. CloudTrail generates thousands of raw JSON lines per hour. Small engineering teams lack the dedicated 24/7 SecOps personnel needed to parse these logs, estimate blast radius, and safely execute manual AWS remediation scripts without breaking production.
>
> That is the problem InfraMind solves."

---

### [1:00 – 1:30] Architecture & Operating Modes (Version 2)
*(Screen: Slide 5 — Architecture Diagram & Terminal)*
> "Here is our Version 2 architecture:
> - **Dual Operating Modes:** InfraMind supports both a 100% offline **Demo Mode** using curated mock logs, and an **AWS Live-Ingestion Mode** streaming genuine telemetry.
> - **Real-Time Telemetry Pipeline:** In live mode, AWS CloudTrail and GuardDuty stream via Amazon EventBridge into an encrypted Amazon SQS queue with an automated Dead-Letter Queue.
> - **Background Ingestion Worker:** A dedicated Python worker polls SQS, verifies S3 live posture in read-only mode, and atomically commits events to an ACID SQLite store using Write-Ahead Logging.
> - **Inference Engine:** An open-weights large language model (Llama-3-8B-Instruct) served via an **AMD Instinct GPU endpoint** utilizing **AMD ROCm and the vLLM serving container** (or local Ollama). For offline resilience, our engine features an instant deterministic fallback with in-memory caching.
> - **Operator Console:** An auto-refreshing Streamlit dashboard monitoring SQS queue depth and worker health with human-in-the-loop oversight.
> - **Remediation Engine:** Production-grade Python scripts using AWS Boto3 that enforce defense-in-depth: dry-run simulations by default, operator approval checkboxes, and identity validation."

---

### [1:30 – 3:00] Scenario A: Public S3 Bucket Auto-Patch
*(Action: Open Browser to `http://localhost:8501` on the "Active Threat Dashboard" tab)*
> "Let's see InfraMind in action. Here on our **Active Threat Dashboard**, we see an alert flagged from CloudTrail:
> `evt-101`: `PutBucketAcl` on `inframind-customer-data-backup`.
>
> Notice that telemetry shows public read-write permissions were granted to the global AllUsers group.
>
> Let's click **'🤖 Analyze Alert via AMD GPU'**.
>
> *(Click Button)*
>
> Instantly, our model evaluates the telemetry and populates our threat card:
> - **Threat Severity:** `CRITICAL`
> - **Threat Score:** `9 / 10`
> - **Blast Radius:** `8 / 10` — highlighting immediate risk of PII data exposure.
> - **Recommended Action:** `fix_s3_bucket`
>
> Now observe our **Controlled Remediation Console**. InfraMind never makes autonomous changes without human confirmation. The console clearly shows the exact target bucket.
>
> I check the authorization box:
> *'I authorize and approve executing fix_s3_bucket on target resource inframind-customer-data-backup.'*
>
> And click **'⚡ Approve & Execute Patch'**.
>
> *(Click Button)*
>
> Look at the result:
> **`🛡️ Simulation Complete: Dry run only. No AWS changes were made.`**
>
> Because our environment is safely configured with `DRY_RUN=True`, InfraMind simulates the API call, verifies that all four public-access block flags would be enabled, and protects our live cloud environment from unintended disruption."

---

### [3:00 – 4:00] Scenario B: Compromised IAM Key Revocation
*(Action: Scroll down to `evt-102`)*
> "Next, let's look at Scenario B: `evt-102`.
>
> Here, an active IAM access key `AKIAIOSFODNN7EXAMPLE` was leaked in a public code repository for user `demo-compromised-user`.
>
> Let's click **'🤖 Analyze Alert via AMD GPU'**.
>
> *(Click Button)*
>
> The AI flags this with a **Threat Score of 10 / 10** and a **Blast Radius of 9 / 10**.
>
> Our remediation engine binds the fix to the verified IAM username `demo-compromised-user`. Notice an essential safety rule: InfraMind **never deletes the access key**. Instead, it sets the status to `Inactive`. This preserves the key for CloudTrail audit trails and forensic investigations. Furthermore, our engine includes hardcoded guardrails that block automated deactivation of root account credentials.
>
> I check the operator approval box and click **'Approve & Execute Patch'**. The key deactivation is safely simulated, logged, and updated in our incident console."

---

### [4:00 – 4:30] Incident Time-Machine (Conversational AI Assistant)
*(Action: Click on the '🤖 Incident Time-Machine (AI Assistant)' Tab)*
> "Now let's switch to our second tab: the **Incident Time-Machine**.
>
> Security analysts often need to interrogate their incident history using natural language.
>
> Let's click our suggested question:
> **'🔑 What API keys were flagged?'**
>
> *(Click Button)*
>
> Immediately, our assistant returns a structured audit:
> It identifies access key `AKIAIOSFODNN7EXAMPLE` for `demo-compromised-user` and `AKIA222233334444EXMP` for `contractor-external-dev`, along with their current statuses.
>
> Let's ask:
> **'Which incidents are critical?'**
>
> *(Type or click)*
>
> The assistant filters through all records, returning both our public S3 bucket and leaked IAM key with their corresponding threat scores."

---

### [4:30 – 5:00] Safety Controls & Business Impact
*(Action: Highlight Sidebar Metrics and Executive KPIs)*
> "To summarize, InfraMind provides three critical innovations:
> 1. **AI-Driven Threat Prioritization:** Translating dense JSON logs into actionable threat scores and blast radius estimates using AMD GPU-accelerated LLMs.
> 2. **Controlled Auto-Patching:** Standardized, test-verified Boto3 remediation scripts that eliminate hours of manual console navigation.
> 3. **Defense-in-Depth:** Default dry-run simulations, mandatory human approval, and sanitization of all credentials and tokens.
>
> With a complete test suite of **63 automated unit tests** passing with zero errors across remediation, agent analysis, persistent database operations, and live SQS ingestion, InfraMind transforms cloud security from reactive panic into proactive, controlled guardrails.
>
> Thank you!"

---

## 🛠️ Offline & Fallback Execution Notes
- If running without an internet connection or without an active AMD ROCm container, the local application automatically switches to its **Deterministic Rule-Based Engine**.
- All threat scores, blast-radius metrics, and incident chat answers remain fully functional.
- The UI will clearly reflect `"Offline Fallback (Deterministic Rule-Based)"` in the AI Engine field, ensuring total honesty during evaluations.
