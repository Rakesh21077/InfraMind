# InfraMind — AI Cloud Security Guardrail for Startups & IT

![InfraMind Banner](https://img.shields.io/badge/Security-AI%20Guardrail-blue)
![Python](https://img.shields.io/badge/Python-3.12-brightgreen)
![AWS Boto3](https://img.shields.io/badge/AWS-Boto3%20Remediation-orange)
![AMD ROCm](https://img.shields.io/badge/AMD%20ROCm-vLLM%20Serving-red)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![Tests](https://img.shields.io/badge/Tests-50%20Passed-success)
![Safety](https://img.shields.io/badge/Dry--Run-Enforced%20by%20Default-blueviolet)

InfraMind is an AI-assisted cloud security threat detection, prioritization, and controlled auto-patching engine built for modern startups and IT engineering teams. It ingests AWS CloudTrail security events, evaluates risk severity (0–10) and blast radius using open-weights LLMs accelerated on AMD Instinct GPUs, and provides single-click, human-approved Boto3 automated cloud remediations.

---

## 1. Project Introduction
Cloud infrastructure moves fast, but security breaches happen in seconds. Startups and high-growth engineering teams lack dedicated 24/7 Security Operations Centers (SOC). When developers inadvertently create public Amazon S3 buckets or leak AWS IAM access keys in public code repositories, automated attacker bots exploit them within minutes.

InfraMind closes the gap between raw telemetry and safe cloud remediation through a human-in-the-loop, AI-assisted guardrail.

---

## 2. Problem Statement
1. **Acute Alert Fatigue:** AWS CloudTrail produces tens of thousands of raw JSON lines per day. Critical misconfigurations drown in operational noise.
2. **Specialized IAM/S3 Complexity:** Interpreting bucket ACLs, wildcard bucket policies, and cross-account IAM permissions requires senior cloud security expertise.
3. **The Manual Remediation Bottleneck:** Navigating the AWS Management Console during high-stress security incidents is slow, error-prone, and risks breaking live production dependencies.

---

## 3. Proposed Solution
InfraMind implements an automated, closed-loop telemetry pipeline:
- **Real-Time Log Ingestion:** Parses CloudTrail and service events into normalized incident records.
- **AI-Powered Threat Prioritization:** Evaluates incident severity, calculates blast radius (0–10), and generates plain-English risk summaries using Llama-3-8B.
- **Controlled Auto-Patching:** Standardized, test-verified Boto3 remediation scripts that execute safely with default dry-run simulation and explicit human authorization.
- **Incident Time-Machine:** Conversational assistant for historical log queries and compliance audits.

---

## 4. Main Features
- 🚨 **Active Threat Dashboard:** Interactive incident alert feed with color-coded severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- 🤖 **AMD GPU / vLLM Accelerated Inference:** Evaluates risk via open-weights `meta-llama/Meta-Llama-3-8B-Instruct` served with ROCm on AMD Instinct GPUs.
- 🛡️ **Safe Dry-Run Simulations by Default:** Zero accidental cloud mutations. `DRY_RUN=True` and `LIVE_EXECUTION_ENABLED=False` protect production.
- ⚡ **1-Click Controlled Patching:**
  - **S3 Public Bucket Remediation:** Applies AWS S3 Public Access Block (enabling all 4 restriction flags).
  - **IAM Access Key Revocation:** Safely sets access keys to `Inactive` without deleting them, preserving CloudTrail forensic trails.
- 🔒 **Defense-in-Depth Guardrails:** Mandatory operator approval checkboxes, exact identity validation, and automated lockout of root account keys.
- 💬 **Incident Time-Machine:** Natural-language conversational assistant answering audit inquiries.
- 🧪 **Comprehensive Quality Assurance:** 50 automated offline unit tests with 100% pass rate.

---

## 5. System Architecture

```text
[ AWS Cloud Logs / CloudTrail ]
               │
               ▼
[ Telemetry Ingestion (mock_logs.json / Upload) ]
               │
               ▼
[ AI Threat Analysis Engine (agent.py) ]
   ├── Primary: AMD Instinct GPU (ROCm + vLLM)
   ├── Alternative: Local Ollama (llama3:8b)
   └── Resilient Fallback: Deterministic Rule-Based Engine
               │
               ▼
[ Operator Console (app.py - Streamlit) ]
   ├── Executive Metric KPIs (Total, Critical, Pending, Remediated)
   ├── Threat Severity & Blast Radius Display
   └── Human Authorization Checkbox (approved=True)
               │
               ▼
[ Guardrail Remediation Engine (remediation.py) ]
   ├── Dry-Run Mode: Safe Simulation Output (SIMULATED)
   └── Live Execution: AWS Boto3 (put_public_access_block / update_access_key)
```

---

## 6. Technology Stack
- **Backend & Logic:** Python 3.10+ (tested on Python 3.12)
- **Cloud SDK:** AWS Boto3 & Botocore
- **Web UI & Dashboard:** Streamlit
- **LLM Serving & Inference:** AMD Developer Cloud (ROCm vLLM) / Ollama / OpenAI Standard API
- **Testing:** Python `unittest` & `unittest.mock` (zero external test dependencies)
- **Configuration:** `python-dotenv`
- **Presentation Deck:** `python-pptx`

---

## 7. Project Folder Structure

```text
InfraMind-Team/
|
|-- app.py                     # Streamlit web dashboard & Incident Time-Machine
|-- agent.py                   # AI log evaluation engine & conversational query solver
|-- remediation.py             # Member 3: S3 & IAM cloud remediation scripts & safety gates
|-- mock_logs.json             # Realistic CloudTrail security incident events (S3 & IAM)
|-- requirements.txt           # Unified project runtime dependencies
|-- .env.example               # Safe environment configuration template
|-- .gitignore                 # Excludes .env, virtual environments, and caches
|-- deploy_amd.sh              # AMD ROCm vLLM docker container deployment script
|-- README.md                  # Master project architecture and operational guide
|-- README_MEMBER3.md          # Dedicated technical guide for Member 3 module
|-- sample_incidents.json      # Sample data contract for Member 2 & Member 5
|-- build_pitch_deck.py        # Script generating 12-slide PowerPoint presentation
|
|-- docs/
|   `-- architecture.md        # Technical architecture, sequence diagrams, and risk notes
|
|-- presentation/
|   |-- InfraMind_Pitch_Deck.pptx # Editable 12-slide widescreen PowerPoint pitch deck
|   |-- slides_content.md      # Markdown transcript of all 12 pitch deck slides
|   `-- demo_script.md         # Timed 5-minute presenter script & video storyboard
|
|-- tests/
|   |-- __init__.py            # Test package marker
|   |-- test_remediation.py    # 34 Member 3 remediation & safety tests
|   `-- test_agent.py          # 16 AI analysis, LLM client, and chat history tests
```

---

## 8. Prerequisites (Windows / Linux)
- **Operating System:** Windows 10/11 (64-bit) or Linux (Ubuntu 22.04+).
- **Python:** Python 3.10, 3.11, or 3.12 (verified with Python 3.12.10).
- **Terminal:** Windows PowerShell, Windows Terminal, or Bash.
- **Git:** Installed and configured.

Verify Python installation:
```powershell
python --version
```

---

## 9. Windows Step-by-Step Setup

```powershell
# 1. Clone or navigate to the repository
cd C:\Users\santh\InfraMind-Team

# 2. Create the Python virtual environment
python -m venv .venv

# 3. Allow execution for the current PowerShell session (if restricted)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 4. Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

---

## 10. Dependency Installation

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## 11. Environment Configuration

Copy the template `.env.example` into a local `.env`:
```powershell
Copy-Item .env.example .env
```

Contents of `.env`:
```ini
# AI / LLM Serving Configuration (AMD GPU Endpoint)
AMD_ENDPOINT_URL="http://localhost:11434/v1"
MODEL_NAME="llama3:8b"

# AWS Configuration
AWS_DEFAULT_REGION="us-east-1"

# Member 3: Auto-Patch & Remediation Safety Controls
# When DRY_RUN is True, all remediation actions run in simulation mode without calling AWS
DRY_RUN="True"

# Master circuit breaker for live AWS API remediation calls.
# Requires both DRY_RUN=False and LIVE_EXECUTION_ENABLED=True plus human approval to execute.
LIVE_EXECUTION_ENABLED="False"
```

> **Safety Notice:** `.env` is excluded from Git via `.gitignore`. Never hardcode AWS secrets or tokens.

---

## 12. Local Ollama Alternative Setup (Optional)
If running a local LLM on developer machines:
1. Install Ollama from [ollama.com](https://ollama.com).
2. Pull and start the Llama-3 model:
   ```bash
   ollama run llama3:8b
   ```
3. Set `AMD_ENDPOINT_URL="http://localhost:11434/v1"` in `.env`.

*Note: If no local model is running, InfraMind automatically falls back to its built-in deterministic rule-based engine.*

---

## 13. AMD Developer Cloud Endpoint Configuration
For high-performance GPU serving on AMD Developer Cloud (Instinct MI300X/MI250 GPUs):
1. Execute the containerized deployment script:
   ```bash
   bash deploy_amd.sh
   ```
   Or launch manually with Docker:
   ```bash
   docker run -d --rm \
     --network=host \
     --device=/dev/kfd --device=/dev/dri \
     --group-add video \
     --ipc=host \
     rocm/vllm:latest \
     python3 -m vllm.entrypoints.openai.api_server \
       --model meta-llama/Meta-Llama-3-8B-Instruct \
       --port 8000
   ```
2. In your `.env`, update the endpoint URL:
   ```ini
   AMD_ENDPOINT_URL="http://<YOUR_AMD_INSTANCE_IP>:8000/v1"
   MODEL_NAME="meta-llama/Meta-Llama-3-8B-Instruct"
   ```

---

## 14. Running the Streamlit Application

Launch the interactive web console:
```powershell
streamlit run app.py
```

Open your browser to:
```text
http://localhost:8501
```

---

## 15. How the AI Log Analysis Works
When an operator clicks **"🤖 Analyze Alert via AMD GPU"**:
1. `agent.py` validates the log dictionary.
2. Dispatches telemetry to the configured model endpoint with strict JSON schema instructions.
3. Normalizes priority into `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
4. Computes a threat score (0–10) and blast radius risk estimate (0–10).
5. Maps the threat to a pre-vetted remediation action (`fix_s3_bucket`, `revoke_iam_key`, or `none`).
6. If the model endpoint is unreachable or times out, the resilient deterministic engine produces the calibrated assessment instantly.

---

## 16. How to Use the Incident Time-Machine
1. Click the **"🤖 Incident Time-Machine (AI Assistant)"** tab.
2. Click any of the pre-built audit query buttons or type a custom question:
   - *"What API keys were flagged?"*
   - *"Which incidents are critical?"*
   - *"What happened to the S3 bucket?"*
   - *"What remediation was recommended for evt-101?"*
   - *"Which incidents are still unresolved?"*
3. The assistant interrogates the loaded security logs and audit history, returning structured markdown summaries.

---

## 17. How the Remediation Functions Work

### S3 Public Bucket Remediation (`fix_s3_bucket`)
- **API Call:** AWS S3 `put_public_access_block()`
- **Configuration:** Enforces all four flags:
  - `BlockPublicAcls = True`
  - `IgnorePublicAcls = True`
  - `BlockPublicPolicy = True`
  - `RestrictPublicBuckets = True`

### IAM Access Key Revocation (`revoke_iam_key`)
- **API Call:** AWS IAM `update_access_key(Status='Inactive')`
- **Forensic Guarantee:** Deactivates the key immediately while preserving it for CloudTrail forensic investigation. Never deletes keys.

---

## 18. How Dry-Run and Explicit Approval Work
InfraMind uses multi-layer defense-in-depth:
1. **Simulation Default:** `DRY_RUN=True` simulates all actions and returns `SIMULATED`.
2. **Circuit Breaker:** `LIVE_EXECUTION_ENABLED=False` prevents live cloud calls unless explicitly enabled.
3. **Mandatory Human Approval:** In the UI, the operator must review the exact target resource and check the authorization box before clicking **"⚡ Approve & Execute Patch"**.
4. **Root Protection:** Automated deactivation of root account credentials is hardcoded as `BLOCKED`.

---

## 19. How to Run Automated Unit Tests

Run the complete 50-test automated test suite:
```powershell
python -m unittest discover -s tests -v
```

Expected output:
```text
Ran 50 tests in 0.910s

OK
```
- All tests execute 100% offline. Zero AWS network calls or real credentials required.

---

## 20. Troubleshooting

| Issue | Cause | Resolution |
|---|---|---|
| `running scripts is disabled` | PowerShell execution policy restricted | Run `Set-ExecutionPolicy -Scope Process Bypass`. |
| `ModuleNotFoundError: No module named 'streamlit'` | Virtual environment not activated | Run `.\.venv\Scripts\Activate.ps1` and verify `pip list`. |
| Remediation returns `SIMULATED` | Safe local mode is active (`DRY_RUN=True`) | Expected behavior. For real cloud changes, configure valid AWS credentials, set `DRY_RUN=False`, `LIVE_EXECUTION_ENABLED=True`, and pass `approved=True`. |
| AI Engine reports `Offline Fallback` | AMD/Ollama model server not running | Application remains fully functional via deterministic rule-based analysis. Start Ollama (`ollama run llama3:8b`) or AMD vLLM container if LLM output is desired. |
| Remediation returns `BLOCKED` | Approval checkbox unchecked or root user targeted | Check the operator authorization box. If targeting root account, use AWS Management Console manually. |

---

## 21. Security & Operational Limitations
- **Blast Radius Score:** The blast radius score (0–10) is an estimated risk proxy based on telemetry indicators. It does not perform live dependency graph traversal unless integrated with production asset management systems.
- **Service Disruption Notice:** Setting an IAM key to `Inactive` or enabling Public Access Block may interrupt dependent services that intentionally rely on anonymous read access or that key.

---

## 22. Member 3 & Member 5 Interface Information
- **Member 3 (Auto-Patch Engine):**
  - File: [`remediation.py`](file:///C:/Users/santh/InfraMind-Team/remediation.py)
  - Documentation: [`README_MEMBER3.md`](file:///C:/Users/santh/InfraMind-Team/README_MEMBER3.md)
  - Functions: `fix_s3_bucket(bucket_name, *, approved=False)` and `revoke_iam_key(access_key_id, user_name=None, *, approved=False)`
- **Member 5 (Console & UI):**
  - File: [`app.py`](file:///C:/Users/santh/InfraMind-Team/app.py)
  - Status Handling: Handles `SIMULATED` (info alert), `SUCCESS` (green success alert), `BLOCKED` (warning alert), and `FAILED` (error alert).
