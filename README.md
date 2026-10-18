# InfraMind — Autonomous Cloud Security & Threat Triage Engine

InfraMind is an AI-powered cloud security threat detection, prioritization, and remediation engine built for high-throughput AWS security telemetry. It ingests AWS Security Hub findings (ASFF), performs deterministic evidence-based risk prioritization, generates validated structured explanations using open-weights LLMs, and coordinates safe human-in-the-loop remediations via Boto3.

---

## 🏛️ System Architecture

```text
[ AWS Security Hub / ASFF JSON ]
                │
                ▼
  [ Ingestion & Sanitization Engine ] ──► Extracts Resources, Preserves Raw Audit Evidence
        (inframind/ingestion.py)           Sanitizes Untrusted Text (Prompt Injection Defense)
                │
                ▼
  [ Deterministic Prioritization ]    ──► Separates Observed Facts, Inferred Risks, & Unknowns
     (inframind/prioritization.py)        Independent Rule Engine (Score 0-100, Priority Tiers)
                │
                ▼
  [ Modular Inference Service ]       ──► Sandboxed Prompting & Structured Pydantic Output
       (inframind/inference.py)           Explains Impact, Gaps, Investigation Steps, Predefined Actions
        ├── Ollama (qwen2.5:7b) [Local Windows]
        └── ROCm vLLM (OpenAI-compatible) [AMD GPU Cloud]
                │
                ▼
  [ Remediation Bridge & Safety ]     ──► Multi-gate Safety Protocol (DRY_RUN, LIVE_EXECUTION, approved)
   (inframind/remediation_bridge.py)      Pre-validates Parameters, Never Executes Model Code
                │
                ├──► [ Boto3 Remediation Engine (remediation.py) ] (Member 3)
                ├──► [ Operator Dashboard / Console (app.py) ] (Member 5)
                └──► [ Evolus Business-Agent Workflow ] (Hackathon Business Agent)
```

---

## 👥 Team Responsibilities & Module Boundaries

| Role | Responsibility | Key Files |
|---|---|---|
| **Member 1** | AMD GPU Infrastructure & vLLM Serving | `deploy_amd.sh` |
| **Member 2** | Log Ingestion & Threat Detection | `mock_logs.json` |
| **Member 3** | Auto-Patch & Boto3 Remediation Functions | `remediation.py`, `tests/test_remediation.py` |
| **Member 4 (This Module)** | **AI Threat Ingestion, Prioritization & Explanation Backend** | `inframind/`, `agent.py`, `tests/test_triage.py` |
| **Member 5** | Human-in-the-Loop Streamlit Dashboard | `app.py` |
| **Member 6** | Integration, CI/CD, & Cloud Audit Trail | `.github/`, audit logging |

---

## 🚀 Key Features of the Threat Triage Backend

1. **ASFF Parsing & Ingestion (`inframind.ingestion`):**
   - Ingests standard AWS Security Hub `{"Findings": [...]}` arrays, bare lists, and flat incident payloads.
   - Preserves original raw finding payloads (`raw_evidence`) for forensic auditability.
   - Sanitizes untrusted text and implements prompt injection boundaries (`<untrusted_finding_data>`).

2. **Deterministic Risk Prioritization (`inframind.prioritization`):**
   - Independent rule-based scoring policy producing tiers: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
   - Epistemic clarity: rigorously partitions evidence into **Observed Facts**, **Inferred Risks**, and **Unknown Information**.
   - Non-assumptive safety: Missing evidence is **never** treated as proof of safety.
   - Deterministic tie-breaking: Sorts by priority tier, score descending, and finding ID.

3. **Modular LLM Inference Engine (`inframind.inference`):**
   - Modular provider interface (`BaseInferenceProvider`, `OllamaProvider`, `AMDvLLMProvider`, `MockInferenceProvider`).
   - Defaults to local Ollama on Windows running `qwen2.5:7b`.
   - Ready for drop-in transition to AMD Developer Cloud ROCm vLLM endpoints.
   - Structured JSON validation via Pydantic (`StructuredLLMResponse`).
   - Complete fault tolerance: Fallback logic preserves deterministic assessment if the model server is offline, times out, or returns malformed JSON.

4. **Safety-First Remediation Bridge (`inframind.remediation_bridge`):**
   - Maps predefined action identifiers (`RESTRICT_S3_PUBLIC_ACCESS`, `REVOKE_IAM_KEY`) to Member 3's `remediation.py`.
   - Respects all three safety gates: `DRY_RUN=True` default, `LIVE_EXECUTION_ENABLED=False` master breaker, and `approved=True` human operator approval.
   - Generates read-only remediation previews for dashboard display without making AWS API calls.

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- **Operating System:** Windows 10/11 or Linux.
- **Python:** Python 3.10+ (tested with Python 3.12 and 3.14).
- **Ollama:** Installed locally on Windows (for local LLM inference).

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Setup Local Ollama Model
```bash
# Pull the target open-weights model
ollama pull qwen2.5:7b

# Verify Ollama is running at http://localhost:11434
curl http://localhost:11434/api/tags
```

### 4. Configure Environment
Copy the example environment template:
```powershell
Copy-Item .env.example .env
```
Default configuration settings:
```ini
INFERENCE_PROVIDER="ollama"
OLLAMA_BASE_URL="http://localhost:11434"
MODEL_NAME="qwen2.5:7b"
LLM_TIMEOUT_SECONDS="30"
AWS_DEFAULT_REGION="us-east-1"
DRY_RUN="True"
LIVE_EXECUTION_ENABLED="False"
```

---

## 💻 Developer API & Usage Guide

### Programmatic Python Interface

Another developer (e.g. Member 5 building the UI or Member 6 building CI/CD) can consume the triage engine with a single function call:

```python
from inframind import triage_findings

# Ingest raw AWS Security Hub JSON
with open("security_hub_findings.json", "r") as f:
    raw_payload = f.read()

# Run full pipeline (Ingestion -> Scoring -> Ollama Explanation -> Action Preview)
result = triage_findings(raw_payload)

print(f"Total findings: {result.total_findings}")
print(f"Priority breakdown: {result.counts_by_priority}")

for item in result.findings:
    print(f"\n[{item.assessment.priority_tier}] {item.finding.title} (Score: {item.assessment.score})")
    print(f"Basis: {item.assessment.basis}")
    print(f"Observed Facts: {item.assessment.observed_facts}")
    print(f"Evidence Gaps:  {item.assessment.unknown_information}")
    print(f"AI Justification: {item.explanation.priority_justification}")
    print(f"Business Impact:  {item.explanation.business_impact_summary}")

    if item.explanation.recommended_action:
        print(f"Recommended Action: {item.explanation.recommended_action.action_id}")
        print(f"Remediation Preview: {item.remediation_preview}")
```

### Executing Approved Remediations
```python
from inframind import RemediationBridge

# Once the operator clicks 'Approve' in the dashboard:
rec = item.explanation.recommended_action
result = RemediationBridge.execute(rec, approved=True)

if result["status"] == "SUCCESS":
    print("Cloud resource safely remediated:", result["message"])
elif result["status"] == "SIMULATED":
    print("Dry-run simulation completed:", result["message"])
elif result["status"] == "BLOCKED":
    print("Safety gate blocked execution:", result["message"])
```

---

## 📋 Data Contract Schemas

### Input Schema (AWS Security Hub ASFF / JSON)
Accepts:
1. Standard ASFF JSON payload with top-level `"Findings": [...]`
2. Bare list of findings: `[{...}, {...}]`
3. Single finding dictionary: `{...}`
4. Flat incident dictionary (compatible with `sample_incidents.json`)

### Output Schema (`TriageBatchResult` JSON Example)
```json
{
  "total_findings": 1,
  "counts_by_priority": {
    "CRITICAL": 1
  },
  "provider_info": {
    "provider": "OllamaProvider",
    "model": "qwen2.5:7b"
  },
  "generated_at": "2026-10-18T09:17:02Z",
  "findings": [
    {
      "finding": {
        "id": "arn:aws:securityhub:us-east-1:123456789012:finding/s3-public-001",
        "title": "S3 bucket has public access block completely disabled",
        "description": "Amazon S3 bucket financial-data allows unrestricted public access.",
        "source": "AWS_SECURITY_HUB",
        "source_severity": "CRITICAL",
        "finding_types": ["Software and Configuration Checks/AWS Security Best Practices/Public"],
        "resources": [
          {
            "id": "arn:aws:s3:::financial-data",
            "type": "AwsS3Bucket",
            "region": "us-east-1",
            "details": {
              "AwsS3Bucket": {
                "PublicAccessBlockConfiguration": {
                  "BlockPublicAcls": false,
                  "IgnorePublicAcls": false,
                  "BlockPublicPolicy": false,
                  "RestrictPublicBuckets": false
                }
              }
            }
          }
        ]
      },
      "assessment": {
        "priority_tier": "CRITICAL",
        "score": 95.0,
        "basis": "Assigned priority CRITICAL (score 95.0/100) based on source severity CRITICAL with 2 verified fact(s)...",
        "observed_facts": [
          "Source reporting system classified severity as 'CRITICAL'.",
          "Resource configuration explicitly confirms lack of public access blocks or internet reachability."
        ],
        "inferred_risks": [
          "Storage service could contain sensitive business data vulnerable to unauthorized download if exposed."
        ],
        "unknown_information": [
          "Environment criticality (production vs staging/dev) is unknown from available resource tags.",
          "Data sensitivity and payload classification are unknown (no DLP or inventory scan attached)."
        ],
        "suggested_action_id": "RESTRICT_S3_PUBLIC_ACCESS"
      },
      "explanation": {
        "priority_justification": "Classified as CRITICAL because configuration confirms the bucket lacks all public access restrictions...",
        "business_impact_summary": "Unrestricted public access risks data exfiltration of internal customer and financial records...",
        "missing_evidence_notes": [
          "Verify data sensitivity via DLP or object inventory.",
          "Check CloudTrail access logs for unauthorized object downloads."
        ],
        "recommended_investigation_steps": [
          "Check bucket policy for wildcard principal access.",
          "Verify if bucket hosts static website assets or confidential datasets."
        ],
        "recommended_action": {
          "action_id": "RESTRICT_S3_PUBLIC_ACCESS",
          "target_resource_id": "financial-data",
          "target_resource_type": "AwsS3Bucket",
          "parameters": {
            "bucket_name": "financial-data"
          },
          "rationale": "Applying S3 Public Access Block immediately neutralizes anonymous internet exposure.",
          "requires_approval": true,
          "confidence": 0.85
        },
        "is_llm_available": true,
        "model_name": "qwen2.5:7b",
        "provider": "ollama"
      },
      "remediation_preview": {
        "status": "READY_FOR_APPROVAL",
        "action": "fix_s3_bucket",
        "target_resource": "financial-data",
        "target_type": "AwsS3Bucket",
        "parameters": {
          "bucket_name": "financial-data"
        },
        "rationale": "Applying S3 Public Access Block immediately neutralizes anonymous internet exposure.",
        "executable": true,
        "requires_approval": true
      }
    }
  ]
}
```

---

## ⚡ Mock-JSON Test Runner & Demo (`scripts/test_findings.py`)

A dedicated offline demonstration script is available under `scripts/test_findings.py` to triage synthetic AWS findings without requiring live AWS credentials or a running Ollama server.

### Available Synthetic Fixtures (`tests/fixtures/`)
- `findings_normal.json`: Complete synthetic batch (verified S3 exposure, incomplete evidence, medium config, unknown severity, prompt injection).
- `findings_s3_public.json`: Single verified public S3 bucket with production tag and missing public access block.
- `findings_empty.json`: Empty findings array (`{"Findings": []}`).
- `findings_incomplete.json`: Critical severity finding with missing telemetry and resource information.
- `findings_prompt_injection.json`: Malicious finding attempting to override prompt instructions and force INFORMATIONAL priority.
- `findings_malformed.json`: Deliberately truncated JSON testing error handling.

### Exact PowerShell Demo Commands:
```powershell
# 1. Run complete automated unit test suite (68 tests, 100% offline)
python -m unittest discover -v

# 2. Complete synthetic batch triage
python scripts/test_findings.py tests/fixtures/findings_normal.json

# 3. Single verified high-impact S3 public exposure
python scripts/test_findings.py tests/fixtures/findings_s3_public.json

# 4. Empty findings payload
python scripts/test_findings.py tests/fixtures/findings_empty.json

# 5. Critical finding with incomplete evidence (unknowns surfaced)
python scripts/test_findings.py tests/fixtures/findings_incomplete.json

# 6. Malicious prompt-injection finding (score & tier remain invariant)
python scripts/test_findings.py tests/fixtures/findings_prompt_injection.json

# 7. Malformed JSON rejection (exits with code 1 and readable error message)
python scripts/test_findings.py tests/fixtures/findings_malformed.json
```

---

## ⚡ Agent CLI Runner (`agent.py`)

For interactive or agent-based execution supporting both local Ollama and AMD endpoints:

```powershell
# 1. Run with live local Ollama (qwen2.5:7b)
python agent.py --provider ollama

# 2. Run offline with mock inference (no Ollama required)
python agent.py --mock-llm

# 3. Triage a specific AWS ASFF JSON file
python agent.py --file tests/fixtures/findings_normal.json

# 4. Include dry-run remediation simulation for recommended actions
python agent.py --simulate-remediation

# 5. Output raw JSON (for piping into other scripts or Evolus agents)
python agent.py --mock-llm --json

# 6. Save triage results to file
python agent.py --mock-llm --output triage_report.json
```

---

## 🧪 Automated Testing

InfraMind includes comprehensive, 100% offline unit tests covering:
- Ingestion of standard and edge-case ASFF payloads.
- Malformed JSON resilience and untrusted text sanitization.
- Prompt injection attack defense (verifying deterministic score and tier invariance).
- Deterministic prioritization (facts, inferences, unknowns, sorting).
- Inference resilience (offline Ollama fallback, malformed LLM JSON).
- AMD ROCm vLLM inference resilience (HTTP errors, timeouts, connection drops, empty choices, schema validation).
- Safety gates and Boto3 remediation dispatch.
- Integration boundaries: confirming previews and triage NEVER trigger execution.
- CLI runner execution, exit codes, and report generation.

Run all tests:
```powershell
python -m unittest discover -v
```

Expected output:
```text
Ran 80 tests in ~6s
OK
```

---

## 🚀 AMD Deployment Readiness & Evolus Workflow

### AMD Cloud Deployment (ROCm + vLLM)

The `deploy_amd.sh` script deploys an OpenAI-compatible vLLM serving container on AMD ROCm GPU infrastructure (e.g. AMD Developer Cloud instances with AMD Instinct MI210/MI250/MI300 GPUs or ROCm-compatible Linux hosts).

#### Prerequisites:
1. **AMD Developer Cloud Instance:** Provision a ROCm Linux instance through the AMD Developer Cloud console.
2. **Drivers & Devices:** Host must have ROCm kernel drivers loaded with `/dev/kfd` and `/dev/dri` present.
3. **Docker Access:** Docker must be running with the user added to `docker` and `video`/`render` groups.
4. **Model License:** For gated models such as `meta-llama/Meta-Llama-3-8B-Instruct`, accept the license on Hugging Face and export `HF_TOKEN=<token>`.

#### Deployment Steps:
1. SSH into your provisioned AMD ROCm instance and clone the repository.
2. (Optional) Set custom configuration:
   ```bash
   export MODEL_NAME="meta-llama/Meta-Llama-3-8B-Instruct"
   export PORT="8000"
   export VLLM_API_KEY="your-secure-key"  # Optional token authentication
   export HF_TOKEN="hf_..."               # Required for gated Llama 3 models
   ```
3. Run the hardened deployment script:
   ```bash
   bash deploy_amd.sh
   ```
   The script verifies prerequisites, launches the container (retaining diagnostic logs on failure), and polls the readiness endpoint (`/health`) until the model is ready.
4. Configure InfraMind in `.env`:
   ```ini
   INFERENCE_PROVIDER="amd_vllm"
   AMD_ENDPOINT_URL="http://<AMD_INSTANCE_IP>:8000/v1"
   AMD_API_KEY="your-secure-key"
   AMD_REQUIRE_AUTH="true"
   MODEL_NAME="meta-llama/Meta-Llama-3-8B-Instruct"
   ```
   > **Note:** The canonical `AMD_ENDPOINT_URL` must end in `/v1`. The client automatically and canonically constructs `/chat/completions`.

### Evolus Business-Agent Integration Workflow
In the hackathon architecture, InfraMind functions as an autonomous cloud security sub-agent within the required Evolus business-agent workflow:
1. **Trigger:** Evolus business orchestrator invokes `agent.py` or imports `triage_findings()` upon receiving cloud security webhooks or scheduled log scans.
2. **Analysis:** The triage component enriches raw telemetry into business-contextualized risk assessments, separating verified facts from inferences and gaps.
3. **Escalation:** Findings evaluated as `CRITICAL` or `HIGH` are presented to business stakeholders or engineering leads with explicit financial/business impact statements.
4. **Approval Gate:** The Evolus approval workflow captures manager authorization before passing `approved=True` to `RemediationBridge.execute()`.
5. **Audit Trail:** Completed remediations and verified post-states are recorded back to the Evolus audit store.

---

## 📝 Remaining Integration Checklist

- [ ] **AMD Hardware Validation:** Connect `AMDvLLMProvider` to the provisioned AMD Developer Cloud instance and verify inference latency and throughput.
- [ ] **Evolus Webhook Integration:** Connect `agent.py` or an API endpoint to the Evolus business agent orchestrator.
- [ ] **Teammate UI Integration (Member 5):** Connect `app.py` to `triage_findings()` to render the threat queue and approval buttons.
- [ ] **Live AWS Validation (Member 3):** Test live execution with approved AWS sandbox credentials when `LIVE_EXECUTION_ENABLED=True`.
