# InfraMind — AI-Driven Cloud Security Guardrail Engine

InfraMind is an automated, real-time cloud security threat detection and remediation engine. Built for high-throughput log analysis, it ingests AWS security events, evaluates risk severity using open-weights LLMs, and presents interactive, single-click automated remediation actions via Boto3.

---

## 🏛️ System Architecture

[ AWS Cloud Logs ] ──► [ Streamlit Dashboard (app.py) ]
│
Queries Security Agent
│
▼
[ AI Parser Engine (agent.py) ]
│
Inference Request (OpenAI Standard API)
│
▼
[ AMD Developer Cloud (ROCm + vLLM) ]
Serving Llama-3-8B-Instruct
│
Returns Structured JSON
│
▼
[ Remediation Engine (remediation.py) ]
Executes Boto3 Security Fixes


---

## 🚀 Key Features

* **Real-time Log Parsing:** Processes CloudTrail and service logs to identify exposure points (e.g., public S3 buckets, compromised IAM keys).
* **AI Severity Rating:** Evaluates threat scores (1–10) and outputs structured mitigation plans using Llama-3.
* **1-Click Remediation:** Executes automated Boto3 remediation scripts with full dry-run simulation support.
* **Incident Time-Machine:** Interactive natural language assistant for querying historical security logs.

---

## ⚡ AMD Cloud & ROCm Deployment Guide

This project is natively containerized to run on **AMD Developer Cloud** utilizing **AMD Instinct GPUs (MI300X/MI250)** and the **ROCm vLLM server**.

### 1. Launch the vLLM Serving Container
Run the included deployment script on your AMD instance:

```bash
bash deploy_amd.sh
Or execute the Docker container manually:

Bash
docker run -d --rm \
  --network=host \
  --device=/dev/kfd --device=/dev/dri \
  --group-add video \
  --ipc=host \
  rocm/vllm:latest \
  python3 -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Meta-Llama-3-8B-Instruct \
    --port 8000
2. Configure Environment Variables
Copy .env.example to .env and configure your active endpoint:

Bash
AMD_ENDPOINT_URL="http://<YOUR_AMD_INSTANCE_IP>:8000/v1"
MODEL_NAME="meta-llama/Meta-Llama-3-8B-Instruct"
AWS_DEFAULT_REGION="us-east-1"
DRY_RUN="True"
🛠️ Local Development & Running the App
Install Dependencies:

Bash
pip install -r requirements.txt
Start Local AI Engine (Fallback):

Bash
ollama run llama3:8b
Launch Dashboard:

Bash
streamlit run app.py

---

### Final Steps to Save

1. Click the green **Commit changes...** button at the top right of the GitHub page.
2. Click **Commit changes** in the popup window.
3. Your main repository page will now display a clean, professional `README.md` with fully formatted code blocks and diagrams.
