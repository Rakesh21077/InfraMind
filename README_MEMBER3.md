# InfraMind — Member 3: Auto-Patch & Remediation Scripts

## 1. Project Introduction

**InfraMind** is an AI-assisted cloud security guardrail application designed for startups and IT engineering teams. Modern cloud environments are vulnerable to accidental misconfigurations and credential leakage—such as publicly exposed Amazon S3 storage buckets or compromised AWS Identity and Access Management (IAM) access keys.

InfraMind monitors cloud environments, detects vulnerabilities, uses artificial intelligence to analyze security telemetry and recommend targeted remediations, and allows human security operators to review and execute remediations through an interactive dashboard.

The engineering team is organized into six functional roles:
- **Member 1:** GPU Endpoint & Model Serving (AMD GPU Infrastructure)
- **Member 2:** Threat Detection & AI Log Parser (`mock_logs.json`, `agent.py`)
- **Member 3 (This Module):** Auto-Patch & Remediation Scripts (`remediation.py`, `tests/`)
- **Member 4:** Incident Triage & Severity Prioritization
- **Member 5:** Streamlit Dashboard & Human-in-the-Loop Operator Console
- **Member 6:** Integration, CI/CD, & Cloud Audit Trail

---

## 2. My Responsibilities (Member 3)

As **Member 3**, my assigned mandate is the implementation of production-grade, safe, and testable Python remediation functions. Specifically:

1. **S3 Public-Access Remediation (`fix_s3_bucket`):**
   - Applies AWS S3 Public Access Block configuration to close exposed S3 buckets.
   - Sets all four public-access block flags (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) to `True`.

2. **IAM Access-Key Revocation (`revoke_iam_key`):**
   - Changes the status of compromised AWS IAM user access keys to `Inactive`.
   - Never deletes access keys, preserving them for forensic investigation.
   - Refuses automated remediation on root account keys.

3. **Multi-Layer Safety Controls & Dry-Run Simulation:**
   - Default execution mode is strictly `DRY_RUN=True`.
   - Requires explicit environment flag `LIVE_EXECUTION_ENABLED=True` and explicit human operator approval (`approved=True`) before any live AWS API is called.

4. **Input Validation & Error Handling:**
   - Validates resource names, types, and lengths prior to client initialization.
   - Catches AWS `ClientError`, `BotoCoreError`, and runtime exceptions, returning standardized, sanitized payloads.
   - Prevents credential, token, or password leakage in logs or responses.

5. **Automated Unit Testing & Mocking:**
   - 100% offline unit tests using Python's standard `unittest` and `unittest.mock`.
   - Complete test coverage across input validation, dry-run simulation, mock live paths, error branches, and safety invariants.

6. **Clean Integration Interface:**
   - Simple dictionary contract for Member 5's Streamlit UI and clear input specifications for Member 2's parser.

---

## 3. Complete Folder Structure

```text
InfraMind-Member3/
|
|-- remediation.py          # Core remediation engine, validation logic, safety gates, and local demo
|-- requirements.txt        # Runtime dependencies (boto3, python-dotenv)
|-- .env.example            # Version-controlled template of safe environment variables
|-- .env                    # Local environment configuration (excluded from Git)
|-- .gitignore              # Git ignore rules for .env, virtualenvs, bytecode, and IDE caches
|-- README_MEMBER3.md       # Comprehensive architecture, setup, and integration documentation
|-- sample_incidents.json   # Illustrative integration payload from Member 2 (fictitious sample data)
|
|-- tests/
|   |-- __init__.py         # Python test package marker
|   |-- test_remediation.py # Automated test suite (34+ unit tests covering all edge cases)
|
|-- .venv/                  # Local Python virtual environment (generated during setup)
```

### Detailed File Descriptions:
- **`remediation.py`:** Contains the primary remediation functions (`fix_s3_bucket`, `revoke_iam_key`), input validation rules, boolean environment parsers, security sanitization, and the local safe demonstration entry point (`if __name__ == "__main__":`).
- **`requirements.txt`:** Specifies minimal production dependencies: `boto3` for AWS SDK communication and `python-dotenv` for local `.env` parsing.
- **`.env.example`:** Safe reference template containing default non-sensitive settings (`DRY_RUN=True`, `LIVE_EXECUTION_ENABLED=False`, `AWS_DEFAULT_REGION=us-east-1`).
- **`.env`:** Active local environment file. Contains developer settings. Never committed to version control.
- **`.gitignore`:** Protects against accidental commits of secrets, virtual environments (`.venv/`), and compiled bytecode (`__pycache__/`).
- **`tests/test_remediation.py`:** Unit test suite covering 34+ test cases with zero external network or credential dependencies.
- **`sample_incidents.json`:** Fictitious example showing how Member 2's AI agent formats incidents for consumption by Member 3.

---

## 4. Prerequisites

To run, test, and integrate this module on Windows:
1. **Operating System:** Windows 10 or Windows 11 (tested on Windows 64-bit).
2. **Python:** Python 3.10+ (tested with Python **3.12.10**).
3. **Terminal:** Windows PowerShell or Windows Terminal.
4. **Git:** Optional for local development; required for GitHub repository push.

Verify your installed Python version:
```powershell
python --version
```

---

## 5. Step-by-Step Setup

Open Windows PowerShell and navigate to the project directory:

```powershell
# Navigate into the project folder
cd InfraMind-Member3

# Create the Python virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

> **Note regarding PowerShell script execution:** If PowerShell reports `cannot be loaded because running scripts is disabled on this system`, execute:
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> ```
> Alternatively, invoke the virtual environment's Python executable directly:
> ```powershell
> .\.venv\Scripts\python.exe <command>
> ```

---

## 6. Dependency Installation

With the virtual environment activated, install the required packages:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Verify installed packages:
```powershell
python -m pip list
```
Expected output includes:
- `boto3` (AWS SDK for Python)
- `botocore` (Low-level core library for Boto3)
- `python-dotenv` (Loads `.env` files into `os.environ`)

---

## 7. Environment Configuration

### Safe Defaults
The project relies on safe environment settings defined in `.env.example`:

```ini
# Safe default settings for local development and testing
DRY_RUN=True
LIVE_EXECUTION_ENABLED=False
AWS_DEFAULT_REGION=us-east-1
```

Create your local `.env` by copying `.env.example`:
```powershell
Copy-Item .env.example .env
```

### Safety Flags Explained:
| Variable | Allowed Values | Default | Purpose |
|---|---|---|---|
| `DRY_RUN` | `True` / `False` | `True` | When `True`, all actions return `SIMULATED` without making AWS API requests. |
| `LIVE_EXECUTION_ENABLED` | `True` / `False` | `False` | Global master circuit breaker. Must be explicitly set to `True` for live cloud actions. |
| `AWS_DEFAULT_REGION` | e.g. `us-east-1`, `us-west-2` | `us-east-1` | Target AWS region for Boto3 client initialization. |

> **Critical Safety Rule:** No AWS API request is ever dispatched unless:
> 1. `DRY_RUN=False`
> 2. `LIVE_EXECUTION_ENABLED=True`
> 3. The caller passes `approved=True`

---

## 8. How to Run the Demo

Run the safe local demo directly from the command line:

```powershell
python remediation.py
```

### Expected Behavior:
- Loads settings from `.env`.
- Verifies `DRY_RUN=True`.
- Simulates an S3 Public Access Block remediation for bucket `demo-public-bucket`.
- Simulates an IAM Access Key deactivation for key `AKIAIOSFODNN7EXAMPLE`.
- Displays formatted JSON payloads.
- Makes **zero AWS API calls** and requires **no AWS credentials**.

### Sample Terminal Output:
```text
==================================================
InfraMind Member 3 - Remediation Demo
Execution mode: DRY RUN
==================================================

--- S3 Public Bucket Remediation ---
Status:  SIMULATED
Action:  fix_s3_bucket
Target:  demo-public-bucket
Message: Dry run only. No AWS changes were made.
Full payload: {
  "status": "SIMULATED",
  "action": "fix_s3_bucket",
  "resource": "demo-public-bucket",
  "message": "Dry run only. No AWS changes were made."
}

--- IAM Access Key Deactivation ---
Status:  SIMULATED
Action:  revoke_iam_key
Target:  AKIAIOSFODNN7EXAMPLE
Message: Dry run only. No AWS changes were made.
Full payload: {
  "status": "SIMULATED",
  "action": "revoke_iam_key",
  "resource": "AKIAIOSFODNN7EXAMPLE",
  "message": "Dry run only. No AWS changes were made."
}

==================================================
Demo completed safely.
No AWS credentials were required and no cloud changes were made.
==================================================
```

---

## 9. How to Run Unit Tests

Execute the automated test suite using Python's built-in `unittest` runner:

```powershell
python -m unittest discover -s tests -v
```

### Interpreting Test Results:
- Each passing test prints `... ok`.
- Output summary at the end:
  ```text
  ----------------------------------------------------------------------
  Ran 34 tests in 0.021s

  OK
  ```
- **Passing tests confirm:**
  1. Invalid inputs are rejected immediately with `FAILED`.
  2. In dry-run mode, no AWS calls are ever attempted (`SIMULATED`).
  3. Live execution without explicit approval is blocked (`BLOCKED`).
  4. Live execution without `LIVE_EXECUTION_ENABLED=True` is blocked (`BLOCKED`).
  5. S3 remediation applies all four public-access block flags.
  6. IAM remediation sets access key status to `Inactive` and never deletes the key.
  7. Client errors (`NoSuchBucket`, `NoSuchEntity`) and network errors are handled gracefully.
  8. Secrets and credentials are automatically redacted from error messages.

---

## 10. S3 Remediation Function

### Function Signature:
```python
def fix_s3_bucket(
    bucket_name: str,
    *,
    approved: bool = False,
    s3_client: Optional[Any] = None
) -> Dict[str, str]:
```

### Parameters:
- `bucket_name` (*str*): The name of the S3 bucket to secure. Must be a valid S3 bucket name (3-63 characters, alphanumeric with hyphens/dots).
- `approved` (*bool*, keyword-only, default `False`): Explicit approval from human dashboard operator.
- `s3_client` (*Optional[boto3.client]*, keyword-only, default `None`): Injected Boto3 S3 client for testing.

### AWS API Action:
When live execution is permitted, the function invokes `s3_client.put_public_access_block()`:
```python
PublicAccessBlockConfiguration = {
    'BlockPublicAcls': True,
    'IgnorePublicAcls': True,
    'BlockPublicPolicy': True,
    'RestrictPublicBuckets': True
}
```

### Operational Considerations:
- **Scope:** Enabling bucket-level public access block will block public access to all objects in the bucket, overriding any public bucket policies or object ACLs.
- **Service Impact:** If the bucket intentionally hosts public static assets (such as public web assets or documentation), applying this block may render those assets inaccessible to anonymous users.
- **Audit Verification:** The function verifies that the AWS API accepted the configuration; it does not perform an end-to-end security penetration test or assess object-level encryption.

---

## 11. IAM Remediation Function

### Function Signature:
```python
def revoke_iam_key(
    access_key_id: str,
    user_name: Optional[str] = None,
    *,
    approved: bool = False,
    iam_client: Optional[Any] = None
) -> Dict[str, str]:
```

### Parameters:
- `access_key_id` (*str*): The 16 to 128 character AWS IAM Access Key ID (e.g., `AKIAIOSFODNN7EXAMPLE`).
- `user_name` (*Optional[str]*, default `None`): The IAM username associated with the key. Optional in dry-run mode, but **strictly mandatory** for live execution.
- `approved` (*bool*, keyword-only, default `False`): Explicit approval from human operator.
- `iam_client` (*Optional[boto3.client]*, keyword-only, default `None`): Injected Boto3 IAM client for testing.

### AWS API Action:
When live execution is permitted, invokes `iam_client.update_access_key()`:
```python
iam_client.update_access_key(
    UserName=user_name,
    AccessKeyId=access_key_id,
    Status='Inactive'
)
```

### Operational Considerations:
- **No Key Deletion:** The access key is marked `Inactive` rather than deleted. This preserves the key identifier for CloudTrail forensic investigation and enables emergency re-activation if needed.
- **Service Interruption:** Any application, CI/CD pipeline, or automated script relying on this access key will immediately receive `InvalidClientTokenId` or `AccessDenied` errors.
- **Root Account Safeguard:** AWS root account credentials cannot and should not be modified via `update_access_key`. If `user_name="root"` is provided, the function blocks execution with `BLOCKED`.

---

## 12. Safety Controls & Status Dictionary

Every remediation call returns a dictionary conforming to this standard schema:

```json
{
  "status": "SIMULATED",
  "action": "fix_s3_bucket",
  "resource": "customer-reports-bucket",
  "message": "Dry run only. No AWS changes were made."
}
```

### Status Code Definitions:
| Status | Meaning | Dashboard Interpretation |
|---|---|---|
| `SIMULATED` | Dry-run mode active. No AWS changes were attempted or made. | Show simulation result. **Do not** mark incident as resolved. |
| `SUCCESS` | AWS API call completed successfully without exception. | Display success confirmation and record remediation event. |
| `BLOCKED` | Prevented by safety rule (missing approval, disabled live flag, missing username, root account). | Alert operator of missing prerequisite or safety condition. |
| `FAILED` | Validation error, AWS permission error, or operational failure occurred. | Display error message. Retain incident as unresolved. |

---

## 13. Member 2 Integration (Threat Detection & AI Agent)

Member 2 is responsible for `mock_logs.json` and `agent.py`. The AI agent scans security logs, detects threats, and generates incident alerts.

### Expected Incident Fields:
1. **For S3 Public Bucket Exposure:**
   - Must provide `bucket_name` (string).
2. **For Compromised IAM Access Keys:**
   - Must provide `access_key_id` (string).
   - Must provide `user_name` (string) whenever available in logs (e.g. from CloudTrail `userIdentity.userName`).

### Reference Mapping:
See `sample_incidents.json` in the root directory for an illustrative payload structure:
```python
# Integration bridge example
if incident["threat_type"] == "PUBLIC_S3_BUCKET":
    bucket_name = incident["parameters"]["bucket_name"]
    result = fix_s3_bucket(bucket_name, approved=user_approved)

elif incident["threat_type"] == "COMPROMISED_ACCESS_KEY":
    key_id = incident["parameters"]["access_key_id"]
    user_name = incident["parameters"].get("user_name")
    result = revoke_iam_key(key_id, user_name=user_name, approved=user_approved)
```

---

## 14. Member 5 Integration (Streamlit Dashboard)

Member 5 builds the human-in-the-loop dashboard. Member 5 imports the remediation functions directly:

```python
from remediation import fix_s3_bucket, revoke_iam_key
```

### Dashboard Usage Examples:

#### A. Safe Simulation / Preview Call:
```python
# Previewing action when an incident card is displayed
preview_result = fix_s3_bucket("customer-data-bucket")
# Returns: {"status": "SIMULATED", "action": "fix_s3_bucket", ...}
```

#### B. Operator Approval Button:
```python
import streamlit as st
from remediation import fix_s3_bucket, revoke_iam_key

st.subheader("Incident Remediation")

if st.button("Approve & Execute Remediation"):
    # Member 5 passes approved=True after the operator confirms
    result = fix_s3_bucket(st.session_state.selected_bucket, approved=True)

    if result["status"] == "SUCCESS":
        st.success(f"Remediated: {result['message']}")
        st.session_state.incident_status = "RESOLVED"
    elif result["status"] == "SIMULATED":
        st.info(f"Simulation: {result['message']} (Dry-run mode is enabled)")
    elif result["status"] == "BLOCKED":
        st.warning(f"Blocked by guardrail: {result['message']}")
    elif result["status"] == "FAILED":
        st.error(f"Remediation failed: {result['message']}")
```

### Strict UI Rules for Member 5:
- **Never mark an incident as remediated if status is `SIMULATED` or `BLOCKED`.**
- **Re-approval required:** If the user selects a different bucket or key, human approval must be cleared and re-requested.

---

## 15. Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| `activate.ps1 cannot be loaded` | PowerShell execution policy restricted | Run `Set-ExecutionPolicy -Scope Process Bypass` in the current terminal session. |
| `ModuleNotFoundError: No module named 'boto3'` | Virtual environment not activated or dependencies not installed | Run `.\.venv\Scripts\Activate.ps1` and `pip install -r requirements.txt`. |
| Function returns `BLOCKED` during testing | `LIVE_EXECUTION_ENABLED` is False or `approved=False` | This is intended safety behavior. In live production, set `LIVE_EXECUTION_ENABLED=True` in `.env` and pass `approved=True`. |
| S3 error: `NoSuchBucket` | Bucket name does not exist in target AWS account | Verify bucket name spelling and check the configured AWS region. |
| IAM error: `NoSuchEntity` | Access key ID or user name does not exist in AWS IAM | Verify CloudTrail logs to confirm exact username and key ID. |
| S3 error: `AccessDenied` | IAM role/user running the application lacks `s3:PutBucketPublicAccessBlock` | Attach appropriate IAM policy granting `s3:PutBucketPublicAccessBlock` to the principal. |

---

## 16. GitHub Handover Checklist

Before committing to Git or pushing to GitHub:

- [x] **Verified `.gitignore`:** Contains `.env`, `.venv/`, `__pycache__/`, `.pytest_cache/`.
- [x] **No hardcoded secrets:** Verified no AWS secret access keys, access keys, or bearer tokens exist in source code or `.env.example`.
- [x] **Safe `.env.example` committed:** Contains only template configuration (`DRY_RUN=True`, `LIVE_EXECUTION_ENABLED=False`).
- [x] **Active `.env` excluded:** Local `.env` file is excluded from Git via `.gitignore`.
- [x] **All tests passing:** 34 unit tests pass with zero failures.
- [x] **Standalone execution:** Module runs independently without Member 1 (GPU) or Member 2 (AI parser).
- [x] **Files to commit:**
  - `remediation.py`
  - `requirements.txt`
  - `.env.example`
  - `.gitignore`
  - `README_MEMBER3.md`
  - `sample_incidents.json`
  - `tests/__init__.py`
  - `tests/test_remediation.py`
