# InfraMind — AWS Setup & Configuration Guide (Version 2)

This guide provides instructions to connect InfraMind to genuine AWS security telemetry using Amazon CloudTrail, Amazon EventBridge, and Amazon SQS.

> [!IMPORTANT]
> InfraMind runs 100% safely in **Demo Mode** (`APP_MODE=demo`) without an AWS account or cloud credentials.
> Follow this guide only when you are authorized to monitor a live AWS environment and have explicit organizational permissions.

---

## 1. Prerequisites

1. **AWS CLI v2** installed and configured:
   ```powershell
   aws --version
   ```
2. **Authorized IAM Identity:** An IAM user or assumed role with permissions to deploy CloudFormation stacks, manage SQS queues, and configure EventBridge rules.
3. **Active CloudTrail Trail:** Ensure at least one multi-region trail is actively logging management events in your target AWS region.

Verify your active credentials before proceeding:
```powershell
aws sts get-caller-identity
```
Ensure the returned Account ID and ARN match your intended test environment.

---

## 2. Deploy Infrastructure via CloudFormation

InfraMind includes a production-grade CloudFormation template (`infra/cloudformation-realtime.yaml`) that provisions:
- An Amazon SQS Primary Queue (`InfraMindSecurityEventsQueue`) with SSE-SQS encryption.
- An Amazon SQS Dead-Letter Queue (`InfraMindSecurityEventsDLQ`).
- Least-privilege Queue Policies granting EventBridge access.
- An Amazon EventBridge Rule capturing security-critical S3, IAM, and GuardDuty events.

### Step 1: Deploy the Stack

Run the following command from the repository root:

```powershell
aws cloudformation deploy `
  --template-file infra/cloudformation-realtime.yaml `
  --stack-name inframind-realtime-telemetry `
  --capabilities CAPABILITY_IAM `
  --region us-east-1
```

### Step 2: Retrieve Stack Outputs

Retrieve the generated Queue URL and Dead-Letter Queue URL:

```powershell
aws cloudformation describe-stacks `
  --stack-name inframind-realtime-telemetry `
  --region us-east-1 `
  --query "Stacks[0].Outputs" `
  --output table
```

Expected output:
| OutputKey | OutputValue |
| :--- | :--- |
| `SecurityEventsQueueUrl` | `https://sqs.us-east-1.amazonaws.com/123456789012/InfraMindSecurityEventsQueue` |
| `SecurityEventsDLQUrl` | `https://sqs.us-east-1.amazonaws.com/123456789012/InfraMindSecurityEventsDLQ` |

---

## 3. Configure Local Environment

Copy `.env.example` to `.env` and populate your AWS settings:

```powershell
Copy-Item .env.example .env
```

Edit `.env` with your active configuration:

```ini
# Operating Mode
APP_MODE=live

# AWS Region & Credentials
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
# Leave empty if using default AWS CLI credentials profile (~/.aws/credentials)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=

# Ingestion SQS Queue URL from CloudFormation output
SQS_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/123456789012/InfraMindSecurityEventsQueue

# Database & Ingestion Worker
DATABASE_PATH=data/inframind.db
WORKER_POLL_INTERVAL=20
DASHBOARD_REFRESH_SECONDS=10

# AI Threat Engine
AI_PROVIDER=amd
AMD_ENDPOINT_URL=http://localhost:11434/v1
MODEL_NAME=meta-llama/Meta-Llama-3-8B-Instruct

# Guardrail Safety Controls
DRY_RUN=True
LIVE_EXECUTION_ENABLED=False
```

> [!NOTE]
> When `APP_MODE=live` is selected but `SQS_QUEUE_URL` is empty, the dashboard will prominently display:
> `LIVE INGESTION: NOT CONFIGURED — Please set SQS_QUEUE_URL in your .env file.`

---

## 4. Run the Real-Time Platform

For live telemetry ingestion, run the background worker and the operator dashboard in two separate PowerShell terminal windows.

### Terminal 1: Background Ingestion Worker

Activate your virtual environment and launch the worker:

```powershell
# In C:\Users\santh\InfraMind-Team
..\InfraMind-Member3\.venv\Scripts\Activate.ps1
python ingestion_worker.py
```

Expected worker startup output:
```text
[2026-10-18 13:00:00] [INFO] [InfraMind-Ingestion] Starting InfraMind Ingestion Worker in [live] mode.
[2026-10-18 13:00:00] [INFO] [InfraMind-Ingestion] Connected to SQS queue: https://sqs.us-east-1.amazonaws.com/...
[2026-10-18 13:00:00] [INFO] [InfraMind-Ingestion] Worker polling SQS (long-poll: 20s, graceful shutdown: SIGINT/SIGTERM)...
```

### Terminal 2: Streamlit Operator Console

In a second terminal window, launch the interactive dashboard:

```powershell
..\InfraMind-Member3\.venv\Scripts\Activate.ps1
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 5. Least-Privilege IAM Policies

If you are running InfraMind under dedicated IAM roles (such as on an EC2 instance or ECS task), use these minimal policies:

### Worker Ingestion Policy (`InfraMindWorkerPolicy`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSQSPolling",
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ],
      "Resource": "arn:aws:sqs:*:*:InfraMindSecurityEventsQueue"
    },
    {
      "Sid": "AllowS3PostureRead",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

### Live Remediation Policy (`InfraMindRemediationPolicy`)
Used only when `LIVE_EXECUTION_ENABLED=True`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3PublicAccessBlock",
      "Effect": "Allow",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "AllowIAMAccessKeyDeactivation",
      "Effect": "Allow",
      "Action": [
        "iam:UpdateAccessKey"
      ],
      "Resource": "arn:aws:iam::*:user/*"
    }
  ]
}
```

---

## 6. Safe Verification Procedure

To verify real-time event delivery without risking production infrastructure:

1. **Create a Test S3 Bucket:**
   ```powershell
   aws s3 mb s3://inframind-test-verification-bucket-12345 --region us-east-1
   ```
2. **Apply a Test ACL modification:**
   ```powershell
   aws s3api put-bucket-acl --bucket inframind-test-verification-bucket-12345 --acl public-read
   ```
3. **Observe the Worker Log:** Within 60–120 seconds (CloudTrail delivery window), the worker will log:
   ```text
   [INFO] [InfraMind-Ingestion] Ingested 1 security events from SQS.
   ```
4. **Observe the Dashboard:** The new threat card appears automatically with `CRITICAL` priority and remediation recommendations.
5. **Clean Up Test Bucket:**
   ```powershell
   aws s3 rb s3://inframind-test-verification-bucket-12345 --force
   ```

---

## 7. Teardown & Cloud Cost Prevention

When testing is complete, destroy the CloudFormation stack to ensure no AWS resources linger:

```powershell
aws cloudformation delete-stack --stack-name inframind-realtime-telemetry --region us-east-1
```
Confirm stack deletion:
```powershell
aws cloudformation wait stack-delete-complete --stack-name inframind-realtime-telemetry --region us-east-1
```
