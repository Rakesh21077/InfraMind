#!/usr/bin/env bash
# =============================================================================
# InfraMind - AMD ROCm vLLM Deployment Script
# =============================================================================
# Deploys an OpenAI-compatible vLLM inference server on AMD ROCm GPU infrastructure
# (e.g. AMD Developer Cloud instances with AMD Instinct MI210/MI250/MI300 GPUs
# or ROCm-compatible Linux hosts).
#
# PREREQUISITES & SCOPE:
# 1. This script runs on an already-provisioned AMD ROCm Linux host. It does NOT
#    provision the cloud GPU or VM itself; launch an instance via the AMD
#    Developer Cloud console first.
# 2. Host must have Docker installed with user in 'docker' and 'video'/'render' groups.
# 3. Kernel drivers /dev/kfd and /dev/dri must be present on the host.
# 4. Gated models (e.g. Meta-Llama-3-8B-Instruct) require accepting the license
#    on Hugging Face and setting HF_TOKEN in your environment before running.
# =============================================================================

set -euo pipefail

# Configurable deployment parameters with safe defaults
MODEL_NAME="${MODEL_NAME:-meta-llama/Meta-Llama-3-8B-Instruct}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8000}"
CONTAINER_NAME="${CONTAINER_NAME:-inframind-vllm-amd}"
# Note: For production AMD Developer Cloud, specify the pinned image matching your ROCm driver:
# e.g., rocm/vllm:rocm6.2_mi300_ubuntu22.04. Verify current tags at hub.docker.com/r/rocm/vllm.
VLLM_IMAGE="${VLLM_IMAGE:-rocm/vllm:latest}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-4096}"
GPU_MEMORY_UTILIZATION="${GPU_MEMORY_UTILIZATION:-0.90}"
VLLM_API_KEY="${VLLM_API_KEY:-}"
HF_TOKEN="${HF_TOKEN:-${HUGGING_FACE_HUB_TOKEN:-}}"
READINESS_TIMEOUT="${READINESS_TIMEOUT:-180}"

echo "================================================================="
echo "[*] InfraMind - AMD ROCm vLLM Inference Deployment"
echo "================================================================="
echo "Target Model:      ${MODEL_NAME}"
echo "Container Image:   ${VLLM_IMAGE}"
echo "Host Interface:    ${HOST}"
echo "Port:              ${PORT}"
echo "Container Name:    ${CONTAINER_NAME}"
echo "Max Model Length:  ${MAX_MODEL_LEN}"
echo "Auth Required:     $([ -n "${VLLM_API_KEY}" ] && echo "YES (API key enabled)" || echo "NO (Local/Private only)")"
echo "-----------------------------------------------------------------"

# Pre-flight Check 1: Docker CLI and daemon
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: Docker CLI not found. Please install Docker before running this script." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running or current user lacks docker group permissions." >&2
    exit 1
fi

# Pre-flight Check 2: AMD ROCm kernel devices
if [ ! -e "/dev/kfd" ] || [ ! -d "/dev/dri" ]; then
    echo "ERROR: AMD ROCm kernel devices (/dev/kfd, /dev/dri) not found on this host." >&2
    echo "Ensure AMD GPU kernel drivers (amdgpu, amdkfd) are installed and loaded." >&2
    echo "If running in AMD Developer Cloud, verify ROCm kernel module status via 'lsmod | grep kfd'." >&2
    exit 1
fi

# Pre-flight Check 3: Meta-Llama license / HF_TOKEN check
if [[ "${MODEL_NAME}" =~ [Ll]lama.*3 ]] && [ -z "${HF_TOKEN}" ]; then
    echo "WARNING: Selected model '${MODEL_NAME}' requires Hugging Face license approval." >&2
    echo "If container startup fails with 401/403 Unauthorized, export HF_TOKEN=<token> and re-run." >&2
fi

# Pre-flight Check 4: Clean up existing container if stopped
if docker ps -a --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    echo "Notice: Container '${CONTAINER_NAME}' already exists. Removing previous instance..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
fi

# Determine video/render group flags
GROUP_FLAGS=""
if getent group video >/dev/null 2>&1; then
    GROUP_FLAGS="${GROUP_FLAGS} --group-add video"
fi
if getent group render >/dev/null 2>&1; then
    GROUP_FLAGS="${GROUP_FLAGS} --group-add render"
fi

# Prepare environment flags
ENV_FLAGS=""
if [ -n "${HF_TOKEN}" ]; then
    ENV_FLAGS="${ENV_FLAGS} -e HF_TOKEN=${HF_TOKEN}"
fi

# Prepare vLLM API server arguments
EXTRA_VLLM_ARGS=""
if [ -n "${VLLM_API_KEY}" ]; then
    EXTRA_VLLM_ARGS="${EXTRA_VLLM_ARGS} --api-key ${VLLM_API_KEY}"
fi

echo "[*] Launching vLLM container '${CONTAINER_NAME}' on AMD ROCm device..."
# Note: --rm is intentionally OMITTED so diagnostic logs persist on startup failure

# shellcheck disable=SC2086
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST}:${PORT}:${PORT}" \
    --device=/dev/kfd \
    --device=/dev/dri \
    ${GROUP_FLAGS} \
    --ipc=host \
    --shm-size=16g \
    ${ENV_FLAGS} \
    "${VLLM_IMAGE}" \
    python3 -m vllm.entrypoints.openai.api_server \
        --model "${MODEL_NAME}" \
        --host 0.0.0.0 \
        --port "${PORT}" \
        --max-model-len "${MAX_MODEL_LEN}" \
        --gpu-memory-utilization "${GPU_MEMORY_UTILIZATION}" \
        ${EXTRA_VLLM_ARGS}

echo "[*] Container launched. Polling readiness endpoint (timeout: ${READINESS_TIMEOUT}s)..."

# Readiness verification loop
START_TIME=$(date +%s)
HEALTH_URL="http://127.0.0.1:${PORT}/health"
MODELS_URL="http://127.0.0.1:${PORT}/v1/models"
IS_READY=0

while [ $(( $(date +%s) - START_TIME )) -lt "${READINESS_TIMEOUT}" ]; do
    # Check if container died prematurely
    STATUS=$(docker inspect -f '{{.State.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "not_found")
    if [ "${STATUS}" != "running" ]; then
        echo ""
        echo "ERROR: Container '${CONTAINER_NAME}' is no longer running (status: ${STATUS})." >&2
        echo "Startup failed. Inspecting recent container logs:" >&2
        echo "-----------------------------------------------------------------" >&2
        docker logs --tail 40 "${CONTAINER_NAME}" >&2 || true
        echo "-----------------------------------------------------------------" >&2
        exit 1
    fi

    # Probe HTTP endpoints using curl or python
    AUTH_HEADER=()
    if [ -n "${VLLM_API_KEY}" ]; then
        AUTH_HEADER=(-H "Authorization: Bearer ${VLLM_API_KEY}")
    fi

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_HEADER[@]}" "${HEALTH_URL}" 2>/dev/null || echo "000")
    if [ "${HTTP_CODE}" = "200" ]; then
        IS_READY=1
        break
    fi

    # Fallback probe to /v1/models
    HTTP_CODE_MODELS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_HEADER[@]}" "${MODELS_URL}" 2>/dev/null || echo "000")
    if [ "${HTTP_CODE_MODELS}" = "200" ]; then
        IS_READY=1
        break
    fi

    echo -n "."
    sleep 5
done

echo ""

if [ "${IS_READY}" -ne 1 ]; then
    echo "ERROR: vLLM server failed to become ready within ${READINESS_TIMEOUT}s." >&2
    echo "Dumping recent container diagnostic logs:" >&2
    echo "-----------------------------------------------------------------" >&2
    docker logs --tail 50 "${CONTAINER_NAME}" >&2 || true
    echo "-----------------------------------------------------------------" >&2
    echo "Troubleshooting:" >&2
    echo "1. Verify ROCm GPU memory: 'rocm-smi'" >&2
    echo "2. If out of memory, reduce MAX_MODEL_LEN or GPU_MEMORY_UTILIZATION." >&2
    echo "3. For gated models, confirm HF_TOKEN validity." >&2
    exit 1
fi

echo "================================================================="
echo "[SUCCESS] AMD ROCm vLLM server is healthy and responding!"
echo "Canonical Base URL:  http://${HOST}:${PORT}/v1"
echo "Chat Endpoint:       http://${HOST}:${PORT}/v1/chat/completions"
echo "Model ID:            ${MODEL_NAME}"
echo "================================================================="
echo "To connect InfraMind to this AMD vLLM instance, configure your .env:"
echo ""
echo "  INFERENCE_PROVIDER=amd_vllm"
echo "  AMD_ENDPOINT_URL=http://<AMD_HOST_IP_OR_DNS>:${PORT}/v1"
if [ -n "${VLLM_API_KEY}" ]; then
    echo "  AMD_API_KEY=<your_vllm_api_key>"
    echo "  AMD_REQUIRE_AUTH=true"
else
    echo "  AMD_REQUIRE_AUTH=false"
fi
echo "================================================================="
