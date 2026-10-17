#!/bin/bash
docker run -d --rm \
  --network=host \
  --device=/dev/kfd --device=/dev/dri \
  --group-add video \
  --ipc=host \
  rocm/vllm:latest \
  python3 -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Meta-Llama-3-8B-Instruct \
    --port 8000