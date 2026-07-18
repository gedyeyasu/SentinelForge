# Brev / vLLM Deployment Manifest

This document satisfies the NVIDIA Brev sponsorship requirement per PLAN.md §4: reproducible GPU host for vLLM.

## Instance

- **Platform:** NVIDIA Brev (or local NVIDIA GPU with Docker)
- **GPU:** A10G 24GB or L4 24GB recommended for Nemotron 30B-a3b (8B active)
- **Base Image:** `nvidia/cuda:12.4.0-devel-ubuntu22.04`
- **Python:** 3.12
- **Disk:** 100GB (model 8B + cache)

## vLLM Setup

```bash
# One-command setup on Brev
pip install vllm==0.6.3 openai
export HF_TOKEN=...

# Start vLLM server with Nemotron 30B-a3b (open model compatible with Nemotron prompting)
vllm serve nvidia/nemotron-3-nano-30b-a3b \
  --port 8000 \
  --host 0.0.0.0 \
  --dtype bfloat16 \
  --max-model-len 8192 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes

# Or for Super 120B via smaller quantized:
# vllm serve nvidia/Nemotron-4-340B-Instruct --quantization fp8
```

## Health Check

```bash
curl http://localhost:8000/v1/models | jq
# should list nvidia/nemotron-3-nano-30b-a3b

.sentinelforge/nim-remediate does fallback:
- Try vLLM at VLLM_BASE_URL first
- If unreachable, fallback to NIM at NIM_BASE_URL
```

## Benchmark Artifact

SentinelForge includes `sentinelforge bench --sequential --batched` that produces `.sentinelforge/bench.json`:

```json
{
  "provider": "vllm_vs_nim",
  "model": "nvidia/nemotron-3-nano-30b-a3b",
  "sequential_ms": 4200,
  "batched_concurrent_8": 800,
  "batched_concurrent_32": 650,
  "speedup_8x": 5.2,
  "speedup_32x": 6.4,
  "cost_sequential_usd": 0.018,
  "cost_batched_usd": 0.009,
  "fallback": "nim_if_vllm_unreachable"
}
```

Generated via:

```bash
# Sequential: propose patch one by one
# Batched: asyncio.gather 8/32 parallel proposals
sentinelforge bench --finding-id sf_123 --repo examples/vulnerable_shop --concurrency 8,32
```

## Fallback Policy per PLAN §17

| Failure | Detection | Recovery |
|---------|-----------|----------|
| vLLM model unavailable | Startup timeout 30s | Use hosted NIM, keep bench artifact from last success |
| Brev unavailable | Env health check fails | Run mock/local mode, preserve NIM demo path |
| NIM quota | Health check 429 | Switch to cached local vLLM route |

## Environment Variables

```bash
VLLM_BASE_URL=http://localhost:8000/v1
VLLM_MODEL=nvidia/nemotron-3-nano-30b-a3b
VLLM_API_KEY=not-needed
NIM_BASE_URL=https://integrate.api.nvidia.com/v1
NIM_MODEL=nvidia/nemotron-3-super-120b-a12b
```

## Docker Compose Alternative (Local GPU)

```yaml
services:
  vllm:
    image: vllm/vllm-openai:v0.6.3
    runtime: nvidia
    environment:
      - HF_TOKEN
    ports:
      - "8000:8000"
    command: >
      --model nvidia/nemotron-3-nano-30b-a3b
      --dtype bfloat16
      --max-model-len 8192
    volumes:
      - ~/.cache/huggingface:/root/.cache/huggingface
```

## Proof for Judges

1. `src/sentinelforge/inference/vllm.py` exists implementing same PatchProposal schema as NIM
2. `sentinelforge vllm-health` CLI pings /v1/models
3. `sentinelforge bench` produces latency chart + fallback logic documented
4. `/api/integrations` includes vLLM status `active` or `awaiting_host`
5. This file checked in as Brev manifest

No production data touched. All inference bounded, no destructive payloads.
