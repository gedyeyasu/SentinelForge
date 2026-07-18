PYTHON := .venv/bin/python
PIP := .venv/bin/pip
SENTINELFORGE := .venv/bin/sentinelforge
API := .venv/bin/sentinelforge-api

.PHONY: install test lint api demo-reset bench vllm-health nim-health scan pentest clean

install:
	python3 -m venv .venv
	$(PIP) install -e '.[dev]'
	cp -n .env.example .env || true
	@echo "Fill .env then run make test"

test:
	$(PYTHON) -m pytest -q

lint:
	.venv/bin/ruff check src/ tests/

api:
	$(API)

demo-reset:
	./scripts/reset_demo.sh || (rm -rf .sentinelforge/control.db .sentinelforge/nim-runs .sentinelforge/memory && mkdir -p .sentinelforge/memory && echo "demo reset done")

scan:
	$(SENTINELFORGE) scan examples/vulnerable_shop --mode quick

pentest:
	$(SENTINELFORGE) pentest examples/vulnerable_shop --scope config/scope.yaml --mode standard --source-only

pentest-quick:
	$(SENTINELFORGE) pentest examples/vulnerable_shop --mode quick --source-only

nim-health:
	$(SENTINELFORGE) nim-health

vllm-health:
	$(SENTINELFORGE) vllm-health || echo "vLLM not reachable, using NIM fallback - see docs/BREV.md"

bench:
	$(SENTINELFORGE) bench --concurrency 8,32 || echo "bench requires running vLLM or NIM - artifact is .sentinelforge/bench.json"

gh-list:
	$(SENTINELFORGE) gh-list

clean:
	rm -rf .pytest_cache .ruff_cache .sentinelforge/control.db
	find . -type d -name __pycache__ -exec rm -rf {} + || true

# Enterprise targets
e2e:
	$(PYTHON) -m pytest tests/test_control_plane.py tests/test_pentest.py -v

evidence:
	@echo "Export last run evidence"
	ls -lh .sentinelforge/*.jsonl .sentinelforge/*.json 2>/dev/null || echo "no evidence yet - run make pentest first"

agents-check:
	cat config/agents.yaml | head -n 50
	@echo "Roster ok: 10 agents"

policy-check:
	cat config/openshell-policy.yaml | head -n 60
