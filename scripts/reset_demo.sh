#!/bin/bash
set -e
echo "=== SentinelForge Demo Reset ==="
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Remove control state
rm -f .sentinelforge/control.db
rm -rf .sentinelforge/nim-runs
rm -f .sentinelforge/bench.json
rm -rf .sentinelforge/memory
rm -rf .sentinelforge/attestations
mkdir -p .sentinelforge/memory .sentinelforge/attestations .sentinelforge/control

# Verify vulnerable fixture still has BOLA
if grep -q "tenant" examples/vulnerable_shop/app/main.py; then
  echo "✓ Vulnerable fixture OK: examples/vulnerable_shop/app/main.py contains tenant logic"
else
  echo "✗ Vulnerable fixture missing tenant logic - check examples/vulnerable_shop"
  exit 1
fi

# Verify config files exist per sponsor contract
for f in config/agents.yaml config/openshell-policy.yaml config/scope.example.yaml HEARTBEAT.md docs/BREV.md docs/DEMO.md docs/SECURITY.md docs/ARCHITECTURE.md Makefile; do
  if [ -f "$f" ]; then
    echo "✓ $f exists"
  else
    echo "✗ $f MISSING - enterprise compliance fail"
  fi
done

# Clear kill switch if exists
rm -f .sentinelforge/STOP || true

echo "Demo reset done - run 'make pentest-quick' or 'sentinelforge pentest examples/vulnerable_shop --source-only --mode quick'"
echo "For full demo: make api & then open http://localhost:8741"
