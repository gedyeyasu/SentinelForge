# Demo Evidence Fallback

Emergency fallback artifacts referenced by `docs/DEMO.md` §Fallback.
If the live demo fails on stage (Wi-Fi, NIM rate limit, staging down),
present these real captured artifacts instead of a live run.

## Contents

- `last_success.json` — Real signed attestation from a completed pentest run
  (copied from `.sentinelforge/attestations/`).
- `last_pentest_run.json` — Real full pentest run record from the control
  plane DB, including phase, verdict, and results payload.

## Refresh procedure

Run after every successful rehearsal so the fallback is always fresh:

```bash
cp .sentinelforge/attestations/$(ls -t .sentinelforge/attestations/ | head -1) \
   fixtures/demo_evidence/last_success.json

.venv/bin/python -c "
import json, sqlite3
conn = sqlite3.connect('.sentinelforge/control/runs.sqlite3')
conn.row_factory = sqlite3.Row
row = conn.execute(\"SELECT * FROM pentest_runs WHERE results_json IS NOT NULL ORDER BY created_at DESC LIMIT 1\").fetchone()
d = dict(row)
d['results'] = json.loads(d.pop('results_json') or '{}')
json.dump(d, open('fixtures/demo_evidence/last_pentest_run.json', 'w'), indent=2, default=str)
"
```
