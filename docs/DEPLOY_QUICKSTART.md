# Deploy Quickstart — Live Demo on Fly.io (Free Tier)

Goal: public HTTPS URL so GitHub OAuth works, then scan `Cini-Labs/Cini-BackEnd`
and run a live pentest from the deployed dashboard against `api.cini.love`.

Verified locally: Docker build passes, container serves `/health` + dashboard.

## 1. One-time setup (~10 min)

```bash
# Install + auth flyctl (free allowance covers this demo)
curl -L https://fly.io/install.sh | sh
fly auth login

# From the repo root — creates the app from fly.toml (don't deploy yet)
fly launch --dockerfile Dockerfile --name sentinelforge --region iad --no-deploy

# Persistent volume for SQLite DB, attestations, exploit artifacts
fly volumes create sentinelforge_data --region iad --size 1
```

## 2. Set secrets

```bash
fly secrets set \
  NVIDIA_API_KEY=<your nvapi-... key from .env> \
  GITHUB_TOKEN=<your ghp_... PAT from .env> \
  GITHUB_CLIENT_ID=<from GitHub OAuth App> \
  GITHUB_CLIENT_SECRET=<from GitHub OAuth App> \
  GITHUB_OAUTH_CALLBACK_URL=https://sentinelforge.fly.dev/api/github/oauth/callback \
  PENTEST_TARGET_HOST='api\.cini\.love' \
  OPENSHELL_POLICY_PATH=config/openshell-policy.yaml
```

Notes:
- `PENTEST_TARGET_HOST` authorizes the OpenShell policy to allow traffic to
  `api.cini.love` while everything else stays deny-by-default. Keep the
  escaped dots (`api\.cini\.love`).
- **Test identities are dynamic**: with `provision_identities: true` in
  `config/scope-cini.yaml` (the default), the agent registers its own
  run-scoped test accounts (`sf-<run>-<role>@sentinelforge-test.invalid`)
  on the cini public registration endpoint at run start and uses those
  JWTs — nothing to configure. Static `CINI_OWNER_JWT`/`CINI_ATTACKER_JWT`
  env vars are only a fallback if provisioning is disabled.

## 3. Deploy

```bash
fly deploy
fly status      # -> https://sentinelforge.fly.dev
curl https://sentinelforge.fly.dev/health   # {"status":"ok"}
```

The machine stays running (`min_machines_running = 1`) so background
pentest threads and SSE streams are not killed mid-run.

## 4. GitHub OAuth App (one-time, in GitHub settings)

github.com → Settings → Developer settings → OAuth Apps → New:

- Homepage URL: `https://sentinelforge.fly.dev`
- Authorization callback URL: `https://sentinelforge.fly.dev/api/github/oauth/callback`

Copy the Client ID/Secret into the `fly secrets set` command above and
redeploy (`fly deploy`).

## 5. The live demo flow

1. Open `https://sentinelforge.fly.dev` → Settings → Connect GitHub
   (OAuth popup → authorize → connected as you)
2. Scan tab → GitHub tab → your repos load from the API → pick
   `Cini-Labs/Cini-BackEnd` → Scan (watch the live agent feed)
3. Pentest tab → Target type: **Deployed staging URL** →
   `https://api.cini.love` → scope file: `config/scope-cini.yaml` →
   mode: standard → Start pentest
4. Watch: swarm agents spawn in parallel → OpenShell blocks
   out-of-scope actions live → novel attacks execute → verdict +
   evidence bundle + EVIDENCE_REPORT.md

## Local fallback (if the demo network dies)

Everything above also works at `http://127.0.0.1:8741` against
`examples/vulnerable_shop` with zero external deps except NIM.
Prerecorded evidence: `fixtures/demo_evidence/`.

## Cost

Fly.io free allowance: 1 shared-cpu VM (256MB) + 1GB volume fits the
demo. Render free tier also works (render.yaml) but spins down on idle,
which kills SSE streams — Fly is the better demo host.
