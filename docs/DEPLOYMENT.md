# Deployment Guide — Get Project URL, Webhook URL, Callback URL for GitHub Integration

> You said: "I think inorder to create the github integration i have to deploy this application to supbase and get the project url, webhook url and callback url. Its asking me for that"

You are right — for GitHub OAuth App (or GitHub App) you need a **public callback URL**, not localhost. localhost works for local dev, but for production / for others to authorize, you need deployed URL.

This guide shows how to deploy SentinelForge to get those URLs, plus how to deploy Supabase schema.

## What URLs Does GitHub Ask For?

**GitHub OAuth App** (what we implemented, simpler, recommended):

- **Homepage URL:** `https://your-app-url.com` (e.g., `https://sentinelforge.fly.dev` or `https://api.cini.love`)
- **Authorization callback URL:** `https://your-app-url.com/api/github/oauth/callback` — GitHub redirects here after user authorizes with `?code=xxx&state=yyy`, backend exchanges code for token

**GitHub App** (more powerful, webhooks, if you want):

- Homepage URL, Callback URL, **Webhook URL:** `https://your-app-url.com/api/github/webhooks`, Webhook secret

**Supabase Auth GitHub Provider** (if using Supabase Auth for user login to dashboard):

- Supabase Dashboard → Authentication → Providers → GitHub → Needs Client ID, Client Secret, and shows **Redirect URL** like `https://ltkdxqbkpgulkpxzlwaz.supabase.co/auth/v1/callback` — you put this Redirect URL into GitHub OAuth App callback URL field.

So you have 2 options:

- **Option A (Current implementation):** SentinelForge's own OAuth flow, callback is `/api/github/oauth/callback` on your deployed FastAPI
- **Option B (Supabase Auth):** Use Supabase Auth to login users to dashboard via GitHub, callback is Supabase Auth callback `https://<project>.supabase.co/auth/v1/callback`

We support Option A out of the box. Option B is optional for SaaS multi-tenant login.

## Step 1: Commit and Push to GitHub (Already Done ✅)

We already committed and pushed all recent changes to `https://github.com/gedyeyasu/SentinelForge.git` up to `896e0a4`.

Verify:

```bash
cd /Users/gedeoneyasu/Projects/SentinelForge
git log --oneline -5
# Should show latest commits including NemoClaw agents, OAuth, Cini scope
git status --short
# Should be clean (no uncommitted files)
git push origin main
# Already pushed
```

If you have new local changes (like .env with GitHub OAuth keys), **don't commit .env** (it's gitignored for security). Only push code, not secrets.

## Step 2: Deploy Supabase Schema (Get Supabase Project URL)

You already have Supabase project: `https://ltkdxqbkpgulkpxzlwaz.supabase.co` (from your .env)

### What is Supabase Project URL?

- **Project URL:** `https://ltkdxqbkpgulkpxzlwaz.supabase.co`
- **API URL:** Same as Project URL
- **DB Connection:** `postgresql://postgres:[...]@db.ltkdxqbkpgulkpxzlwaz.supabase.co:5432/postgres` (in your .env as DB_STRING)
- **Auth Callback URL (for Supabase Auth GitHub provider):** `https://ltkdxqbkpgulkpxzlwaz.supabase.co/auth/v1/callback`
- **Webhook URL (for Supabase webhooks):** You can create webhooks in Supabase Dashboard → Database → Webhooks that call your deployed SentinelForge API

### Deploy Schema to Supabase

**Option 1: Via Supabase Dashboard (Easy, Recommended)**

1. Go to https://supabase.com/dashboard/project/ltkdxqbkpgulkpxzlwaz
2. Click **SQL Editor** in left sidebar
3. Click **New Query**
4. Copy entire `docs/supabase_schema.sql` file content
5. Paste and click **Run**
6. Should create tables: `orgs`, `memberships`, `api_keys`, `pentest_runs`, `events`, `security_invariants`, `target_memory`, `advisory_cursor`, `agent_traces`, `audit_logs`, `vex_documents`

**Option 2: Via Supabase CLI**

```bash
# Install Supabase CLI
npm install -g supabase

# Login
supabase login

# Link project
supabase link --project-ref ltkdxqbkpgulkpxzlwaz

# Run migration
supabase db push --db-url "postgresql://postgres:[YOUR_PASSWORD]@db.ltkdxqbkpgulkpxzlwaz.supabase.co:5432/postgres" --file docs/supabase_schema.sql
```

**Option 3: Via psql**

```bash
psql "postgresql://postgres:[PASSWORD]@db.ltkdxqbkpgulkpxzlwaz.supabase.co:5432/postgres" -f docs/supabase_schema.sql
```

### Verify Supabase Deployment

```bash
# Test connection via Python
.venv/bin/python -c "
import os
from supabase import create_client
url = os.environ.get('SUPABASE_URL')
key = os.environ.get('SUPABASE_SECRET_KEY')
print(f'URL: {url}')
# Try to list tables via SQL
"
```

Or check in Supabase Dashboard → Table Editor → Should see tables listed.

## Step 3: Deploy FastAPI Control Plane (Get Project URL, Callback URL)

You need to deploy the FastAPI app (`sentinelforge-api`) to a public URL to get callback URL for GitHub OAuth.

**We created Dockerfile for you** — now you can deploy to Fly.io, Render, Railway, or AWS (since Cini backend is on AWS).

### Option A: Deploy to Fly.io (Recommended, 5 min, free tier)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Launch app (from SentinelForge root)
fly launch --dockerfile Dockerfile --name sentinelforge --region iad
# Answer:
# - Would you like to set up a Postgresql database? No (we use Supabase)
# - Would you like to set up a Redis database? No
# - Would you like to set up an Upstash Redis database? No
# - Would you like to deploy now? Yes

# After deploy, get URL:
fly status
# Shows URL: https://sentinelforge.fly.dev

# Set secrets (env vars) for deployed app:
fly secrets set \
  GITHUB_CLIENT_ID=Ov23li... \
  GITHUB_CLIENT_SECRET=... \
  GITHUB_OAUTH_CALLBACK_URL=https://sentinelforge.fly.dev/api/github/oauth/callback \
  NVIDIA_API_KEY=nvapi-... \
  SUPABASE_URL=https://ltkdxqbkpgulkpxzlwaz.supabase.co \
  SUPABASE_SECRET_KEY=sb_secret_... \
  SUPABASE_PUBLISHABLE_KEY=sb_publishable_...

# Your callback URL is now:
# https://sentinelforge.fly.dev/api/github/oauth/callback

# Your project URL is:
# https://sentinelforge.fly.dev

# Webhook URL (if using GitHub App webhooks):
# https://sentinelforge.fly.dev/api/github/webhooks
```

### Option B: Deploy to Render (Free tier, easy)

1. Go to https://dashboard.render.com → New → Web Service
2. Connect GitHub repo `gedyeyasu/SentinelForge`
3. Settings:
   - Runtime: Docker
   - Dockerfile Path: `./Dockerfile`
   - Port: 8741
   - Health Check Path: `/health`
4. Environment → Add env vars:
   - `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_OAUTH_CALLBACK_URL` = `https://sentinelforge.onrender.com/api/github/oauth/callback`
   - `NVIDIA_API_KEY`, `SUPABASE_URL`, `SUPABASE_SECRET_KEY`, etc.
5. Deploy → Get URL: `https://sentinelforge.onrender.com`
6. Callback URL: `https://sentinelforge.onrender.com/api/github/oauth/callback`

### Option C: Deploy to AWS (Since Cini backend is on AWS, e.g., ECS, EC2, or App Runner)

**App Runner (Easiest for AWS):**

```bash
# Build and push Docker image to ECR
aws ecr create-repository --repository-name sentinelforge --region us-east-1
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <your-account>.dkr.ecr.us-east-1.amazonaws.com

docker build -t sentinelforge .
docker tag sentinelforge:latest <your-account>.dkr.ecr.us-east-1.amazonaws.com/sentinelforge:latest
docker push <your-account>.dkr.ecr.us-east-1.amazonaws.com/sentinelforge:latest

# In AWS Console: App Runner → Create service → Source ECR → Image <account>.dkr.ecr.../sentinelforge:latest → Port 8741
# Add env vars same as Fly.io
# Get URL: https://xxxx.us-east-1.awsapprunner.com
# Callback: https://xxxx.us-east-1.awsapprunner.com/api/github/oauth/callback
```

**Or reuse Cini backend infrastructure:**

If Cini backend is deployed at `https://api.cini.love`, you could deploy SentinelForge as separate service at `https://sentinelforge.api.cini.love` or `https://api.cini.love/sentinelforge` via ALB path routing.

### After Deployment — Update GitHub OAuth App

1. Go to https://github.com/settings/developers → OAuth Apps → Your app (SentinelForge Local)
2. Edit:
   - Homepage URL: `https://sentinelforge.fly.dev` (your deployed URL)
   - Authorization callback URL: `https://sentinelforge.fly.dev/api/github/oauth/callback` (your deployed callback)
3. Save

Now when you click Connect with GitHub in deployed WebUI at `https://sentinelforge.fly.dev`, it will redirect correctly.

## Step 4: Update .env For Deployed URLs

**Local .env (for localhost dev):**

```bash
GITHUB_CLIENT_ID=Ov23li...
GITHUB_CLIENT_SECRET=...
GITHUB_OAUTH_CALLBACK_URL=http://localhost:8741/api/github/oauth/callback
```

**Deployed env vars (Fly.io, Render, etc):**

Same but with deployed URL:

```bash
GITHUB_OAUTH_CALLBACK_URL=https://sentinelforge.fly.dev/api/github/oauth/callback
```

## Step 5: Webhook URL (If Using GitHub App Webhooks)

If you want GitHub webhooks for PR events (optional, advanced):

- GitHub App asks for Webhook URL: `https://your-app-url.com/api/github/webhooks`
- Webhook secret: generate random string via `openssl rand -hex 20`
- In SentinelForge, you would need to implement `/api/github/webhooks` endpoint that handles `pull_request`, `push` events and triggers pentest.

We have not implemented webhooks yet, but we have `/api/pentest/schedule` for recurring scans. For now, you can skip webhook URL or set to same as callback URL with `/api/github/webhooks` path.

If GitHub OAuth App (not GitHub App), you don't need webhook URL — only callback URL.

## Step 6: Supabase Auth GitHub Provider (Optional)

If you want users to login to SentinelForge dashboard via GitHub using Supabase Auth (separate from repo listing OAuth):

1. Go to Supabase Dashboard → Authentication → Providers → GitHub
2. Enable GitHub provider
3. It shows **Redirect URL** like `https://ltkdxqbkpgulkpxzlwaz.supabase.co/auth/v1/callback` — copy this
4. Go to GitHub OAuth App → Add this Redirect URL as additional callback URL (GitHub allows multiple? OAuth App only allows one callback, but GitHub allows multiple callback URLs for GitHub Apps, or you can create separate OAuth App for Supabase)
5. Paste Client ID and Client Secret into Supabase GitHub provider settings
6. Save

Now users can login to dashboard via Supabase Auth GitHub.

But our current implementation uses direct GitHub OAuth, not Supabase Auth, so this step is optional for SaaS.

## Summary — URLs You Get After Deployment

After deploying FastAPI to Fly.io/Render/AWS:

- **Project URL (Homepage):** `https://sentinelforge.fly.dev` (or your custom domain)
- **API Base URL:** `https://sentinelforge.fly.dev/api`
- **Health Check:** `https://sentinelforge.fly.dev/health`
- **Dashboard:** `https://sentinelforge.fly.dev/` (serves index.html)
- **GitHub OAuth Callback URL:** `https://sentinelforge.fly.dev/api/github/oauth/callback` ← Put this in GitHub OAuth App settings
- **Webhook URL (if GitHub App):** `https://sentinelforge.fly.dev/api/github/webhooks` (optional, not yet implemented, but you can set)
- **Supabase Project URL:** `https://ltkdxqbkpgulkpxzlwaz.supabase.co`
- **Supabase Auth Callback (if using Supabase Auth):** `https://ltkdxqbkpgulkpxzlwaz.supabase.co/auth/v1/callback`

## Quick Checklist

- [x] Code committed and pushed to GitHub (we did: https://github.com/gedyeyasu/SentinelForge)
- [ ] Supabase schema deployed via SQL Editor (you do: copy docs/supabase_schema.sql → Run in Supabase Dashboard)
- [ ] FastAPI deployed to Fly.io/Render/AWS (you do: fly launch or Render new service with Dockerfile)
- [ ] Env vars set in deployed platform (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, callback URL with deployed URL, NVIDIA_API_KEY, Supabase keys)
- [ ] GitHub OAuth App callback URL updated to deployed URL (e.g., https://sentinelforge.fly.dev/api/github/oauth/callback)
- [ ] Test deployed: curl https://sentinelforge.fly.dev/health → should return {"status":"ok"}
- [ ] Test OAuth: Open https://sentinelforge.fly.dev → Scan → GitHub tab → Connect with GitHub OAuth → Should authorize and list repos

## Dockerfile Already Created

We created `Dockerfile` in repo root with:

- Python 3.12 slim
- Non-root user appuser
- git + gh CLI installed
- pip install -e .
- Expose 8741
- Health check GET /health
- CMD sentinelforge-api

You can build locally to test:

```bash
docker build -t sentinelforge .
docker run -p 8741:8741 --env-file .env sentinelforge
# Open http://localhost:8741
```

## Next Steps For You

1. Deploy Supabase schema (SQL Editor → docs/supabase_schema.sql)
2. Deploy FastAPI via Fly.io `fly launch` (easiest)
3. Get deployed URL (e.g., https://sentinelforge.fly.dev)
4. Update GitHub OAuth App callback URL to deployed URL + /api/github/oauth/callback
5. Set env vars in Fly.io via `fly secrets set`
6. Test OAuth flow on deployed URL
7. For Cini live pentest, update `config/scope-cini.yaml` base_url to https://api.cini.love/api/v1 and allowed_hosts api.cini.love, run via deployed WebUI

Let me know your deployed URL after Fly.io/Render and I can verify health check and OAuth config!
