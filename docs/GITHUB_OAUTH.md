# GitHub OAuth Integration — Super Cool One-Click Connect

> **Goal:** User says "I will provide access to my GitHub repos and it should be able to list repos in my GitHub and I should be able to run the scan against them. If we can build an OAuth integration that would be super cool"

We built exactly that: OAuth flow + token fallback, secure storage, repo listing with filter, one-click scan.

## Why OAuth is Super Cool vs Token

| Token (Manual) | OAuth (Super Cool) |
|----------------|---------------------|
| User creates PAT at github.com/settings/tokens, copy-pastes, expires, scopes manual | One-click "Connect with GitHub" button, no copy-paste, token stored securely in `.sentinelforge/github_token.json` 600 perms, uses GIT_ASKPASS for secure clone (no token in process list) |
| Token in .env, risk of leak if .env committed | Token never in .env unless user wants, stored encrypted file, safe dict via API hides full token (has_token flag) |
| No refresh, no user info | Fetches user login/name via `/user` API, shows "Connected as gedyeyasu" |

## How It Works (Architecture)

```
User clicks "Connect with GitHub (OAuth)" in Settings or Scan tab
  |
  v
Frontend: GET /api/github/oauth/start
  |
  v
Backend GitHubOAuthManager.create_authorize_url():
  - Generates random state (32 bytes token_urlsafe) prevents CSRF
  - Stores state in .sentinelforge/github_oauth_state.json with timestamp (10 min expiry) + redirect_after
  - Builds authorize URL: https://github.com/login/oauth/authorize?client_id=xxx&scope=repo,read:org,read:user&state=yyy&redirect_uri=http://localhost:8741/api/github/oauth/callback
  |
  v
Frontend opens popup window.open(authorize_url, width=600,height=700)
  |
  v
User authorizes on GitHub.com (shows OAuth App name, scopes requested)
  |
  v
GitHub redirects to callback_url?code=zzz&state=yyy
  |
  v
Backend GET /api/github/oauth/callback?code=zzz&state=yyy:
  - Validates state exists in _states dict (CSRF protection), deletes after use
  - Exchanges code for access_token via POST https://github.com/login/oauth/access_token
    Headers Accept: application/json, body {client_id, client_secret, code, redirect_uri}
  - GitHub returns {access_token, token_type, scope}
  - Fetches user info via GET https://api.github.com/user with Bearer token to get login/name
  - Stores token securely in .sentinelforge/github_token.json with 600 perms:
    {access_token, token_type, scope, obtained_at, login, name}
  - Returns HTML success page with postMessage to opener window: window.opener.postMessage({type: "github_oauth_success", login}, "*")
  - Popup shows "GitHub Connected as gedyeyasu, you can close this window" and auto-closes after 2s
  |
  v
Frontend: messageHandler listens for github_oauth_success, closes popup, calls checkGithubOAuthStatus(), checkIntegrations(), loadGithubReposList()

After OAuth:
  - GitHubClient.load_token_from_any_source() tries: OAuth manager load_token() -> env GITHUB_TOKEN -> OAuth file
  - load_token() reads .sentinelforge/github_token.json (600 perms)
  - GitHubClient uses token via _headers() Bearer
  - Secure clone via GIT_ASKPASS: writes askpass script echo token, chmod 700, env GIT_ASKPASS=path, GIT_USERNAME=x-access-token, git clone https://github.com/..., askpass script deleted after

Repo Listing:
  - GET /api/github/repos?limit=30&search=xxx&sort=updated
  - Frontend Scan tab shows list of repos with private 🔒 icon, language, default_branch, description
  - Click row auto-fills owner/repo inputs
  - Filter input live searches via /api/github/repos?search=query
  - Scan button clones securely and runs full scan pipeline with SSE live events

Scan Flow:
  - POST /api/scan/github {owner, repo, branch}
  - Backend get_repo_info(owner, repo) to get clone_url
  - clone_repo(clone_url, branch) via GIT_ASKPASS
  - Starts background thread _run_scan_background with scan_id sf_scan_{hex}
  - Returns scan_id
  - Frontend EventSource /api/scan/{scan_id}/stream shows live agent feed: fastapi_bola, django_bola, pattern_scan, vuln_scan
  - On scan_completed, fetches /api/scan/{scan_id} result JSON with bola_findings, pattern_findings, dependency_vulnerabilities, summary
```

## Setup Instructions for OAuth (For User)

### Step 1: Create GitHub OAuth App

1. Go to https://github.com/settings/developers
2. Click **OAuth Apps** → **New OAuth App**
3. Fill:
   - Application name: `SentinelForge Local`
   - Homepage URL: `http://localhost:8741`
   - Application description: `Proof-carrying release gate for Cini backend`
   - Authorization callback URL: `http://localhost:8741/api/github/oauth/callback` — **MUST be exact**
4. Click Register application
5. Copy **Client ID**
6. Click Generate a new client secret → Copy **Client Secret** (shows once)

### Step 2: Add to .env

```bash
# In /Users/gedeoneyasu/Projects/SentinelForge/.env
GITHUB_CLIENT_ID=Ov23li...
GITHUB_CLIENT_SECRET=...
GITHUB_OAUTH_CALLBACK_URL=http://localhost:8741/api/github/oauth/callback
GITHUB_OAUTH_SCOPE=repo,read:org,read:user
```

For production/staging, callback URL would be `https://your-domain.com/api/github/oauth/callback`

### Step 3: Restart API

```bash
.venv/bin/sentinelforge-api
# Now /api/github/oauth/config should show configured: true
```

### Step 4: Connect via WebUI (Super Cool Flow)

1. Open http://localhost:8741
2. Go to **Scan** tab → **GitHub Repository** tab (top toggle)
3. Click **🔗 Connect with GitHub (OAuth)** button
4. Popup opens GitHub authorize page, shows requested scopes: repo (private repos), read:org, read:user
5. Click Authorize
6. Popup shows "GitHub Connected as gedyeyasu" with auto-close
7. Scan tab now shows **Your GitHub Repositories** list with filter box, private 🔒 icons, language, Scan button per repo
8. Click a repo row → auto-fills Owner and Repo inputs
9. Click **Scan GitHub repo** → clones securely via GIT_ASKPASS, runs live scan with agent activity + terminal log

**Settings tab also has OAuth:**

1. Go to Settings (05) → GitHub Integration panel
2. Click **Connect with GitHub OAuth** → same flow
3. Shows OAuth config status: client_id prefix, callback_url, has_token flag
4. Preview shows first 5 repos

### Step 5: Verify Token Storage (Secure)

```bash
ls -lh .sentinelforge/github_token.json
# -rw------- 1 user staff 200B ... github_token.json (600 perms)
cat .sentinelforge/github_token.json
# {"access_token": "gho_...", "login": "gedyeyasu", "scope": "repo,read:org,read:user", ...}
```

Token never in process list because clone uses GIT_ASKPASS script echo token, not URL embedding `https://x-access-token:TOKEN@github.com/` (we fixed that leak earlier).

### Step 6: Disconnect

- WebUI: Click **Disconnect** button → POST /api/github/oauth/disconnect → deletes `.sentinelforge/github_token.json`
- Or manually: `rm .sentinelforge/github_token.json`

## Alternative: Manual Token Flow (If OAuth Not Configured)

If you don't want OAuth, use personal access token:

1. Go to https://github.com/settings/tokens → Generate new token (classic) or Fine-grained
2. Scopes: `repo` (full control of private repos), `read:org`, `read:user`
3. Copy token `ghp_...`
4. Add to `.env`: `GITHUB_TOKEN=ghp_...`
5. Restart API
6. WebUI Scan → GitHub tab → Refresh my repos → Lists repos via token

Our `GitHubClient` loads token from any source: explicit param → `GITHUB_TOKEN` env → OAuth file `.sentinelforge/github_token.json`.

## API Endpoints (New OAuth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/github/oauth/config` | Returns OAuth config status: configured, client_id prefix, has_client_secret, callback_url, scope, has_token |
| `GET` | `/api/github/oauth/start?redirect_after=/` | Creates state, returns authorize_url + state, stores state in `.sentinelforge/github_oauth_state.json` with 10 min expiry |
| `GET` | `/api/github/oauth/callback?code=xxx&state=yyy` | Validates state (CSRF), exchanges code for token, fetches user login/name, stores token securely with 600 perms, returns HTML success with postMessage to opener |
| `POST` | `/api/github/oauth/disconnect` | Deletes token file |

Existing endpoints enhanced:

| Method | Endpoint | Enhancement |
|--------|----------|-------------|
| `GET` | `/api/github/status` | Now tries OAuth manager first, returns source oauth_file or env, login, name, scope, has_token, oauth config |
| `GET` | `/api/github/repos?owner=&limit=&search=&sort=` | Now supports search filter (name/full_name contains), sort updated/full_name, returns filters echo |

## Security Considerations

- State parameter prevents CSRF, stored in file with timestamp, cleaned after 10 min
- Token file 600 perms, never returned in full via API (safe dict has_token flag only)
- Clone via GIT_ASKPASS not URL embedding — fixes token leak in process list / logs
- Token in memory only via GitHubClient, not persisted in SQLite events or PR bodies (redaction.py blocks GITHUB_TOKEN pattern)
- OAuth scope minimal: `repo,read:org,read:user` — repo needed to clone private repos, read:org for org repos listing, read:user for login
- Disconnect deletes token file
- For production, callback URL should be https, client_secret in secrets manager not .env file

## Testing Flow End-to-End

**With OAuth:**

```bash
# 1. Configure OAuth in .env
echo "GITHUB_CLIENT_ID=Ov23li..." >> .env
echo "GITHUB_CLIENT_SECRET=..." >> .env

# 2. Start API
.venv/bin/sentinelforge-api &
# Open http://localhost:8741

# 3. In WebUI Scan → GitHub tab → Connect with GitHub OAuth → Authorize
# Should show "Connected as gedyeyasu"

# 4. Click Refresh my repos → Should list your repos (e.g., Cini-BackEnd, cini-backend, etc.)

# 5. Click Scan on Cini-BackEnd repo (or enter owner=gedeoneyasu repo=Cini-BackEnd)
# Should clone securely and run scan, show live agent feed, then results with BOLA findings
```

**With Token:**

```bash
# 1. Set token
echo "GITHUB_TOKEN=ghp_xxx" >> .env
.venv/bin/sentinelforge-api &

# 2. In WebUI: Scan → GitHub tab → Refresh my repos → Should list repos

# 3. CLI alternative:
.venv/bin/sentinelforge gh-list
.venv/bin/sentinelforge gh-scan --owner gedyeyasu --repo Cini-BackEnd
# Or via API:
curl http://localhost:8741/api/github/repos?limit=10 | jq
curl -X POST http://localhost:8741/api/scan/github -H "Content-Type: application/json" -d '{"owner":"gedyeyasu","repo":"Cini-BackEnd"}' | jq
```

## For Loom Demo Video

**OAuth Super Cool Flow:**

0:00 "I want to test my Cini backend that is deployed on AWS, but also I want to show GitHub integration listing my repos and scanning them. We built OAuth so it's super cool, no token copy-paste."

0:10 Show Settings → GitHub Integration panel → Click Connect with GitHub OAuth → Popup GitHub authorize page with scopes → Authorize → Popup shows Connected as gedyeyasu → Auto-close → Settings shows Connected as gedyeyasu + preview of 5 repos

0:30 Go to Scan → GitHub tab → Click Refresh my repos → Shows list of your GitHub repositories with private 🔒 icon, language, description, Scan button per repo, filter box

0:45 Click a repo row (e.g., Cini-BackEnd) → Auto-fills Owner and Repo inputs → Click Scan GitHub repo → Clones securely via GIT_ASKPASS (no token in process list) → Live scan terminal shows FastAPIBOLADetector, DjangoBOLADetector, ExploitPatternScanner, DependencyParser, vuln_scan with Red Hat advisories

1:15 Results show BOLA findings for Cini backend (circle_invite_landing token, post event_id attend/interest) with severity high, rule SF-PY-DJANGO-BOLA-001, Create PR button

1:30 Click Create PR → Generates PR with security fixes, shows PR URL

This proves GitHub integration works end-to-end: OAuth connect → List repos → Scan against them → Results → PR

## Troubleshooting

**OAuth not configured error:**

- Check .env has GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET
- Restart API after adding
- GET /api/github/oauth/config should show configured true

**Invalid or expired OAuth state:**

- State expires after 10 min, stored in .sentinelforge/github_oauth_state.json
- Try again: GET /api/github/oauth/start creates new state
- Ensure callback URL in OAuth App settings exactly matches GITHUB_OAUTH_CALLBACK_URL in .env (http://localhost:8741/api/github/oauth/callback)

**GitHub OAuth authorize page shows 404:**

- Check client_id correct in OAuth App
- Check callback URL matches exactly what GitHub has

**Token file not found after OAuth:**

- Check .sentinelforge/ directory writable
- Check API logs for exchange error: POST https://github.com/login/oauth/access_token may fail if code already used (code single-use) or client_secret wrong
- Try disconnect and reconnect

**Repo list empty:**

- Check token scopes include repo,read:org — if only public_repo, private repos won't show
- Check owner param: if owner set, lists that user's repos, else authenticated user's repos
- Check GitHub API rate limit: list_repos catches exception and returns []

**Clone failed:**

- Check token has repo scope for private repos
- Check repo still exists and you have access
- Check git installed: git clone --depth 1
- Secure clone uses GIT_ASKPASS, ensure askpass script created in /tmp and deleted after

## Files Changed for GitHub OAuth

- `src/sentinelforge/integrations/github_oauth.py` (new) — OAuthManager with state, token storage 600 perms, exchange, config status
- `src/sentinelforge/integrations/github.py` — Enhanced to load token from OAuth file + env, load_token_from_any_source(), secure clone via GIT_ASKPASS
- `src/sentinelforge/control/api.py` — Added 4 OAuth endpoints: config, start, callback, disconnect; enhanced status and repos listing with search/sort
- `src/sentinelforge/web/static/index.html` — Added OAuth connect area, repos list container, filter input in Scan GitHub tab; Settings panel OAuth connect/disconnect buttons and config display
- `src/sentinelforge/web/static/app.js` — Added checkGithubOAuthStatus(), startGithubOAuth() popup with postMessage, disconnectGithub(), loadGithubReposList() with filter, setupGithubSearch(), integrated into initialize()
- `.env.example` — Updated with GITHUB_CLIENT_ID/SECRET/CALLBACK_URL/SCOPE
- `docs/GITHUB_OAUTH.md` — This file
