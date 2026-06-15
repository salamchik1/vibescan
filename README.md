---
title: VibeScan Scanner
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 8787
pinned: false
---

# 🛡️ VibeScan

Free security scanner for vibe-coded apps (Lovable / Bolt / Base44 / Supabase / Firebase).
Paste a URL → get a plain-English report of leaked secrets, open databases, missing logins and
basic web-hardening issues, each with a copy-paste fix.

This is **stage 1** (the free public scanner). See [VIBE-SECURITY-ANALYSIS.md](VIBE-SECURITY-ANALYSIS.md)
for the full strategy and later stages (accounts, monitoring, payments, agency mode).

## How it works

```
[ Browser ]
     │ URL + "I'm allowed to scan this" checkbox
     ▼
apps/web (Next.js)  ──POST /api/scan (server-side, shared secret)──▶  apps/scanner (Fastify)
  landing, report 🔴🟡🟢                                              Playwright + detectors
  Vercel                ◀──────────── ScanResult JSON ──────────────  Render / Railway (Docker)
```

- The browser never sees the scanner URL or secret — the Next.js route forwards the request server-side.
- The scanner is **stateless** and **stores nothing**. Secrets are masked (`sk_live_****abcd`); the
  downloaded page is discarded after the scan.

### Scan modes

| Mode | Input | What runs |
|---|---|---|
| **URL** | a live URL | Playwright + the live detectors (secrets, open DB, auth, OWASP, exposed files) — synchronous |
| **Code** | pasted source | the text-only detectors (leaked secrets, DB creds, hard-coded config) — synchronous |
| **Repo** | a public Git URL | **async job**: clone the repo, then **Semgrep** (SAST), **dependency CVEs** (OSV.dev) and **gitleaks** over the full git history |

Repository scans run as an **asynchronous job** (clone + Semgrep + OSV + gitleaks take minutes): the
scanner returns a `jobId` immediately and records progress in the Supabase `repo_scan_jobs` table; the
web app polls that table and opens the saved report at `/r/{id}` when it's done. The cloned repo lives
only in a temp dir and is deleted after the scan. Enable with `SCANNER_USE_REPO_SCAN=1`
(+ `SCANNER_USE_SEMGREP=1` for SAST, `SCANNER_USE_GITLEAKS=1` for the history secret scan); needs `git`
(always), and `semgrep`/`gitleaks` on PATH (both baked into the Docker image). Only public
GitHub/GitLab/Bitbucket `https` URLs are accepted (host allowlist, no credentials, size/time caps).

## Structure

| Path | What |
|---|---|
| `packages/findings` | Shared catalog: finding types, plain-language explanations, fix prompts, scoring. Used by both apps. |
| `apps/scanner` | Fastify service. `collector.ts` (Playwright) + `detectors/*` + `ssrfGuard.ts` + `scorer` + `server.ts`. |
| `apps/web` | Next.js landing, `/api/scan` proxy route, loading screen, report UI. |

## Checks performed

1. **Leaked secrets** — 30+ high-signal key formats: Stripe (incl. webhook secrets), OpenAI,
   **Anthropic**, Google API/OAuth, AWS, GitHub/GitLab, npm/PyPI, SendGrid/Mailgun, Slack/Discord/Telegram,
   Shopify/Square/Notion/Linear/Doppler/Sentry/Mapbox/DigitalOcean/HuggingFace, FCM server keys, private keys,
   Supabase `service_role` JWTs, **database connection strings** (`postgres://user:pass@…`, Mongo/MySQL/Redis),
   plus high-entropy tokens with hash/UUID noise filtered out. Optional
   [gitleaks](https://github.com/gitleaks/gitleaks) for 150+ more patterns (Docker/CI only).
   - **Liveness verification** — for OpenAI, Anthropic, Stripe, GitHub, GitLab, SendGrid, Hugging Face,
     DigitalOcean, Telegram and Slack we make **one read-only call** to the provider (`/v1/models`,
     `/v1/balance`, `/user`, `getMe`, …) to confirm the key actually still works. A **confirmed-live** key
     is flagged as exploitable *right now* (and shows scope/account detail); a **revoked** key is auto-downgraded
     to `low` so dead keys stop generating false alarms. Strictly read-only, never follows redirects with the
     key attached, raw value never logged. Toggle with `SCANNER_VERIFY_SECRETS` (on by default).
2. **Open database** — finds the Supabase project + anon key, **enumerates the real schema via the PostgREST
   OpenAPI root** and probes each table for RLS-off reads; detects **public Storage buckets** that allow
   anonymous listing; Firebase Realtime DB / Firestore open-read check.
3. **Missing/weak auth** — JSON API endpoints returning data without login (high); private pages served as a
   client-only SPA shell (informational); **GraphQL introspection** left enabled in production.
4. **OWASP hygiene** — missing security headers, **weak CSP** (`unsafe-inline`/`unsafe-eval`/wildcard),
   clickjacking, **CORS that reflects any origin with credentials**, **insecure session cookies**
   (missing HttpOnly/Secure/SameSite), **mixed content**, source maps, and exposed sensitive files:
   `/.env*`, `/.git`, **database backups/dumps** (`.sql`/`.zip`/`.bak`), and config files
   (`.npmrc`, `docker-compose.yml`, `.DS_Store`, `.aws/credentials`, `wp-config.php`).

## Local development

Prerequisites: Node ≥ 20.

```bash
npm install
npx playwright install chromium       # one-time browser download for the scanner

cp .env.example .env                   # then set a real SCANNER_SHARED_SECRET
```

Run the two services (two terminals):

```bash
npm run dev:scanner                    # http://localhost:8787
npm run dev:web                        # http://localhost:3000
```

Open http://localhost:3000 and scan a public URL you own.

### Tests & checks

```bash
npm run test --workspace @vibescan/scanner    # SSRF guard + detector unit tests (offline)
npm run typecheck                              # all workspaces
npm run build --workspace @vibescan/web        # production build
```

## Environment

A single repo-root `.env` configures both services (the web app loads it via `next.config.mjs`).

| Var | Used by | Notes |
|---|---|---|
| `SCANNER_PORT` | scanner | default 8787 |
| `SCANNER_SHARED_SECRET` | both | required header `x-scan-secret` (web → scanner). Empty = dev-only, no auth. |
| `SCANNER_ALLOWED_ORIGINS` | scanner | CORS allow-list (your web origin) |
| `SCANNER_RATE_MAX` / `SCANNER_RATE_WINDOW_MS` | scanner | per-IP rate limit |
| `SCANNER_TIMEOUT_MS` | scanner | hard cap per scan |
| `SCANNER_USE_GITLEAKS` | scanner | `1` to run gitleaks if on PATH |
| `SCANNER_VERIFY_SECRETS` | scanner | read-only key liveness checks; `0` to disable (default on) |
| `SCANNER_URL` | web | where the proxy route forwards (e.g. your Render URL) |

## Deployment

- **web** → Vercel. Set `SCANNER_URL` (the deployed scanner) and `SCANNER_SHARED_SECRET`.
- **scanner** → Render / Railway via `apps/scanner/Dockerfile` (Playwright base image, optional gitleaks).
  Set the same `SCANNER_SHARED_SECRET`, plus `SCANNER_ALLOWED_ORIGINS` = your Vercel origin.
  (Docker is required to build the scanner image; it is not needed for local dev.)

## Safety / abuse controls

- **SSRF guard** rejects localhost, private, link-local and reserved IPs — before navigation and per
  request. Run `npm run test:ssrf` to verify.
- Per-IP rate limiting, per-scan timeout, JS-size cap, and a shared secret on the scanner.
- Terms checkbox: the user confirms they are allowed to scan the target.
- We are building a security product, so the scanner must not itself become an attack tool or a
  secret store — hence URL-only, stateless, masked, and no client tokens.

## Roadmap (later stages)

Accounts + saved reports + multi-project dashboard → monitoring (scheduled re-scans + alerts) +
fix-verification loop + trust badge → payments + tiers + agency white-label. See the strategy doc.
