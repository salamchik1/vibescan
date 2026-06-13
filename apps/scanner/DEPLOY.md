# Deploying the scanner

The scanner runs Playwright (headless Chromium) + gitleaks, so it can't live on
Vercel or in the browser — it needs a real container host. The web app (Vercel)
calls it server-side over HTTP with a shared secret.

```
Browser ──> Vercel web app ──(x-scan-secret)──> Scanner (Render/Railway, this service)
```

## Render (blueprint)

1. Push this repo to GitHub.
2. Render → **New → Blueprint** → select the repo. It reads [`render.yaml`](../../render.yaml).
3. Render auto-generates `SCANNER_SHARED_SECRET`. Set `SCANNER_ALLOWED_ORIGINS`
   to your web origin (e.g. `https://your-app.vercel.app`).
4. Deploy. Public URL: `https://vibescan-scanner.onrender.com`.

Use the **Starter** plan or higher — Chromium OOMs on the 512 MB free tier.

## Railway

1. Railway → **New Project → Deploy from GitHub repo**.
2. Railway reads [`railway.json`](../../railway.json) (Dockerfile build, `/health` check).
3. In **Variables**, set:
   - `SCANNER_SHARED_SECRET` = a long random string
   - `SCANNER_ALLOWED_ORIGINS` = your web origin
   - `SCANNER_USE_GITLEAKS=1`, `SCANNER_VERIFY_SECRETS=1`
4. **Generate Domain** to get a public URL. Railway injects `PORT` automatically.

## Wire the web app to it

In the Vercel project env (server-side only, never `NEXT_PUBLIC_`):

```
SCANNER_URL=https://<your-scanner-host>
SCANNER_SHARED_SECRET=<same secret as the scanner>
```

## Verify

```bash
# health
curl https://<host>/health
# -> {"ok":true,"version":"0.3.0"}

# a real scan (needs the secret)
curl -X POST https://<host>/scan \
  -H "content-type: application/json" \
  -H "x-scan-secret: <SCANNER_SHARED_SECRET>" \
  -d '{"url":"https://example.com"}'
```

Without the header you get `401`. `SCANNER_ALLOWED_ORIGINS` only gates browsers
(CORS); server-to-server calls from the web app are gated by the secret.

## Env vars

| Var | Purpose |
|-----|---------|
| `SCANNER_SHARED_SECRET` | Required `x-scan-secret` header. Empty = open (dev only). |
| `SCANNER_ALLOWED_ORIGINS` | Comma-separated CORS origins for browser calls. |
| `PORT` / `SCANNER_PORT` | Listen port. Host injects `PORT`; `SCANNER_PORT` is the local default. |
| `SCANNER_USE_GITLEAKS` | `1` to run the bundled gitleaks binary. |
| `SCANNER_VERIFY_SECRETS` | `1` to do read-only liveness checks on found keys. |
| `SCANNER_RATE_MAX` / `SCANNER_RATE_WINDOW_MS` | Per-IP rate limit. |
| `SCANNER_TIMEOUT_MS` | Hard per-scan timeout. |
