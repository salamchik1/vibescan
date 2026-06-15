// VibeScan "online" agent — keeps the local scanner reachable from the Vercel site
// with zero manual steps.
//
// What it does, in a loop:
//   1. Make sure the scanner is up on localhost:PORT (reuse it if already running,
//      otherwise start it).
//   2. Open a public tunnel (Cloudflare quick tunnel by default) and capture its
//      https URL.
//   3. Publish that URL to Supabase (table scanner_endpoint, row id=1) and refresh
//      a heartbeat every 30s. The Vercel /api/scan route reads this row at request
//      time, so a changing tunnel URL is picked up live — no env edit, no redeploy.
//   4. If the tunnel drops, reopen it and publish the new URL automatically.
//
// Run it via: npm run online   (or the Сканер-онлайн launchers in the repo root).

import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

// ---- config (read from the repo-root .env) --------------------------------
const env = loadEnv(resolve(ROOT, '.env'));
const PORT = (env.SCANNER_PORT || '8787').trim();
const SUPABASE_URL = (env.NEXT_PUBLIC_SUPABASE_URL || '').trim().replace(/\/+$/, '');
const SERVICE_KEY = (env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
const HEALTH_URL = `http://localhost:${PORT}/health`;
const HEARTBEAT_MS = 30_000;

// ---- tunnel provider ------------------------------------------------------
// tunnelmole's free service is unreliable: it often connects at the TCP level
// but never emits a public URL, so the agent looped "no public URL → reopen"
// forever and the site stayed "offline". Default to Cloudflare's quick tunnel
// instead — free, no account, reliable, and it serves our JSON straight through
// (no interstitial warning page like loca.lt). Override with TUNNEL_PROVIDER
// (cloudflared | tunnelmole | localtunnel) in the repo-root .env.
const PROVIDER = (env.TUNNEL_PROVIDER || 'cloudflared').trim().toLowerCase();
const CF_PROTOCOL = (env.CLOUDFLARED_PROTOCOL || 'http2').trim().toLowerCase();

/** Locate the cloudflared binary: explicit env path, common install dir, or PATH. */
function cloudflaredBin() {
  const candidates = [
    env.CLOUDFLARED_PATH,
    'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
    'C:\\Program Files\\cloudflared\\cloudflared.exe',
  ].filter(Boolean);
  for (const c of candidates) {
    if (existsSync(c)) return `"${c}"`;
  }
  return 'cloudflared'; // assume it's on PATH
}

const PROVIDERS = {
  cloudflared: {
    label: 'Cloudflare quick tunnel',
    urlRe: /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i,
    // --protocol http2 forces the edge connection over TCP 7844 instead of QUIC.
    // Many networks (incl. this one) block outbound UDP, so QUIC never connects
    // and the tunnel stays dead; TCP 7844 is reachable, so http2 is the reliable
    // default. Override via CLOUDFLARED_PROTOCOL=auto to let cloudflared pick QUIC.
    command: () =>
      `${cloudflaredBin()} tunnel --url http://localhost:${PORT} --no-autoupdate --protocol ${CF_PROTOCOL}`,
  },
  tunnelmole: {
    label: 'tunnelmole',
    urlRe: /https:\/\/[a-z0-9-]+\.tunnelmole\.net/i,
    command: () => `npx -y tunnelmole ${PORT}`,
  },
  localtunnel: {
    label: 'localtunnel',
    urlRe: /https:\/\/[a-z0-9-]+\.loca\.lt/i,
    command: () => `npx -y localtunnel --port ${PORT}`,
  },
};
const TUNNEL = PROVIDERS[PROVIDER] || PROVIDERS.cloudflared;

if (!SUPABASE_URL || !SERVICE_KEY) {
  console.error('[online] .env is missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY.');
  console.error('[online] Fill those in (see SUPABASE-SETUP.md) — the agent needs them to publish the URL.');
  process.exit(1);
}

let currentUrl = null;     // last tunnel URL we published
let tunnel = null;         // tunnelmole child process
let tunnelStartedAt = 0;   // when the current tunnel was (re)opened
let publicFails = 0;       // consecutive heartbeats the public URL failed to reach us

// ---- main -----------------------------------------------------------------
log('starting…');
await ensureScanner();
openTunnel();
setInterval(heartbeat, HEARTBEAT_MS);

// ---------------------------------------------------------------------------

/** Ensure the scanner answers /health; start it (detached, reused next time) if not. */
async function ensureScanner() {
  if (await healthy()) {
    log(`scanner already running on :${PORT} — reusing it.`);
    return;
  }
  log(`scanner not up — starting it on :${PORT}…`);
  const child = spawn('npm run start:scanner', {
    cwd: ROOT,
    shell: true,
    detached: true,      // survives this agent so it can be reused
    stdio: 'ignore',
    windowsHide: true,
  });
  child.unref();

  // Wait up to ~60s for it to come alive (first run compiles + boots Fastify).
  for (let i = 0; i < 60; i++) {
    await sleep(1000);
    if (await healthy()) {
      log('scanner is up.');
      return;
    }
  }
  console.error('[online] scanner did not become healthy in time. Check the scanner logs.');
  process.exit(1);
}

/** Spawn the tunnel client, capture its public URL, and republish if it restarts. */
function openTunnel() {
  log(`opening public tunnel (${TUNNEL.label})…`);
  tunnelStartedAt = Date.now();
  tunnel = spawn(TUNNEL.command(), {
    cwd: ROOT,
    shell: true,
    windowsHide: true,
  });

  const onData = (buf) => {
    const text = buf.toString();
    process.stdout.write(text); // mirror tunnel output so the window shows it
    const m = text.match(TUNNEL.urlRe);
    if (m && m[0] !== currentUrl) {
      currentUrl = m[0];
      log(`public URL: ${currentUrl}`);
      publish(currentUrl);
    }
  };
  tunnel.stdout.on('data', onData);
  tunnel.stderr.on('data', onData);

  tunnel.on('exit', (code) => {
    log(`tunnel exited (code ${code}). Reopening in 5s…`);
    currentUrl = null;
    setTimeout(openTunnel, 5000);
  });
}

/** Refresh the heartbeat (and self-heal the scanner / tunnel if needed). */
async function heartbeat() {
  // 1. Keep the local scanner alive.
  if (!(await healthy())) {
    log('scanner stopped responding — restarting it…');
    await ensureScanner();
  }

  // 2. Only refresh the heartbeat if the PUBLIC url really reaches the scanner.
  //    A tunnel can lose its registration while the child process stays alive; the
  //    URL then serves a provider error page (HTML, not our JSON), which the Vercel
  //    site reports as an "unreadable response". Verifying the public url (not just
  //    localhost) stops us from publishing a dead tunnel as "live".
  if (currentUrl && (await publicHealthy(currentUrl))) {
    publicFails = 0;
    await publish(currentUrl);
    return;
  }

  // 3. The URL is missing or dead. While the tunnel is still coming up after a
  //    (re)open, just wait. Tolerate a single transient miss, then reopen to get a
  //    fresh, working URL. We deliberately stop refreshing updated_at so the site
  //    goes honestly "offline" rather than "unreadable" while we recover.
  if (!currentUrl && Date.now() - tunnelStartedAt <= 25_000) return;

  if (currentUrl && ++publicFails < 2) {
    log(`public URL didn't answer (strike ${publicFails}/2) — will reopen if it misses again.`);
    return;
  }

  log(currentUrl
    ? `public URL ${currentUrl} is dead — reopening tunnel…`
    : 'no public URL yet (no internet?) — reopening tunnel…');
  currentUrl = null;
  publicFails = 0;
  if (tunnel) tunnel.kill(); // the exit handler reopens it after 5s
}

/** Does the PUBLIC tunnel URL actually reach our scanner (not a tunnelmole error page)? */
async function publicHealthy(url) {
  try {
    const res = await fetch(`${url.replace(/\/+$/, '')}/health`, {
      // Bypass localtunnel's reminder page (harmless for other providers).
      headers: { 'bypass-tunnel-reminder': '1' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return false;
    const data = await res.json().catch(() => null);
    return !!(data && data.ok === true);
  } catch {
    return false;
  }
}

/** Upsert the current URL + a fresh timestamp into Supabase (row id = 1). */
async function publish(url) {
  try {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/scanner_endpoint`, {
      method: 'POST',
      headers: {
        apikey: SERVICE_KEY,
        authorization: `Bearer ${SERVICE_KEY}`,
        'content-type': 'application/json',
        prefer: 'resolution=merge-duplicates,return=minimal',
      },
      body: JSON.stringify({ id: 1, url, updated_at: new Date().toISOString() }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error(`[online] publish failed: HTTP ${res.status} ${body}`);
    }
  } catch (err) {
    console.error('[online] publish error:', err.message);
  }
}

async function healthy() {
  try {
    const res = await fetch(HEALTH_URL, { signal: AbortSignal.timeout(4000) });
    return res.ok;
  } catch {
    return false;
  }
}

function loadEnv(path) {
  const out = {};
  let raw = '';
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    return out;
  }
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const i = t.indexOf('=');
    if (i === -1) continue;
    out[t.slice(0, i).trim()] = t.slice(i + 1).trim();
  }
  return out;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function log(msg) {
  console.log(`[online] ${new Date().toLocaleTimeString()} ${msg}`);
}

// Keep the public URL from looking "live" the instant we shut down on purpose.
function shutdown() {
  if (tunnel) tunnel.kill();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
