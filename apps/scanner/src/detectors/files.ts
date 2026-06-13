import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch, looksLikeHtml } from '../util/fetch';

interface ProbeHit {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** GET a path; return it only when it is a real 200 that is NOT the SPA index.html fallback. */
async function probe(url: string): Promise<ProbeHit | null> {
  try {
    const res = await safeFetch(url, { timeoutMs: 7_000, maxBytes: 120_000, redirect: 'manual' });
    if (res.status !== 200) return null;
    if (looksLikeHtml(res.headers, res.body)) return null;
    return { status: res.status, headers: res.headers, body: res.body };
  } catch {
    return null;
  }
}

/** A live .env file is mostly KEY=value lines, not an HTML page or random text. */
function looksLikeEnv(body: string): boolean {
  const lines = body.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#'));
  if (lines.length === 0) return false;
  const kv = lines.filter((l) => /^[A-Z0-9_]+\s*=/.test(l.trim()));
  return kv.length >= 1 && kv.length / lines.length > 0.5;
}

/** Heuristic: a real binary archive (zip/gzip/sqlite) carries control bytes that text/HTML never do. */
function looksBinary(body: string): boolean {
  return /[\x00-\x08\x0e\x0f]/.test(body.slice(0, 1024));
}

const ENV_PATHS = ['/.env', '/.env.local', '/.env.production', '/.env.development', '/.env.prod'];
const GIT_PATHS = ['/.git/config', '/.git/HEAD'];
const BACKUP_PATHS = [
  '/backup.sql',
  '/dump.sql',
  '/database.sql',
  '/db.sql',
  '/backup.zip',
  '/backup.tar.gz',
  '/backup.bak',
  '/db.sqlite',
];

const SQL_HINT = /\b(CREATE TABLE|INSERT INTO|DROP TABLE|PostgreSQL database dump|-- MySQL dump)\b/i;
const ARCHIVE_CT = /(zip|gzip|x-tar|octet-stream|sql|sqlite)/i;

export async function detectFiles(collected: CollectResult): Promise<Finding[]> {
  const origin = collected.origin;
  if (!origin) return [];
  const findings: Finding[] = [];

  // Probe everything in parallel; each request has its own timeout.
  const [envHits, gitHits, backupHits, npmrc, dockerCompose, dsStore, awsCreds, wpConfig] =
    await Promise.all([
      Promise.all(ENV_PATHS.map((p) => probe(origin + p).then((h) => [p, h] as const))),
      Promise.all(GIT_PATHS.map((p) => probe(origin + p).then((h) => [p, h] as const))),
      Promise.all(BACKUP_PATHS.map((p) => probe(origin + p).then((h) => [p, h] as const))),
      probe(origin + '/.npmrc'),
      probe(origin + '/docker-compose.yml'),
      probe(origin + '/.DS_Store'),
      probe(origin + '/.aws/credentials'),
      probe(origin + '/wp-config.php'),
    ]);

  // 1) Environment files (any variant) — usually the jackpot for attackers.
  for (const [path, hit] of envHits) {
    if (hit && looksLikeEnv(hit.body)) {
      findings.push({
        type: 'exposed_env_file',
        severity: 'critical',
        category: 'owasp',
        summary: `Your ${path} file is publicly downloadable.`,
        evidence: `${path} → 200`,
        params: { path },
      });
      break; // one finding is enough; the fix covers all of them
    }
  }

  // 2) Exposed .git — full source history can be reconstructed.
  for (const [path, hit] of gitHits) {
    if (!hit) continue;
    const isConfig = path.endsWith('config') && /\[core\]|\[remote |\[branch /.test(hit.body);
    const isHead = path.endsWith('HEAD') && /^ref:\s+refs\//.test(hit.body.trim());
    if (isConfig || isHead) {
      findings.push({
        type: 'exposed_git',
        severity: 'high',
        category: 'owasp',
        summary: 'Your /.git directory is publicly accessible — source code can be downloaded.',
        evidence: `${path} → 200`,
        params: { path: '/.git/' },
      });
      break;
    }
  }

  // 3) Database backups / source archives.
  for (const [path, hit] of backupHits) {
    if (!hit) continue;
    const ct = hit.headers['content-type'] ?? '';
    const isSql = path.endsWith('.sql') && SQL_HINT.test(hit.body);
    const isArchive =
      /\.(zip|tar\.gz|bak|sqlite)$/.test(path) && (ARCHIVE_CT.test(ct) || looksBinary(hit.body));
    if (isSql || isArchive) {
      findings.push({
        type: 'exposed_backup',
        severity: 'critical',
        category: 'owasp',
        summary: `A downloadable backup/archive is exposed at ${path}.`,
        evidence: `${path} → 200`,
        params: { path },
      });
    }
  }

  // 4) Config / metadata files.
  if (npmrc && /_authToken|registry\s*=/.test(npmrc.body)) {
    const hasToken = /_authToken/.test(npmrc.body);
    findings.push({
      type: 'exposed_config_file',
      severity: hasToken ? 'high' : 'low',
      category: 'owasp',
      summary: hasToken
        ? 'Your /.npmrc is exposed and contains an npm auth token.'
        : 'Your /.npmrc file is publicly accessible.',
      evidence: '/.npmrc → 200',
      params: { path: '/.npmrc' },
    });
  }
  if (dockerCompose && /^\s*services\s*:/m.test(dockerCompose.body)) {
    findings.push({
      type: 'exposed_config_file',
      severity: /environment\s*:|[A-Z_]+_PASSWORD|[A-Z_]+_KEY/.test(dockerCompose.body) ? 'medium' : 'low',
      category: 'owasp',
      summary: 'Your docker-compose.yml is publicly accessible.',
      evidence: '/docker-compose.yml → 200',
      params: { path: '/docker-compose.yml' },
    });
  }
  if (dsStore && /Bud1/.test(dsStore.body.slice(0, 8))) {
    findings.push({
      type: 'exposed_config_file',
      severity: 'low',
      category: 'owasp',
      summary: 'A macOS /.DS_Store file is exposed, revealing your file and folder names.',
      evidence: '/.DS_Store → 200',
      params: { path: '/.DS_Store' },
    });
  }
  if (awsCreds && /aws_access_key_id/i.test(awsCreds.body)) {
    findings.push({
      type: 'exposed_config_file',
      severity: 'critical',
      category: 'owasp',
      summary: 'Your AWS credentials file (/.aws/credentials) is publicly downloadable.',
      evidence: '/.aws/credentials → 200',
      params: { path: '/.aws/credentials' },
    });
  }
  if (wpConfig && /DB_PASSWORD|DB_NAME|AUTH_KEY/.test(wpConfig.body)) {
    findings.push({
      type: 'exposed_config_file',
      severity: 'critical',
      category: 'owasp',
      summary: 'Your wp-config.php is served as plain text, exposing database credentials.',
      evidence: '/wp-config.php → 200',
      params: { path: '/wp-config.php' },
    });
  }

  return findings;
}
