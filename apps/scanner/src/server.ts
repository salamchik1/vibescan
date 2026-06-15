import { timingSafeEqual } from 'node:crypto';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { config, SCANNER_VERSION } from './config';
import { runScan, runCodeScan, TimeoutError } from './scan';
import { SsrfError } from './ssrfGuard';
import { closeBrowser } from './collector';
import { runRepoScan } from './repo/runRepoScan';
import { RepoLimitError } from './repo/clone';
import {
  createJob,
  updateJobStatus,
  completeJob,
  failJob,
  getJob,
  saveRepoScan,
  recoverOrphanJobs,
  repoJobsConfigured,
} from './repo/jobs';

function secretMatches(provided: string): boolean {
  if (!config.sharedSecret) return true; // dev mode: no secret configured
  const a = Buffer.from(provided);
  const b = Buffer.from(config.sharedSecret);
  return a.length === b.length && timingSafeEqual(a, b);
}

const MAX_CODE_BYTES = 512 * 1024; // pasted-code scans accept larger bodies

// Security response headers applied to every reply. This service is a JSON API
// that is never meant to be embedded or to load remote resources, so a locked
// down CSP is safe. Mirrors apps/web/next.config.mjs so the scanner's own
// backend passes the same OWASP header checks it runs against other sites.
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  // Only honored over HTTPS, so harmless on localhost.
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

const app = Fastify({
  logger: { level: 'info' },
  bodyLimit: MAX_CODE_BYTES + 1024,
});

await app.register(cors, {
  origin: config.allowedOrigins.length ? config.allowedOrigins : false,
  methods: ['POST', 'GET'],
  allowedHeaders: ['content-type', 'x-scan-secret'],
});

await app.register(rateLimit, {
  max: config.rateMax,
  timeWindow: config.rateWindowMs,
});

// Stamp security headers onto every response (including 404s, errors and
// rate-limit 429s). onSend runs for all replies before headers are flushed.
app.addHook('onSend', async (_req, reply, payload) => {
  reply.headers(SECURITY_HEADERS);
  return payload;
});

app.get('/health', async () => ({ ok: true, version: SCANNER_VERSION }));

app.post('/scan', async (req, reply) => {
  const provided = (req.headers['x-scan-secret'] as string | undefined) ?? '';
  if (!secretMatches(provided)) {
    return reply.code(401).send({ error: 'Unauthorized.' });
  }

  const body = req.body as { url?: unknown; code?: unknown } | undefined;
  const code = body?.code;
  const url = body?.url;

  // Code-paste scan takes precedence when a non-empty "code" string is provided.
  if (typeof code === 'string' && code.trim().length > 0) {
    if (code.length > MAX_CODE_BYTES) {
      return reply.code(400).send({ error: 'Pasted code is too large (max ~500 KB).' });
    }
    try {
      const result = await runCodeScan(code);
      return reply.send(result);
    } catch (err) {
      if (err instanceof TimeoutError) {
        return reply.code(504).send({ error: 'The scan took too long. Try pasting less code.' });
      }
      req.log.error(err);
      return reply.code(500).send({ error: 'The scan failed unexpectedly. Please try again.' });
    }
  }

  if (typeof url !== 'string' || url.length === 0 || url.length > 2048) {
    return reply.code(400).send({ error: 'Provide a valid "url" string or "code" to scan.' });
  }

  try {
    const result = await runScan(url);
    return reply.send(result);
  } catch (err) {
    if (err instanceof SsrfError) {
      return reply.code(400).send({ error: err.message });
    }
    if (err instanceof TimeoutError) {
      return reply.code(504).send({ error: 'The scan took too long. The site may be slow or very large.' });
    }
    req.log.error(err);
    return reply.code(500).send({ error: 'The scan failed unexpectedly. Please try again.' });
  }
});

// --- Repository (source-code) scan: async job pipeline ---------------------

/**
 * Run a repo scan to completion, recording every state transition in Supabase
 * so the web app can poll without touching the scanner. Fire-and-forget: errors
 * are captured as a failed-job status, never thrown to an awaiting request.
 */
async function processRepoJob(jobId: string, repoUrl: string, userId: string | null): Promise<void> {
  try {
    const result = await runRepoScan(repoUrl, (phase) => {
      void updateJobStatus(jobId, phase);
    });
    const scanId = await saveRepoScan(result, userId);
    await completeJob(jobId, scanId);
  } catch (err) {
    const message =
      err instanceof SsrfError
        ? err.message
        : err instanceof RepoLimitError
          ? err.message
          : err instanceof TimeoutError
            ? 'The repository scan took too long.'
            : 'The repository scan failed unexpectedly.';
    if (!(err instanceof SsrfError) && !(err instanceof RepoLimitError)) app.log.error(err);
    await failJob(jobId, message);
  }
}

// Enqueue a repo scan. Returns a jobId immediately (202); the web app polls
// Supabase for completion. Rate-limited harder than /scan — repo scans are heavy.
app.post(
  '/scan/repo',
  { config: { rateLimit: { max: 2, timeWindow: config.rateWindowMs } } },
  async (req, reply) => {
    const provided = (req.headers['x-scan-secret'] as string | undefined) ?? '';
    if (!secretMatches(provided)) {
      return reply.code(401).send({ error: 'Unauthorized.' });
    }
    if (!config.useRepoScan) {
      return reply.code(503).send({ error: 'Repository scanning is not enabled on this server.' });
    }
    if (!repoJobsConfigured) {
      return reply.code(503).send({ error: 'Repository scanning needs a database, which is not configured.' });
    }

    const body = req.body as { repoUrl?: unknown; userId?: unknown } | undefined;
    const repoUrl = typeof body?.repoUrl === 'string' ? body.repoUrl.trim() : '';
    if (!repoUrl || repoUrl.length > 2048) {
      return reply.code(400).send({ error: 'Provide a valid "repoUrl" to scan.' });
    }
    const userId = typeof body?.userId === 'string' && body.userId ? body.userId : null;

    const jobId = await createJob(repoUrl, userId);
    if (!jobId) {
      return reply.code(503).send({ error: 'Could not start the scan. Please try again shortly.' });
    }

    void processRepoJob(jobId, repoUrl, userId);
    return reply.code(202).send({ jobId });
  }
);

// Poll a repo-scan job. The web app normally reads Supabase directly; this is a
// convenience/debug surface that mirrors the same fields.
app.get('/scan/repo/:id', async (req, reply) => {
  const provided = (req.headers['x-scan-secret'] as string | undefined) ?? '';
  if (!secretMatches(provided)) {
    return reply.code(401).send({ error: 'Unauthorized.' });
  }
  const { id } = req.params as { id: string };
  const job = await getJob(id);
  if (!job) return reply.code(404).send({ error: 'Job not found.' });
  return reply.send({ status: job.status, scanId: job.scan_id, error: job.error });
});

if (!config.sharedSecret) {
  app.log.warn('SCANNER_SHARED_SECRET is not set — running without scanner auth (dev only).');
}

// Fail any repo-scan jobs left mid-flight by a previous process so clients don't
// poll a zombie job forever.
if (config.useRepoScan && repoJobsConfigured) {
  void recoverOrphanJobs();
}

try {
  await app.listen({ port: config.port, host: '0.0.0.0' });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}

async function shutdown() {
  await closeBrowser().catch(() => {});
  await app.close().catch(() => {});
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
