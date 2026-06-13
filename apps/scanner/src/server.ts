import { timingSafeEqual } from 'node:crypto';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import { config, SCANNER_VERSION } from './config';
import { runScan, runCodeScan, TimeoutError } from './scan';
import { SsrfError } from './ssrfGuard';
import { closeBrowser } from './collector';

function secretMatches(provided: string): boolean {
  if (!config.sharedSecret) return true; // dev mode: no secret configured
  const a = Buffer.from(provided);
  const b = Buffer.from(config.sharedSecret);
  return a.length === b.length && timingSafeEqual(a, b);
}

const MAX_CODE_BYTES = 512 * 1024; // pasted-code scans accept larger bodies

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

if (!config.sharedSecret) {
  app.log.warn('SCANNER_SHARED_SECRET is not set — running without scanner auth (dev only).');
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
