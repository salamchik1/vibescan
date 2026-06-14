// Tiny static file server for the offline ZeeFrames mirror.
// Usage: node serve.mjs   (then open http://localhost:8080)
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 8080;

// Protective HTTP headers stamped onto every response (200s, 403s and 404s alike)
// so the static mirror passes the same OWASP header checks the scanner runs.
// frame-ancestors 'none' also covers clickjacking; X-Frame-Options is kept for
// older browsers. The CSP keeps 'unsafe-inline' for script/style because this is
// a verbatim static mirror full of inline <script> blocks and inline onload/style
// attributes that can't carry a nonce or hash — a deliberate trade-off for a
// reference mirror. HSTS is ignored over plain-HTTP localhost, so it's harmless here.
const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "img-src 'self' data: blob:",
    "font-src 'self' https://fonts.gstatic.com data:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "script-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com",
  ].join('; '),
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.avif': 'image/avif',
  '.gif': 'image/gif', '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.otf': 'font/otf', '.eot': 'application/vnd.ms-fontobject',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.pdf': 'application/pdf',
};

http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p === '/' || p === '') p = '/index.html';
  const abs = path.join(ROOT, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
  if (!abs.startsWith(ROOT)) { res.writeHead(403, { ...SECURITY_HEADERS }).end('Forbidden'); return; }
  fs.readFile(abs, (err, data) => {
    if (err) { res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' }).end('404 Not Found'); return; }
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(abs).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(PORT, () => console.log(`ZeeFrames mirror → http://localhost:${PORT}`));
