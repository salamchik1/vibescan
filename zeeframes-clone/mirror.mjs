// Static-mirror the zeeframes.com homepage into this folder, fully offline.
// Downloads HTML + every same-origin/font asset it references (incl. nested
// url() refs inside CSS), then rewrites all absolute URLs to local paths.
import fs from 'node:fs';
import path from 'node:path';

const ORIGIN = 'https://zeeframes.com';
const START = ORIGIN + '/';
const OUT = process.cwd();
const MIRROR_HOSTS = new Set(['zeeframes.com', 'fonts.googleapis.com', 'fonts.gstatic.com']);
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';

// Only treat same-origin URLs as downloadable assets if they look like asset files
// (real extension). Everything else — nav links, API routes, search — stays a live link.
const ASSET_EXT = /\.(css|js|mjs|map|svg|png|jpe?g|webp|gif|ico|avif|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|json|pdf|txt|xml)(\?|$)/i;

// abs url -> local relative path (from mirror root), or null if it's the page itself / not mirrorable
function localPathFor(u) {
  let url;
  try { url = new URL(u); } catch { return null; }
  if (!/^https?:$/.test(url.protocol)) return null;
  if (!MIRROR_HOSTS.has(url.host)) return null;
  let p = url.pathname;
  if (url.host === 'zeeframes.com') {
    if (p === '/' || p === '') return null;       // the homepage itself stays external
    if (!ASSET_EXT.test(p)) return null;          // nav/page link, not an asset -> leave live
    return decodeURIComponent(p.replace(/^\//, ''));
  }
  if (url.host === 'fonts.googleapis.com') return '_ext/fonts.googleapis.com/fonts.css';
  let rel = '_ext/' + url.host + p;
  if (p.endsWith('/') || p === '') rel += 'index';
  return decodeURIComponent(rel.replace(/^\//, ''));
}

const isCssUrl = (u) => /\.css(\?|$)/i.test(u) || new URL(u, START).host === 'fonts.googleapis.com';

function findUrlsInHtml(html) {
  const re = /https?:\/\/(?:zeeframes\.com|fonts\.googleapis\.com|fonts\.gstatic\.com)[^"'()\s]+/g;
  return [...new Set(html.match(re) || [])];
}
function findUrlsInCss(css, baseUrl) {
  const out = [];
  const reUrl = /url\(\s*(['"]?)([^'")]+)\1\s*\)/g;
  const reImp = /@import\s+(?:url\()?\s*(['"])([^'"]+)\1/g;
  let m;
  for (const re of [reUrl, reImp]) {
    while ((m = re.exec(css))) {
      const ref = m[2].trim();
      if (!ref || ref.startsWith('data:')) continue;
      try { out.push(new URL(ref, baseUrl).href); } catch {}
    }
  }
  return [...new Set(out)];
}

const map = new Map();      // absUrl -> localRelPath (only successfully saved)
const cssText = new Map();  // localRelPath -> { url, text }
const visited = new Set();
let queue = [];
const enqueue = (u) => { if (u && !visited.has(u)) { visited.add(u); queue.push(u); } };

async function fetchBuf(u, tries = 3) {
  for (let i = 1; ; i++) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), 20000);
    try {
      const r = await fetch(u, { headers: { 'User-Agent': UA, 'Accept': '*/*' }, signal: ac.signal });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return Buffer.from(await r.arrayBuffer());
    } catch (e) {
      if (i >= tries) throw e;
    } finally {
      clearTimeout(t);
    }
  }
}
function save(rel, buf) {
  const abs = path.join(OUT, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, buf);
}

let ok = 0, fail = 0;
async function processOne(u) {
  const rel = localPathFor(u);
  if (!rel) return;
  try {
    const buf = await fetchBuf(u);
    save(rel, buf);
    map.set(u, rel);
    ok++;
    if (isCssUrl(u)) {
      const text = buf.toString('utf8');
      cssText.set(rel, { url: u, text });
      for (const nested of findUrlsInCss(text, u)) enqueue(nested);
    }
  } catch (e) {
    fail++;
    console.warn('  ! ' + u + '  (' + e.message + ')');
  }
}

async function drain(concurrency = 8) {
  while (queue.length) {
    const batch = queue.splice(0, concurrency);
    await Promise.all(batch.map(processOne));
  }
}

function rewriteHtml(html) {
  // replace longest URLs first to avoid prefix collisions
  const keys = [...map.keys()].sort((a, b) => b.length - a.length);
  for (const url of keys) html = html.split(url).join(map.get(url));
  return html;
}
function rewriteCss(localCssPath, info) {
  let css = info.text;
  const fromDir = path.dirname(path.join(OUT, localCssPath));
  const replace = (full, quote, ref) => {
    if (!ref || ref.startsWith('data:')) return full;
    let abs;
    try { abs = new URL(ref.trim(), info.url).href; } catch { return full; }
    const local = map.get(abs);
    if (!local) return full;
    let relLocal = path.relative(fromDir, path.join(OUT, local)).split(path.sep).join('/');
    return `url(${quote}${relLocal}${quote})`;
  };
  css = css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, (f, q, r) => replace(f, q, r));
  css = css.replace(/@import\s+(['"])([^'"]+)\1/g, (f, q, r) => {
    const abs = (() => { try { return new URL(r.trim(), info.url).href; } catch { return null; } })();
    const local = abs && map.get(abs);
    if (!local) return f;
    const relLocal = path.relative(fromDir, path.join(OUT, local)).split(path.sep).join('/');
    return `@import ${q}${relLocal}${q}`;
  });
  return css;
}

(async () => {
  console.log('Fetching homepage…');
  const htmlRaw = (await fetchBuf(START)).toString('utf8');
  for (const u of findUrlsInHtml(htmlRaw)) enqueue(u);
  console.log('Discovered ' + queue.length + ' top-level asset URLs. Downloading…');
  await drain();

  console.log('Rewriting CSS files…');
  for (const [rel, info] of cssText) save(rel, Buffer.from(rewriteCss(rel, info), 'utf8'));

  console.log('Rewriting & saving index.html…');
  save('index.html', Buffer.from(rewriteHtml(htmlRaw), 'utf8'));

  console.log(`\nDone. Saved ${ok} assets (${fail} failed). Mirror root: ${OUT}`);
})();
