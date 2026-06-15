import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding, Severity } from '@vibescan/findings';
import type { RepoContext } from '../types';

/** A resolved dependency to check against OSV. */
interface Dep {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Go';
}

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const HTTP_TIMEOUT_MS = 15_000;
const MAX_DEPS = 3000; // safety bound on how many packages we query
const MAX_DETAIL_FETCHES = 60; // bound the per-vuln detail lookups

/** Lockfiles we understand, mapped to a parser. Nested copies (node_modules/vendor) are skipped. */
const LOCKFILES: Record<string, (text: string) => Dep[]> = {
  'package-lock.json': parseNpmLock,
  'npm-shrinkwrap.json': parseNpmLock,
  'yarn.lock': parseYarnLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'requirements.txt': parseRequirements,
  'go.mod': parseGoMod,
};

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i >= 0 ? p.slice(i + 1) : p;
}

function isVendored(relPath: string): boolean {
  return /(^|\/)(node_modules|vendor|\.venv|venv|site-packages)\//.test(relPath);
}

/**
 * Scan committed lockfiles for dependencies with known vulnerabilities via the
 * free OSV.dev API (no key). One Finding per vulnerable package (worst advisory).
 * Network/parse failures degrade gracefully — they propagate to the caller's
 * safe() wrapper, which records a note instead of failing the whole scan.
 */
export async function detectVulnerableDeps(ctx: RepoContext): Promise<Finding[]> {
  // 1) Discover + parse lockfiles into a deduped dependency set.
  const deps = new Map<string, Dep>(); // key: ecosystem|name|version
  for (const rel of ctx.files) {
    if (isVendored(rel)) continue;
    const parser = LOCKFILES[basename(rel)];
    if (!parser) continue;
    let text: string;
    try {
      text = await readFile(join(ctx.dir, rel), 'utf8');
    } catch {
      continue;
    }
    for (const dep of parser(text)) {
      if (!dep.name || !dep.version) continue;
      const key = `${dep.ecosystem}|${dep.name}|${dep.version}`;
      if (!deps.has(key)) deps.set(key, dep);
      if (deps.size >= MAX_DEPS) break;
    }
    if (deps.size >= MAX_DEPS) break;
  }

  if (deps.size === 0) return [];
  const depList = [...deps.values()];

  // 2) Batch-query OSV to learn which deps are vulnerable (ids only).
  const vulnByDep: Array<{ dep: Dep; ids: string[] }> = [];
  for (let i = 0; i < depList.length; i += 100) {
    const chunk = depList.slice(i, i + 100);
    const body = {
      queries: chunk.map((d) => ({
        version: d.version,
        package: { name: d.name, ecosystem: d.ecosystem },
      })),
    };
    const res = await fetchJson(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const results = (res?.results ?? []) as Array<{ vulns?: Array<{ id?: string }> }>;
    results.forEach((r, idx) => {
      const ids = (r.vulns ?? []).map((v) => v.id).filter((x): x is string => !!x);
      if (ids.length) vulnByDep.push({ dep: chunk[idx]!, ids });
    });
  }

  if (vulnByDep.length === 0) return [];

  // 3) Fetch details (severity + summary) for a bounded number of advisories.
  const findings: Finding[] = [];
  let detailFetches = 0;
  for (const { dep, ids } of vulnByDep) {
    let severity: Severity = 'high'; // a known vuln with no severity data is still serious
    let advisory = ids[0]!;
    let summary = '';

    if (detailFetches < MAX_DETAIL_FETCHES) {
      detailFetches += 1;
      const detail = await fetchJson(`${OSV_VULN_URL}${encodeURIComponent(ids[0]!)}`).catch(() => null);
      if (detail) {
        severity = severityFromVuln(detail);
        advisory = pickAdvisoryId(detail) ?? advisory;
        summary = typeof detail.summary === 'string' ? detail.summary : '';
      }
    }

    const extra = ids.length > 1 ? ` (+${ids.length - 1} more)` : '';
    findings.push({
      type: 'vulnerable_dependency',
      severity,
      category: 'dependencies',
      summary: `${dep.name}@${dep.version} — ${advisory}${extra}`,
      evidence: summary ? summary.slice(0, 240) : undefined,
      params: {
        package: dep.name,
        version: dep.version,
        advisory,
        ecosystem: dep.ecosystem,
      },
    });
  }

  return findings;
}

// --- OSV helpers -----------------------------------------------------------

async function fetchJson(url: string, init?: RequestInit): Promise<any> {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  return res.json();
}

const SEV_WORDS: Record<string, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  MEDIUM: 'medium',
  LOW: 'low',
};

/** Derive our severity from an OSV vuln: DB-specific word first, then CVSS score. */
function severityFromVuln(vuln: any): Severity {
  const word = String(vuln?.database_specific?.severity ?? '').toUpperCase();
  if (SEV_WORDS[word]) return SEV_WORDS[word];

  const sevs: Array<{ type?: string; score?: string }> = vuln?.severity ?? [];
  for (const s of sevs) {
    if (typeof s.score === 'string') {
      const m = s.score.match(/(\d+(\.\d+)?)/); // CVSS vector may embed a numeric base score
      const num = m ? Number(m[1]) : NaN;
      if (Number.isFinite(num)) {
        if (num >= 9) return 'critical';
        if (num >= 7) return 'high';
        if (num >= 4) return 'medium';
        return 'low';
      }
    }
  }
  return 'high';
}

/** Prefer a CVE id (more recognisable) over the GHSA/internal id. */
function pickAdvisoryId(vuln: any): string | undefined {
  const aliases: string[] = Array.isArray(vuln?.aliases) ? vuln.aliases : [];
  const cve = aliases.find((a) => /^CVE-/i.test(a));
  return cve ?? (typeof vuln?.id === 'string' ? vuln.id : undefined);
}

// --- Lockfile parsers ------------------------------------------------------

function parseNpmLock(text: string): Dep[] {
  let json: any;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  const out: Dep[] = [];

  // lockfileVersion 2/3: flat `packages` keyed by install path.
  if (json.packages && typeof json.packages === 'object') {
    for (const [path, meta] of Object.entries<any>(json.packages)) {
      if (!path) continue; // "" is the root project
      const name = path.includes('node_modules/')
        ? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length)
        : path;
      if (meta?.version) out.push({ name, version: meta.version, ecosystem: 'npm' });
    }
  }

  // lockfileVersion 1: nested `dependencies`.
  const walk = (deps: Record<string, any> | undefined) => {
    if (!deps) return;
    for (const [name, meta] of Object.entries(deps)) {
      if (meta?.version) out.push({ name, version: meta.version, ecosystem: 'npm' });
      walk(meta?.dependencies);
    }
  };
  if (out.length === 0) walk(json.dependencies);

  return out;
}

function parseYarnLock(text: string): Dep[] {
  const out: Dep[] = [];
  const lines = text.split(/\r?\n/);
  let currentNames: string[] = [];
  for (const line of lines) {
    if (/^[^\s].*:\s*$/.test(line)) {
      // Header line: one or more comma-separated specs ending in ':'.
      currentNames = line
        .replace(/:\s*$/, '')
        .split(',')
        .map((s) => s.trim().replace(/^"|"$/g, ''))
        .map(nameFromYarnSpec)
        .filter(Boolean);
    } else {
      const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
      if (m && currentNames.length) {
        for (const name of currentNames) out.push({ name, version: m[1]!, ecosystem: 'npm' });
        currentNames = [];
      }
    }
  }
  return out;
}

/** "@babel/core@^7.0.0" -> "@babel/core"; "lodash@^4.0.0" -> "lodash". */
function nameFromYarnSpec(spec: string): string {
  const at = spec.lastIndexOf('@');
  if (at <= 0) return spec; // no version range, or scoped name with '@' at 0 only
  return spec.slice(0, at);
}

function parsePnpmLock(text: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    // Package keys look like:  /lodash@4.17.21:  or  /@babel/core@7.12.3(...):  (v6+)
    //                     or:  /lodash/4.17.21:  (v5)
    const m = line.match(/^\s{0,4}\/(.+?):\s*$/);
    if (!m) continue;
    let key = m[1]!;
    // Drop peer-dep suffix in parentheses: "@7.12.3(react@18)" -> "@7.12.3"
    const paren = key.indexOf('(');
    if (paren >= 0) key = key.slice(0, paren);

    let name = '';
    let version = '';
    const atSep = key.lastIndexOf('@');
    if (atSep > 0) {
      name = key.slice(0, atSep);
      version = key.slice(atSep + 1);
    } else {
      const slash = key.lastIndexOf('/');
      if (slash > 0) {
        name = key.slice(0, slash);
        version = key.slice(slash + 1);
      }
    }
    if (name && /^\d/.test(version)) out.push({ name, version, ecosystem: 'npm' });
  }
  return out;
}

function parseRequirements(text: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split('#')[0]!.trim();
    if (!line || line.startsWith('-')) continue; // skip flags/options like -r, -e
    const m = line.match(/^([A-Za-z0-9._-]+)\s*==\s*([^\s;]+)/);
    if (m) out.push({ name: m[1]!, version: m[2]!, ecosystem: 'PyPI' });
  }
  return out;
}

function parseGoMod(text: string): Dep[] {
  const out: Dep[] = [];
  const lines = text.split(/\r?\n/);
  let inBlock = false;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('require (')) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    const body = inBlock ? line : line.startsWith('require ') ? line.slice('require '.length) : '';
    if (!body) continue;
    // e.g. "github.com/foo/bar v1.2.3" or "github.com/foo/bar v1.2.3 // indirect"
    const m = body.match(/^(\S+)\s+(v[^\s/]+)/);
    if (m) out.push({ name: m[1]!, version: m[2]!.replace(/^v/, ''), ecosystem: 'Go' });
  }
  return out;
}
