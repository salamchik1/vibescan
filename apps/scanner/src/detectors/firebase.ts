import type { Finding } from '@vibescan/findings';
import type { CollectResult } from '../collector';
import { safeFetch } from '../util/fetch';

const DB_URL_RE = /https?:\/\/([a-z0-9-]+)\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)/gi;
const PROJECT_ID_RE = /projectId\s*[:=]\s*['"`]([a-z0-9-]+)['"`]/i;

export async function detectFirebase(collected: CollectResult): Promise<Finding[]> {
  const text = collected.jsCombined;
  const findings: Finding[] = [];

  // Collect Realtime Database URLs from JS and from contacted hosts.
  const dbUrls = new Set<string>();
  for (const m of text.matchAll(DB_URL_RE)) dbUrls.add(m[0].replace(/\/+$/, ''));
  for (const host of collected.requestedHosts) {
    if (/\.firebaseio\.com$/i.test(host) || /\.firebasedatabase\.app$/i.test(host)) {
      dbUrls.add(`https://${host}`);
    }
  }

  // Realtime Database: a shallow read of the root reveals whether rules are open.
  for (const dbUrl of dbUrls) {
    try {
      const res = await safeFetch(`${dbUrl}/.json?shallow=true`, { timeoutMs: 8_000, maxBytes: 50_000 });
      if (res.status === 200 && res.body.trim() !== 'null' && !/permission denied/i.test(res.body)) {
        findings.push({
          type: 'firebase_rules_open',
          severity: 'critical',
          category: 'database',
          summary: 'Firebase Realtime Database is readable without authentication.',
          evidence: `${new URL(dbUrl).host}/.json → 200`,
        });
      }
    } catch {
      /* skip */
    }
  }

  // Firestore: try a couple of common collections only if we know the project id.
  const projectMatch = PROJECT_ID_RE.exec(text);
  const projectId = projectMatch?.[1];
  if (projectId && findings.length === 0) {
    for (const coll of ['users', 'profiles']) {
      const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${coll}?pageSize=1`;
      try {
        const res = await safeFetch(url, { timeoutMs: 8_000, maxBytes: 50_000 });
        if (res.status === 200 && /"documents"\s*:/.test(res.body)) {
          findings.push({
            type: 'firebase_rules_open',
            severity: 'critical',
            category: 'database',
            summary: `Firestore collection "${coll}" is readable without authentication.`,
            evidence: `Firestore ${coll} → 200 with documents`,
          });
          break;
        }
      } catch {
        /* skip */
      }
    }
  }

  return findings;
}
