import { toBytes, bytesToBase64, digestInput } from './bytes';

export const SRI_ALGOS = ['sha256', 'sha384', 'sha512'] as const;
export type SriAlgo = (typeof SRI_ALGOS)[number];

const SUBTLE: Record<SriAlgo, AlgorithmIdentifier> = {
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
};

/** A single `<algo>-<base64 digest>` Subresource Integrity token. */
export async function sriHash(content: string | ArrayBuffer, algo: SriAlgo): Promise<string> {
  const bytes = typeof content === 'string' ? toBytes(content) : new Uint8Array(content);
  const digest = await crypto.subtle.digest(SUBTLE[algo], digestInput(bytes));
  return `${algo}-${bytesToBase64(new Uint8Array(digest))}`;
}

export type SriKind = 'script' | 'style';

/** A ready-to-paste tag carrying the integrity + crossorigin attributes. */
export function sriTag(kind: SriKind, url: string, integrity: string): string {
  const src = url.trim() || (kind === 'script' ? 'https://example.com/app.js' : 'https://example.com/app.css');
  if (kind === 'script') {
    return `<script src="${src}"\n        integrity="${integrity}"\n        crossorigin="anonymous"></script>`;
  }
  return `<link rel="stylesheet" href="${src}"\n      integrity="${integrity}"\n      crossorigin="anonymous">`;
}
