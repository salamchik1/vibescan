import { toBytes, toHex, digestInput } from './bytes';

export const HASH_ALGOS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const;
export type HashAlgo = (typeof HASH_ALGOS)[number];

/** Hash arbitrary bytes with the given algorithm, returning lowercase hex. */
export async function hashBytes(bytes: Uint8Array, algo: HashAlgo): Promise<string> {
  if (algo === 'MD5') return md5(bytes);
  const digest = await crypto.subtle.digest(algo, digestInput(bytes));
  return toHex(new Uint8Array(digest));
}

/** Hash a UTF-8 string. */
export async function hashText(text: string, algo: HashAlgo): Promise<string> {
  return hashBytes(toBytes(text), algo);
}

/** Compute every supported digest of a string at once. */
export async function hashAll(text: string): Promise<Record<HashAlgo, string>> {
  const bytes = toBytes(text);
  const entries = await Promise.all(
    HASH_ALGOS.map(async (algo) => [algo, await hashBytes(bytes, algo)] as const)
  );
  return Object.fromEntries(entries) as Record<HashAlgo, string>;
}

// --- MD5 (RFC 1321) ------------------------------------------------------
// The Web Crypto API does not implement MD5, so we ship a small, self-contained
// version. MD5 is broken for security use; it is offered only for legacy
// checksums (the UI warns about this).

const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14,
  20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6,
  10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K = (() => {
  const k = new Int32Array(64);
  for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
  return k;
})();

function rotl(x: number, c: number): number {
  return (x << c) | (x >>> (32 - c));
}

function md5(bytes: Uint8Array): string {
  const len = bytes.length;
  const padded = Math.ceil((len + 9) / 64) * 64;
  const msg = new Uint8Array(padded);
  msg.set(bytes);
  msg[len] = 0x80;
  const view = new DataView(msg.buffer);
  const bitLen = len * 8;
  view.setUint32(padded - 8, bitLen >>> 0, true);
  view.setUint32(padded - 4, Math.floor(bitLen / 0x100000000), true);

  let a0 = 0x67452301 | 0;
  let b0 = 0xefcdab89 | 0;
  let c0 = 0x98badcfe | 0;
  let d0 = 0x10325476 | 0;

  const M = new Int32Array(16);
  for (let off = 0; off < padded; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(off + i * 4, true);
    let A = a0;
    let B = b0;
    let C = c0;
    let D = d0;
    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        f = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        f = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      f = (f + A + K[i] + M[g]) | 0;
      A = D;
      D = C;
      C = B;
      B = (B + rotl(f, S[i])) | 0;
    }
    a0 = (a0 + A) | 0;
    b0 = (b0 + B) | 0;
    c0 = (c0 + C) | 0;
    d0 = (d0 + D) | 0;
  }

  return [a0, b0, c0, d0].map(hexLE).join('');
}

/** 32-bit word → little-endian hex (MD5 output order). */
function hexLE(n: number): string {
  let out = '';
  for (let i = 0; i < 4; i++) out += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
  return out;
}
