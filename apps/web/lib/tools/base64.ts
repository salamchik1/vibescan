import { toBytes, bytesToBase64, base64ToBytes } from './bytes';

export interface Base64Result {
  ok: boolean;
  output: string;
  error?: string;
}

/** UTF-8 → base64. `urlSafe` swaps +/ for -_ and drops padding. */
export function encodeBase64(input: string, urlSafe = false): Base64Result {
  try {
    let b64 = bytesToBase64(toBytes(input));
    if (urlSafe) b64 = b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { ok: true, output: b64 };
  } catch {
    return { ok: false, output: '', error: 'Could not encode this text.' };
  }
}

/** base64 (standard or URL-safe) → UTF-8 text. */
export function decodeBase64(input: string): Base64Result {
  const cleaned = input.trim();
  if (!cleaned) return { ok: true, output: '' };
  if (/[^A-Za-z0-9+/\-_=\s]/.test(cleaned)) {
    return { ok: false, output: '', error: 'Input contains characters that are not valid base64.' };
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(base64ToBytes(cleaned));
    return { ok: true, output: text };
  } catch {
    return { ok: false, output: '', error: 'This is not valid base64.' };
  }
}
