/** Low-level byte helpers shared across the browser-side tools. */

/** UTF-8 encode a string to bytes. */
export function toBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/**
 * Narrow a Uint8Array to an ArrayBuffer-backed view that `crypto.subtle.digest`
 * accepts. Recent DOM typings reject the generic `Uint8Array<ArrayBufferLike>`
 * (it might be backed by a SharedArrayBuffer); ours never is.
 */
export function digestInput(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>;
}

/** Lowercase hex string of a byte array. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Standard base64 (with padding) of a byte array. */
export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Decode standard or URL-safe base64 (padding optional) to bytes. */
export function base64ToBytes(input: string): Uint8Array {
  let s = input.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
