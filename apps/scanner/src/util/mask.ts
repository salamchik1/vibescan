/** Mask a secret so we never display or store the raw value. Keeps a short tail for recognizability. */
export function maskSecret(value: string, keepStart = 0, keepEnd = 4): string {
  const v = value.trim();
  if (v.length <= keepStart + keepEnd) return '*'.repeat(Math.max(4, v.length));
  const start = v.slice(0, keepStart);
  const end = v.slice(v.length - keepEnd);
  return `${start}${'*'.repeat(4)}${end}`;
}

/** Mask keeping a known prefix (e.g. "sk_live_") plus the last few chars. */
export function maskWithPrefix(value: string, prefix: string, keepEnd = 4): string {
  const v = value.trim();
  const end = v.slice(Math.max(prefix.length, v.length - keepEnd));
  return `${prefix}${'*'.repeat(4)}${end}`;
}
