import type { Category, Grade, Platform, Severity, VerificationStatus, Verdict } from '@vibescan/findings';

export { PLATFORMS } from '@vibescan/findings';

export const VERIFICATION_META: Record<
  VerificationStatus,
  { label: string; badge: string; note: string }
> = {
  active: {
    label: '✅ Live key — confirmed by provider',
    badge: 'bg-red-500/10 text-red-700 border-red-500/30',
    note: 'We made one read-only call to the provider and the key still works right now.',
  },
  inactive: {
    label: '⚪ Revoked — no longer works',
    badge: 'bg-black/5 text-ink/60 border-ink/15',
    note: 'The provider rejected this key, so it has already been revoked or rotated. Still worth removing from your code.',
  },
  unverified: {
    label: '◌ Could not verify',
    badge: 'bg-amber-500/10 text-amber-700 border-amber-500/30',
    note: "We couldn't reach the provider to confirm — treat it as live until you've rotated it.",
  },
};

export const SEVERITY_META: Record<
  Severity,
  { label: string; emoji: string; badge: string; order: number }
> = {
  critical: { label: 'Critical', emoji: '🔴', badge: 'bg-red-500/10 text-red-700 border-red-500/30', order: 0 },
  high: { label: 'High', emoji: '🔴', badge: 'bg-orange-500/10 text-orange-700 border-orange-500/30', order: 1 },
  medium: { label: 'Medium', emoji: '🟡', badge: 'bg-amber-500/10 text-amber-700 border-amber-500/30', order: 2 },
  low: { label: 'Low', emoji: '🟡', badge: 'bg-yellow-500/10 text-yellow-700 border-yellow-500/30', order: 3 },
  info: { label: 'Info', emoji: '⚪', badge: 'bg-black/5 text-ink/70 border-ink/15', order: 4 },
};

export const VERDICT_META: Record<
  Verdict,
  { label: string; emoji: string; ring: string; text: string; blurb: string }
> = {
  red: {
    label: 'Not secure',
    emoji: '🔴',
    ring: 'ring-red-500/40',
    text: 'text-red-600',
    blurb: 'Critical issues are exposed right now. Fix these before sharing your app.',
  },
  yellow: {
    label: 'Needs attention',
    emoji: '🟡',
    ring: 'ring-amber-400/50',
    text: 'text-amber-600',
    blurb: 'No critical leaks found, but there are things worth fixing.',
  },
  green: {
    label: 'Looks good',
    emoji: '🟢',
    ring: 'ring-emerald-500/40',
    text: 'text-emerald-600',
    blurb: 'No major issues found in the checks we run. Keep monitoring as you ship.',
  },
};

export const CATEGORY_OK: Record<Category, string> = {
  secrets: 'No exposed API keys or secrets found',
  database: 'No openly readable database detected',
  auth: 'No obvious authentication gaps found',
  owasp: 'Basic web hardening looks OK',
};

/** Colours for the A–F grade badges (overall + per category). */
export const GRADE_COLOR: Record<Grade, string> = {
  A: '#34d399',
  B: '#a3e635',
  C: '#fbbf24',
  D: '#fb923c',
  F: '#f87171',
};

export const CATEGORY_LABEL: Record<Category, string> = {
  secrets: 'Secrets',
  database: 'Database',
  auth: 'Auth & access',
  owasp: 'Web hardening',
};

/** Guess the platform from the scanned URL so the fix prompts default sensibly. */
export function detectPlatform(url: string): Platform {
  const u = url.toLowerCase();
  if (u.includes('lovable')) return 'lovable';
  if (u.includes('bolt') || u.includes('stackblitz') || u.includes('webcontainer')) return 'bolt';
  if (u.includes('replit') || u.includes('repl.co') || u.includes('replit.app')) return 'replit';
  if (u.includes('base44')) return 'base44';
  if (u.includes('v0.dev') || u.includes('v0.app') || u.includes('vusercontent')) return 'v0';
  return 'generic';
}
