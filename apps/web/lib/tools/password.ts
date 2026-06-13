// Lightweight, dependency-free password strength estimator. It scores entropy
// from the character pool and length, then penalises predictable structure
// (common passwords, repeats, sequences, keyboard runs). Everything runs in the
// browser — the password is never sent anywhere.

export interface PasswordResult {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  entropyBits: number;
  crackTime: string;
  warnings: string[];
  suggestions: string[];
}

const LABELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'] as const;

// A small set of the most-abused passwords; substring matches are caught too.
const COMMON = [
  'password', 'passw0rd', '123456', '12345678', '123456789', 'qwerty', 'abc123', 'letmein',
  'admin', 'welcome', 'monkey', 'dragon', 'iloveyou', 'sunshine', 'princess', 'football',
  'login', 'master', 'hello', 'whatever', 'qazwsx', 'trustno1', 'starwars',
];

const KEYBOARD_RUNS = ['qwerty', 'asdf', 'zxcv', '1234', 'qazwsx', 'qwertz', 'azerty'];

function poolSize(pw: string): number {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33; // printable ASCII symbols
  return pool || 1;
}

function hasSequential(pw: string): boolean {
  const lower = pw.toLowerCase();
  for (let i = 0; i < lower.length - 2; i++) {
    const a = lower.charCodeAt(i);
    const b = lower.charCodeAt(i + 1);
    const c = lower.charCodeAt(i + 2);
    if (b - a === 1 && c - b === 1) return true; // abc / 123
    if (a - b === 1 && b - c === 1) return true; // cba / 321
  }
  return false;
}

function hasRepeats(pw: string): boolean {
  return /(.)\1{2,}/.test(pw); // aaa, 1111
}

/** Roughly translate guesses into human time at 1e10 guesses/sec (offline GPU). */
function crackTimeFromBits(bits: number): string {
  const guesses = Math.pow(2, bits) / 2; // average half the space
  const seconds = guesses / 1e10;
  if (seconds < 1) return 'instantly';
  const units: [number, string][] = [
    [60, 'seconds'],
    [60, 'minutes'],
    [24, 'hours'],
    [365, 'days'],
    [100, 'years'],
  ];
  let value = seconds;
  let label = 'seconds';
  for (const [factor, name] of units) {
    if (value < factor) {
      label = name;
      break;
    }
    value /= factor;
    label = name === 'years' ? 'centuries' : name;
  }
  if (label === 'centuries' && value > 1000) return 'longer than the age of the universe';
  return `~${value < 10 ? value.toFixed(1) : Math.round(value)} ${label}`;
}

export function checkPassword(pw: string): PasswordResult {
  if (!pw) {
    return {
      score: 0,
      label: LABELS[0],
      entropyBits: 0,
      crackTime: '—',
      warnings: [],
      suggestions: ['Start typing to see strength.'],
    };
  }

  const lower = pw.toLowerCase();
  let entropy = pw.length * Math.log2(poolSize(pw));
  const warnings: string[] = [];
  const suggestions: string[] = [];

  const matchedCommon = COMMON.find((c) => lower.includes(c));
  if (matchedCommon) {
    entropy = Math.min(entropy, 12);
    warnings.push(`Contains a very common password ("${matchedCommon}").`);
  }
  if (KEYBOARD_RUNS.some((k) => lower.includes(k))) {
    entropy -= 12;
    warnings.push('Contains a keyboard pattern.');
  }
  if (hasSequential(pw)) {
    entropy -= 8;
    warnings.push('Contains a sequence like "abc" or "123".');
  }
  if (hasRepeats(pw)) {
    entropy -= 8;
    warnings.push('Contains repeated characters like "aaa".');
  }
  // Penalise a small alphabet of distinct characters.
  const distinct = new Set(pw).size;
  if (distinct <= 4 && pw.length > 4) {
    entropy *= 0.6;
    warnings.push('Uses only a few distinct characters.');
  }

  entropy = Math.max(0, Math.round(entropy));

  if (pw.length < 12) suggestions.push('Use at least 12–16 characters (length matters most).');
  if (!/[A-Z]/.test(pw)) suggestions.push('Add uppercase letters.');
  if (!/[0-9]/.test(pw)) suggestions.push('Add numbers.');
  if (!/[^A-Za-z0-9]/.test(pw)) suggestions.push('Add symbols.');
  if (warnings.length === 0 && entropy >= 70) {
    suggestions.push('Looks good — store it in a password manager, never reuse it.');
  }
  if (suggestions.length === 0) {
    suggestions.push('A random passphrase of 4–5 unrelated words is both strong and memorable.');
  }

  let score: PasswordResult['score'];
  if (entropy < 28) score = 0;
  else if (entropy < 40) score = 1;
  else if (entropy < 60) score = 2;
  else if (entropy < 80) score = 3;
  else score = 4;
  if (matchedCommon) score = 0;

  return {
    score,
    label: LABELS[score],
    entropyBits: entropy,
    crackTime: crackTimeFromBits(entropy),
    warnings,
    suggestions,
  };
}
