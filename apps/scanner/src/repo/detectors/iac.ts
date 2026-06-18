import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding } from '@vibescan/findings';
import type { RepoContext } from '../types';

/**
 * Lightweight, dependency-free IaC / container misconfig rules over committed
 * Dockerfiles and docker-compose files. This is the "Variant B" engine — no
 * Trivy/Docker required, so it runs anywhere the rest of the repo scan does
 * (including the Windows home-PC scanner where heavier engines are skipped).
 *
 * Rules, deliberately conservative (see the scoring philosophy — minor hardening
 * gaps must not alarm a client):
 *   • dockerfile_secret      — a real-looking secret baked into ENV/ARG (high)
 *   • compose_privileged     — a service running privileged: true (medium)
 *   • dockerfile_root_user   — final image runs as root (low)
 *   • dockerfile_latest_tag  — base image pinned to :latest / no tag (low)
 *   • compose_exposed_port   — a port published on 0.0.0.0 (low)
 *
 * Each finding carries file:line evidence and never echoes a raw secret value.
 */

/** Cap how many files we read so a pathological repo can't blow the budget. */
const MAX_IAC_FILES = 60;
/** Per-file size cap — IaC files are tiny; anything huge isn't a real one. */
const MAX_IAC_BYTES = 256 * 1024;

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i >= 0 ? p.slice(i + 1) : p;
}

function isVendored(relPath: string): boolean {
  return /(^|\/)(node_modules|vendor|\.venv|venv|site-packages|\.git)\//.test(relPath);
}

/** A file named like a Dockerfile: `Dockerfile`, `Dockerfile.prod`, `app.Dockerfile`, `Containerfile`. */
function isDockerfile(rel: string): boolean {
  const name = basename(rel);
  return /^(Dockerfile|Containerfile)(\.[\w.-]+)?$/i.test(name) || /\.Dockerfile$/i.test(name);
}

/** A docker-compose file: `docker-compose.yml`, `compose.yaml`, `docker-compose.prod.yml`. */
function isComposeFile(rel: string): boolean {
  const name = basename(rel);
  return /^(docker-)?compose(\.[\w.-]+)?\.ya?ml$/i.test(name);
}

/**
 * Entry point: discover committed Dockerfiles / compose files in the cloned
 * tree, read each (bounded), and run the line rules. Pure parsing lives in the
 * exported helpers below so it can be unit-tested without a filesystem.
 */
export async function detectIacMisconfig(ctx: RepoContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  let read = 0;

  for (const rel of ctx.files) {
    if (isVendored(rel)) continue;
    const docker = isDockerfile(rel);
    const compose = !docker && isComposeFile(rel);
    if (!docker && !compose) continue;
    if (read >= MAX_IAC_FILES) break;
    read += 1;

    let text: string;
    try {
      text = await readFile(join(ctx.dir, rel), 'utf8');
    } catch {
      continue;
    }
    if (text.length > MAX_IAC_BYTES) continue;

    findings.push(...(docker ? scanDockerfile(text, rel) : scanComposeFile(text, rel)));
  }

  return findings;
}

// --- Shared secret detection ------------------------------------------------

/** Env var names whose value, if hard-coded, is almost certainly a real secret. */
const SECRET_KEY_RE =
  /(PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|_AUTH|AUTH_)/i;

/**
 * Decide whether a key=value pair is a genuine hard-coded secret. We only flag
 * when the *value* is a concrete literal — references to other variables
 * (`$DB_PASS`, `${DB_PASS}`), empty values, and obvious placeholders are how
 * secrets are SUPPOSED to be handled, so they must never be reported.
 */
function isHardcodedSecret(key: string, rawValue: string): boolean {
  if (!SECRET_KEY_RE.test(key)) return false;
  const value = stripQuotes(rawValue.trim());
  if (!value) return false;
  if (value.includes('$')) return false; // ${VAR} / $VAR passthrough — good practice
  return !isPlaceholder(value);
}

const PLACEHOLDER_RE =
  /^(changeme|change[-_]?me|your[-_].*|my[-_]?secret|placeholder|example|sample|dummy|test|secret|password|passwd|none|null|true|false|xxx+|todo|<.*>|\{\{.*\}\}|\*+)$/i;

function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_RE.test(value);
}

function stripQuotes(v: string): string {
  const m = v.match(/^(['"])([\s\S]*)\1$/);
  return m ? m[2]! : v;
}

/** Mask a secret value so it is never displayed or stored raw. */
function maskValue(value: string): string {
  const v = stripQuotes(value.trim());
  if (v.length <= 4) return '****';
  return `${'*'.repeat(4)}${v.slice(-3)}`;
}

// --- Dockerfile rules -------------------------------------------------------

interface Logical {
  instruction: string; // upper-cased, e.g. FROM, USER, ENV
  args: string;
  line: number; // 1-based line of the instruction start
}

/**
 * Join continuation lines (`\` at EOL) and strip comments/blank lines, yielding
 * one logical instruction per entry with its starting line number.
 */
function logicalInstructions(content: string): Logical[] {
  const lines = content.split(/\r?\n/);
  const out: Logical[] = [];
  let buf = '';
  let startLine = 0;

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i]!;
    const trimmed = line.trim();
    // A comment line only counts as a comment when we're not mid-continuation.
    if (!buf && (trimmed === '' || trimmed.startsWith('#'))) continue;
    if (!buf) startLine = i + 1;

    const continues = /\\\s*$/.test(line);
    line = line.replace(/\\\s*$/, '');
    buf += (buf ? ' ' : '') + line.trim();

    if (continues) continue;

    const m = buf.match(/^(\S+)\s*([\s\S]*)$/);
    if (m) out.push({ instruction: m[1]!.toUpperCase(), args: m[2]!.trim(), line: startLine });
    buf = '';
  }
  if (buf) {
    const m = buf.match(/^(\S+)\s*([\s\S]*)$/);
    if (m) out.push({ instruction: m[1]!.toUpperCase(), args: m[2]!.trim(), line: startLine });
  }
  return out;
}

/** Parse a FROM into its image ref + lower-cased stage alias (if any). */
function parseFrom(args: string): { image: string; alias?: string } {
  // Drop leading flags like --platform=linux/amd64
  const tokens = args.split(/\s+/).filter((t) => !t.startsWith('--'));
  const image = tokens[0] ?? '';
  let alias: string | undefined;
  const asIdx = tokens.findIndex((t) => t.toLowerCase() === 'as');
  if (asIdx >= 0 && tokens[asIdx + 1]) alias = tokens[asIdx + 1]!.toLowerCase();
  return { image, alias };
}

/** True when the FROM image is unpinned (`:latest` or no tag), ignoring digests/stage refs/scratch/args. */
function isUnpinnedImage(image: string, stageNames: Set<string>): boolean {
  if (!image) return false;
  if (image.toLowerCase() === 'scratch') return false;
  if (stageNames.has(image.toLowerCase())) return false; // FROM <previous-stage>
  if (image.includes('$')) return false; // FROM ${BASE} — caller controls the pin
  if (image.includes('@sha256:') || image.includes('@sha512:')) return false; // digest-pinned
  // The tag, if any, lives after the LAST ':' in the final path segment (so a
  // registry host:port like "registry:5000/img" isn't mistaken for a tag).
  const lastSegment = image.slice(image.lastIndexOf('/') + 1);
  const colon = lastSegment.lastIndexOf(':');
  if (colon < 0) return true; // no tag -> implicitly :latest
  return lastSegment.slice(colon + 1).toLowerCase() === 'latest';
}

/** Split an `ENV`/`ARG` argument string into key/value pairs (both `K=V` and `K V` forms). */
function parseEnvArg(instruction: string, args: string): Array<{ key: string; value: string }> {
  const pairs: Array<{ key: string; value: string }> = [];
  if (args.includes('=')) {
    // `ENV A=1 B="two words"` — split on whitespace that isn't inside quotes.
    const tokens = args.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
    for (const tok of tokens) {
      const eq = tok.indexOf('=');
      if (eq <= 0) continue;
      pairs.push({ key: tok.slice(0, eq), value: tok.slice(eq + 1) });
    }
  } else {
    // Legacy `ENV KEY the rest is the value`; `ARG KEY` (no value -> not a literal).
    const sp = args.indexOf(' ');
    if (instruction === 'ENV' && sp > 0) {
      pairs.push({ key: args.slice(0, sp), value: args.slice(sp + 1).trim() });
    }
  }
  return pairs;
}

/** Run the Dockerfile rules over one file's content. Exported for unit tests. */
export function scanDockerfile(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const instructions = logicalInstructions(content);

  const stageNames = new Set<string>();
  const unpinned: Array<{ image: string; line: number }> = [];
  let sawFrom = false;
  let finalStageHasNonRootUser = false;
  let finalStageRootUser = false;
  let lastFromLine = 0;

  for (const ins of instructions) {
    if (ins.instruction === 'FROM') {
      sawFrom = true;
      lastFromLine = ins.line;
      // New stage begins: reset the per-stage USER tracking.
      finalStageHasNonRootUser = false;
      finalStageRootUser = false;
      const { image, alias } = parseFrom(ins.args);
      if (isUnpinnedImage(image, stageNames)) unpinned.push({ image, line: ins.line });
      if (alias) stageNames.add(alias);
    } else if (ins.instruction === 'USER') {
      const user = ins.args.split(/\s+/)[0]?.replace(/['"]/g, '').split(':')[0] ?? '';
      if (user && user.toLowerCase() !== 'root' && user !== '0') {
        finalStageHasNonRootUser = true;
        finalStageRootUser = false;
      } else if (user) {
        finalStageRootUser = true;
        finalStageHasNonRootUser = false;
      }
    } else if (ins.instruction === 'ENV' || ins.instruction === 'ARG') {
      for (const { key, value } of parseEnvArg(ins.instruction, ins.args)) {
        if (isHardcodedSecret(key, value)) {
          findings.push({
            type: 'dockerfile_secret',
            severity: 'high',
            category: 'iac',
            summary: `Hard-coded secret in ${file}:${ins.line} (${ins.instruction} ${key})`,
            evidence: `${ins.instruction} ${key}=${maskValue(value)}`,
            params: { file, line: String(ins.line), key, instruction: ins.instruction },
          });
        }
      }
    }
  }

  // Runs as root when the final stage never drops to a non-root user (or sets it
  // back to root). Only meaningful if the file actually defines an image.
  if (sawFrom && !finalStageHasNonRootUser) {
    findings.push({
      type: 'dockerfile_root_user',
      severity: 'low',
      category: 'iac',
      summary: `${file} runs as root (no non-root USER set)`,
      evidence: finalStageRootUser ? 'final stage sets USER root' : 'no USER instruction in the final stage',
      params: { file, line: String(lastFromLine) },
    });
  }

  if (unpinned.length) {
    const first = unpinned[0]!;
    const more = unpinned.length > 1 ? ` (+${unpinned.length - 1} more)` : '';
    findings.push({
      type: 'dockerfile_latest_tag',
      severity: 'low',
      category: 'iac',
      summary: `Unpinned base image in ${file}:${first.line} — ${first.image}${more}`,
      evidence: `FROM ${first.image}`,
      params: { file, line: String(first.line), image: first.image, count: String(unpinned.length) },
    });
  }

  return findings;
}

// --- docker-compose rules ---------------------------------------------------

/** Run the compose rules over one file's content. Exported for unit tests. */
export function scanComposeFile(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split(/\r?\n/);

  let privilegedReported = false;

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.split('#')[0]!; // drop trailing comments
    const lineNo = i + 1;
    const trimmed = line.trim();
    if (!trimmed) continue;

    // privileged: true  (one finding per file is enough to make the point)
    if (!privilegedReported && /^privileged\s*:\s*(true|yes|on)\s*$/i.test(trimmed)) {
      privilegedReported = true;
      findings.push({
        type: 'compose_privileged',
        severity: 'medium',
        category: 'iac',
        summary: `Privileged container in ${file}:${lineNo}`,
        evidence: 'privileged: true',
        params: { file, line: String(lineNo) },
      });
    }

    // A port published on all interfaces: "0.0.0.0:5432:5432" (quoted or not).
    const portMatch = trimmed.match(/['"]?0\.0\.0\.0:(\d+(?::\d+)?)['"]?/);
    if (portMatch) {
      const mapping = `0.0.0.0:${portMatch[1]}`;
      findings.push({
        type: 'compose_exposed_port',
        severity: 'low',
        category: 'iac',
        summary: `Port published on all interfaces in ${file}:${lineNo} — ${mapping}`,
        evidence: mapping,
        params: { file, line: String(lineNo), mapping },
      });
    }

    // Hard-coded secret in an environment entry, list form ("- KEY=value") or
    // map form ("KEY: value"). The placeholder/var-reference filter keeps the
    // false-positive rate down without a full YAML parse.
    const envPair = parseComposeEnvLine(trimmed);
    if (envPair && isHardcodedSecret(envPair.key, envPair.value)) {
      findings.push({
        type: 'dockerfile_secret',
        severity: 'high',
        category: 'iac',
        summary: `Hard-coded secret in ${file}:${lineNo} (${envPair.key})`,
        evidence: `${envPair.key}=${maskValue(envPair.value)}`,
        params: { file, line: String(lineNo), key: envPair.key, instruction: 'environment' },
      });
    }
  }

  return findings;
}

/** Pull a KEY/value out of a compose environment line, or null if it isn't one. */
function parseComposeEnvLine(trimmed: string): { key: string; value: string } | null {
  // List form: "- KEY=value"
  let m = trimmed.match(/^-\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
  if (m) return { key: m[1]!, value: m[2]! };
  // Map form: "KEY: value" — exclude known structural keys to avoid noise.
  m = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\S.*)$/);
  if (m && !/^(ports|image|build|environment|volumes|networks|depends_on|command|entrypoint|labels|expose)$/i.test(m[1]!)) {
    return { key: m[1]!, value: m[2]! };
  }
  return null;
}
