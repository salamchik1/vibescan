import { execFile } from 'node:child_process';
import { mkdtemp, rm, readdir, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { assertSafeGitUrl } from '../ssrfGuard';
import { config } from '../config';
import type { RepoContext } from './types';

const execFileAsync = promisify(execFile);

/** Thrown when a cloned repo exceeds the configured size/file caps. Message is safe to surface. */
export class RepoLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoLimitError';
  }
}

export interface ClonedRepo {
  ctx: RepoContext;
  /** Remove the temp working tree. Always call this (best-effort, never throws). */
  cleanup: () => Promise<void>;
}

/**
 * Validate, clone (full history, big blobs filtered) and inspect a public Git
 * repository. The clone never prompts for credentials, so a private/redirected
 * URL fails fast instead of hanging. On any error the temp dir is cleaned up
 * before rethrowing; on success the caller owns `cleanup()`.
 */
export async function cloneRepo(repoUrl: string): Promise<ClonedRepo> {
  const { url } = await assertSafeGitUrl(repoUrl); // throws SsrfError on unsafe input
  const dir = await mkdtemp(join(tmpdir(), 'vibescan-repo-'));
  const cleanup = () => rm(dir, { recursive: true, force: true }).catch(() => {});

  try {
    await gitClone(url, dir);
    const ctx = await buildRepoContext(dir, url.toString());
    return { ctx, cleanup };
  } catch (err) {
    await cleanup();
    throw err;
  }
}

/**
 * `git clone` with full commit history (gitleaks needs deleted-then-committed
 * secrets) but partial-clone filtering so giant blobs don't blow the disk/time
 * budget. Credentials are fully disabled so a non-public URL can never hang.
 */
async function gitClone(url: URL, dir: string): Promise<void> {
  const env = {
    ...process.env,
    GIT_TERMINAL_PROMPT: '0', // never prompt on a tty
    GCM_INTERACTIVE: 'never', // no Git Credential Manager popups (Windows)
    GIT_CONFIG_NOSYSTEM: '1', // ignore machine-wide git config
  };

  await execFileAsync(
    'git',
    [
      '-c',
      'credential.helper=', // disable any configured credential helper
      'clone',
      '--filter=blob:limit=10m', // full history, but skip blobs > 10 MB
      '--single-branch', // default branch only
      '--no-tags',
      '--quiet',
      url.toString(),
      dir,
    ],
    { timeout: config.repoCloneTimeoutMs, maxBuffer: 8 * 1024 * 1024, env }
  );
}

/**
 * Walk the working tree (excluding .git, never following symlinks), enforce the
 * size/file caps as we go, and collect relative file paths for the engines.
 */
async function buildRepoContext(dir: string, repoUrl: string): Promise<RepoContext> {
  const files: string[] = [];
  const maxBytes = config.repoMaxSizeMb * 1024 * 1024;
  let totalBytes = 0;
  let fileCount = 0;

  async function walk(abs: string, rel: string): Promise<void> {
    const entries = await readdir(abs, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue; // never follow symlinks (could escape the tree)
      const childAbs = join(abs, entry.name);
      const childRel = rel ? `${rel}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        if (entry.name === '.git') continue; // gitleaks reads .git directly; engines don't walk it
        await walk(childAbs, childRel);
      } else if (entry.isFile()) {
        fileCount += 1;
        if (fileCount > config.repoMaxFiles) {
          throw new RepoLimitError(`Repository has too many files (over ${config.repoMaxFiles}).`);
        }
        const st = await stat(childAbs).catch(() => null);
        if (st) {
          totalBytes += st.size;
          if (totalBytes > maxBytes) {
            throw new RepoLimitError(`Repository is too large (over ${config.repoMaxSizeMb} MB).`);
          }
        }
        files.push(childRel);
      }
    }
  }

  await walk(dir, '');

  return { dir, repoUrl, files, hasGitHistory: true };
}
