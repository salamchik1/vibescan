// Shared input for the repository (source-code) scan engines. The clone step
// produces this; each repo detector consumes it. Analogous to CollectResult for
// the live-URL path, but pointing at a cloned working tree on disk.

export interface RepoContext {
  /** Absolute path to the cloned working tree. */
  dir: string;
  /** Original (display) clone URL, used as the ScanResult label. */
  repoUrl: string;
  /** Relative file paths under `dir` (excludes .git, capped), for lockfile
   *  discovery and scoping. */
  files: string[];
  /** True when the clone retained git history (so gitleaks can scan commits). */
  hasGitHistory: boolean;
}
