import Link from 'next/link';
import { SiteHeader } from '../SiteHeader';
import { TOOLS } from '../../lib/tools/registry';

/** Consistent page chrome for an individual tool. */
export function ToolShell({
  icon,
  title,
  blurb,
  slug,
  /**
   * Server-side tools send the target to our server to reach the network, so
   * the "runs in your browser" promise doesn't apply — show an honest note.
   */
  server = false,
  children,
}: {
  icon: string;
  title: string;
  blurb: string;
  /** Current tool slug, so the "more tools" nav can exclude it. */
  slug?: string;
  server?: boolean;
  children: React.ReactNode;
}) {
  const others = TOOLS.filter((t) => t.slug !== slug);

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col px-5 py-10 sm:py-14">
      <SiteHeader active="tools" />

      <Link href="/tools" className="mt-8 inline-flex items-center gap-1 text-sm text-ink/50 hover:text-ink/80">
        ← All tools
      </Link>

      <div className="mt-3 flex items-start gap-3.5">
        <span
          className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-ink/10 bg-white text-2xl"
          aria-hidden
        >
          {icon}
        </span>
        <div>
          <h1 className="text-2xl font-bold text-ink sm:text-3xl">{title}</h1>
          <p className="mt-1.5 max-w-2xl text-ink/60">{blurb}</p>
        </div>
      </div>

      <div className="mt-7 flex-1">{children}</div>

      {server ? (
        <p className="mt-10 flex items-center gap-2 rounded-xl border border-sky-500/20 bg-sky-500/5 px-4 py-3 text-xs text-sky-700/80">
          <span aria-hidden>🌐</span>
          This tool reaches the network from our server to look up the target you enter. We don’t
          store your input or the results.
        </p>
      ) : (
        <p className="mt-10 flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-3 text-xs text-emerald-200/80">
          <span aria-hidden>🔒</span>
          Everything here runs entirely in your browser. Your input is never sent to a server.
        </p>
      )}

      {others.length > 0 && (
        <nav className="mt-8">
          <h2 className="text-xs uppercase tracking-wide text-ink/40">More tools</h2>
          <div className="mt-3 flex flex-wrap gap-2">
            {others.map((t) => (
              <Link
                key={t.slug}
                href={`/tools/${t.slug}`}
                className="flex items-center gap-2 rounded-full border border-ink/10 bg-white px-3 py-1.5 text-sm text-ink/70 transition hover:border-primary/40 hover:text-ink"
              >
                <span aria-hidden>{t.icon}</span>
                {t.title}
              </Link>
            ))}
          </div>
        </nav>
      )}

      <footer className="mt-8 text-center text-xs text-ink/40">
        <Link href="/" className="underline hover:text-ink/70">
          VibeScan
        </Link>{' '}
        free developer &amp; security tools ·{' '}
        <Link href="/terms" className="underline hover:text-ink/70">
          Terms
        </Link>{' '}
        ·{' '}
        <Link href="/privacy" className="underline hover:text-ink/70">
          Privacy
        </Link>
      </footer>
    </main>
  );
}
