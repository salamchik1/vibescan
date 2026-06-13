import type { Metadata } from 'next';
import Link from 'next/link';
import { SiteHeader } from '../../components/SiteHeader';
import { TOOLS } from '../../lib/tools/registry';

export const metadata: Metadata = {
  title: 'Free Security & Developer Tools — VibeScan',
  description:
    'A free toolkit for vibe-coders: JWT debugger, CSP evaluator, password strength checker, hash & SRI generators, and base64 encoder. Everything runs in your browser.',
};

export default function ToolsIndex() {
  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col px-5 py-10 sm:py-14">
      <SiteHeader active="tools" />

      <section className="mt-12 text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
          <span aria-hidden>⚡</span> Free toolkit · runs in your browser
        </span>
        <h1 className="mt-4 text-3xl font-bold text-white sm:text-4xl">
          Security &amp; developer tools
        </h1>
        <p className="mx-auto mt-3 max-w-xl text-white/60">
          Quick, free tools for checking tokens, policies and hashes. Each one runs entirely in your
          browser — nothing you paste ever leaves your device.
        </p>
        <div className="mt-5 flex flex-wrap justify-center gap-x-6 gap-y-2 text-xs text-white/40">
          <span>✓ No signup</span>
          <span>✓ Nothing stored</span>
          <span>✓ Open the devtools and check</span>
        </div>
      </section>

      <div className="mt-10 grid gap-4 sm:grid-cols-2">
        {TOOLS.map((tool) => (
          <Link
            key={tool.slug}
            href={`/tools/${tool.slug}`}
            className="group flex flex-col rounded-2xl border border-white/10 bg-white/5 p-5 transition hover:-translate-y-0.5 hover:border-primary/40 hover:bg-white/[0.07]"
          >
            <div className="flex items-start gap-3">
              <span
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-black/30 text-2xl transition group-hover:border-primary/40"
                aria-hidden
              >
                {tool.icon}
              </span>
              <div className="min-w-0">
                <h2 className="font-ui font-semibold text-white group-hover:text-primary">
                  {tool.title}
                </h2>
                <p className="mt-1 text-sm leading-relaxed text-white/60">{tool.blurb}</p>
              </div>
            </div>
            <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-white/30 transition group-hover:text-primary">
              Open tool
              <span className="transition group-hover:translate-x-0.5" aria-hidden>
                →
              </span>
            </span>
          </Link>
        ))}
      </div>

      <div className="mt-10 rounded-2xl border border-white/10 bg-white/5 p-5 text-center">
        <p className="text-sm text-white/70">
          Want the full picture? Scan your live app for leaked keys, open databases and missing auth.
        </p>
        <Link
          href="/"
          className="mt-3 inline-block rounded-full bg-primary px-5 py-2.5 font-ui font-semibold text-black transition hover:bg-primary-dark"
        >
          Run a free scan →
        </Link>
      </div>

      <footer className="mt-auto w-full pt-12 text-center text-xs text-white/40">
        <Link href="/terms" className="underline hover:text-white/70">
          Terms
        </Link>{' '}
        ·{' '}
        <Link href="/privacy" className="underline hover:text-white/70">
          Privacy
        </Link>
      </footer>
    </main>
  );
}
