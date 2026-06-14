import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Report } from '../../../components/Report';
import { SiteHeader } from '../../../components/SiteHeader';
import { getScan } from '../../../lib/scans';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function generateMetadata({
  params,
}: {
  params: Promise<{ id: string }>;
}): Promise<Metadata> {
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan) return { title: 'Report not found — VibeScan' };
  return {
    title: `Security report for ${scan.target} — VibeScan`,
    description: `VibeScan scored ${scan.target} ${scan.result.score}/100. See the full breakdown of leaked keys, open databases and missing auth.`,
    robots: { index: false }, // reports are public-by-link, not for search engines
  };
}

export default async function ReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan) notFound();

  return (
    <main className="mx-auto flex min-h-screen max-w-3xl flex-col items-center px-5 py-12 sm:py-16">
      <SiteHeader active="scan" />

      <section className="mt-10 flex w-full flex-col items-center">
        <Report result={scan.result} shareUrl={`/r/${scan.id}`} />
        <a
          href="/"
          className="mt-8 text-sm text-ink/40 hover:text-ink/70"
        >
          ← Scan another app
        </a>
      </section>

      <footer className="mt-auto w-full pt-16 text-center text-xs text-ink/40">
        VibeScan checks the most common, high-impact issues in vibe-coded apps. It is not a full
        security audit.{' '}
        <a href="/terms" className="underline hover:text-ink/70">
          Terms
        </a>{' '}
        ·{' '}
        <a href="/privacy" className="underline hover:text-ink/70">
          Privacy
        </a>
      </footer>
    </main>
  );
}
