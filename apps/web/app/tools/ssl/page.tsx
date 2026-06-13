import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { SslTool } from '../../../components/tools/SslTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('ssl')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Check a website’s SSL/TLS certificate: expiry date, issuer, hostname coverage, chain of trust and negotiated TLS protocol — with an A–F grade.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <SslTool />
    </ToolShell>
  );
}
