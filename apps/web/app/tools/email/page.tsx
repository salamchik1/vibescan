import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { EmailTool } from '../../../components/tools/EmailTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('email')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Check a domain’s email security: SPF, DMARC and MX records, with an A–F grade for how well it’s protected against spoofing and phishing.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <EmailTool />
    </ToolShell>
  );
}
