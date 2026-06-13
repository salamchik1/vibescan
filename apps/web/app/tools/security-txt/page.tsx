import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { SecurityTxtTool } from '../../../components/tools/SecurityTxtTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('security-txt')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Fetch and validate a domain’s /.well-known/security.txt against RFC 9116 — Contact, Expires, signature and recommended fields.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <SecurityTxtTool />
    </ToolShell>
  );
}
