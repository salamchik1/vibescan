import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { DnsTool } from '../../../components/tools/DnsTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('dns')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Check a domain’s DNS security: DNSSEC validation status and CAA records that restrict which certificate authorities can issue certificates.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <DnsTool />
    </ToolShell>
  );
}
