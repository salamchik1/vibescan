import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { CspTool } from '../../../components/tools/CspTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('csp')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Paste a Content-Security-Policy and get an A–F grade with a per-directive breakdown of what weakens it — unsafe-inline, unsafe-eval, wildcards and more.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <CspTool />
    </ToolShell>
  );
}
