import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { SriTool } from '../../../components/tools/SriTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('sri')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Generate Subresource Integrity (SRI) hashes and ready-to-paste script/link tags so the browser can verify third-party scripts and stylesheets.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <SriTool />
    </ToolShell>
  );
}
