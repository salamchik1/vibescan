import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { HashTool } from '../../../components/tools/HashTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('hash')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Generate MD5, SHA-1, SHA-256, SHA-384 and SHA-512 hashes of any text instantly in your browser. Legacy algorithms are clearly flagged.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <HashTool />
    </ToolShell>
  );
}
