import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { SecretScannerTool } from '../../../components/tools/SecretScannerTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('secret-scanner')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Paste code, a .env file or any config and find leaked API keys, tokens, private keys and database passwords. Everything runs in your browser — nothing is uploaded.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <SecretScannerTool />
    </ToolShell>
  );
}
