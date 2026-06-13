import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { Base64Tool } from '../../../components/tools/Base64Tool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('base64')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Encode and decode base64 (and URL-safe base64) in your browser. UTF-8 safe, with one-click copy and swap. Nothing is sent to a server.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <Base64Tool />
    </ToolShell>
  );
}
