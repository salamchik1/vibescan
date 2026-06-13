import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { JwtTool } from '../../../components/tools/JwtTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('jwt')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Decode a JWT in your browser and instantly check for alg:none, missing or very long expiry, and sensitive data leaked in the claims.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <JwtTool />
    </ToolShell>
  );
}
