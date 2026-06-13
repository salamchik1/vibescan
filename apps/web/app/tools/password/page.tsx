import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { PasswordTool } from '../../../components/tools/PasswordTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('password')!;

export const metadata: Metadata = {
  title: `${meta.title} Checker — VibeScan`,
  description:
    'Check password strength in your browser: entropy in bits, estimated crack time, and warnings for common passwords, sequences and repeats. Nothing is transmitted.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug}>
      <PasswordTool />
    </ToolShell>
  );
}
