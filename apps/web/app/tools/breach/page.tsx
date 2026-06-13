import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { BreachTool } from '../../../components/tools/BreachTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('breach')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Check whether an email address appears in known data breaches, powered by Have I Been Pwned, and see exactly what was exposed in each.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <BreachTool />
    </ToolShell>
  );
}
