import type { Metadata } from 'next';
import { ToolShell } from '../../../components/tools/ToolShell';
import { CorsTool } from '../../../components/tools/CorsTool';
import { toolBySlug } from '../../../lib/tools/registry';

const meta = toolBySlug('cors')!;

export const metadata: Metadata = {
  title: `${meta.title} — VibeScan`,
  description:
    'Test a URL for CORS misconfigurations: arbitrary-origin reflection, the null origin, and Access-Control-Allow-Credentials combinations that let any site read authenticated responses.',
};

export default function Page() {
  return (
    <ToolShell icon={meta.icon} title={meta.title} blurb={meta.blurb} slug={meta.slug} server>
      <CorsTool />
    </ToolShell>
  );
}
