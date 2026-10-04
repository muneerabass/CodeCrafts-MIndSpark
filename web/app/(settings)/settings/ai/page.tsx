import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { AssistantSettings } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { AIForm } from './form';

export const metadata = { title: 'AI settings' };

export default async function AIPage() {
  const { role } = await requireOrg();
  const settings = await api<AssistantSettings>('/settings/assistant');
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'AI' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader
          title="Ask depguard"
          description="An assistant in the bottom-right corner of every page that answers questions about your projects, pull requests, vulnerabilities and policies. Coding agents get the same answers over MCP."
        />
        <AIForm initial={settings} canEdit={canWrite(role)} />
      </div>
    </>
  );
}
