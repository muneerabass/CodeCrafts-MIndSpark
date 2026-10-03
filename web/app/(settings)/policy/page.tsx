import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { Policy } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { PolicyEditor } from './editor';

export const metadata = { title: 'Policy' };

export default async function PolicyPage() {
  const { role } = await requireOrg();
  const policy = await api<Policy>('/policy');
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Policy' }]}
        info="The policy decides which dependencies are allowed. Every scan evaluates it; matches become policy violations and, in block mode, fail the pull request check."
        actions={null}
      />
      <div className="mx-auto w-full max-w-5xl p-4 md:p-6">
        <SectionHeader title="Policy" description="Rules every scan checks your dependencies against" />
        <PolicyEditor initial={policy} canEdit={canWrite(role)} />
      </div>
    </>
  );
}
