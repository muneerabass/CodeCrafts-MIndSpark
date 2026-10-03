import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { PRSettingsResponse } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { PRSettingsForm } from './form';

export const metadata = { title: 'Pull request settings' };

export default async function PRSettingsPage() {
  const { role } = await requireOrg();
  const data = await api<PRSettingsResponse>('/settings/pr');
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Pull Requests' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Pull request reviews" description="What the depguard bot posts on every pull request, the labels it adds and the AI security review." />
        <PRSettingsForm initial={data} canEdit={canWrite(role)} />
      </div>
    </>
  );
}
