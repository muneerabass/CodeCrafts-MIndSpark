import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import { listMembers } from '@/lib/org-data';
import type { NotificationsResponse } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { NotificationsForm } from './form';

export const metadata = { title: 'Notifications' };

export default async function NotificationsPage() {
  const ctx = await requireOrg();
  const [data, members] = await Promise.all([api<NotificationsResponse>('/settings/notifications'), listMembers(ctx.org.id)]);
  const admins = members.filter((m) => m.role === 'owner' || m.role === 'admin').map((m) => m.email);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Notifications' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Notifications" description="Where depguard tells your team about new risks: Slack, email, a weekly digest, and Jira tickets." />
        <NotificationsForm initial={data} suggested={admins} canEdit={canWrite(ctx.role)} />
      </div>
    </>
  );
}
