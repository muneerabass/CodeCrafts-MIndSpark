import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { FixPR, FixSettings, List } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { AutoFixForm } from './form';

export const metadata = { title: 'Auto-fix settings' };

export default async function AutoFixPage() {
  const { role } = await requireOrg();
  const [settings, recent] = await Promise.all([api<FixSettings>('/settings/fixes'), api<List<FixPR>>('/fixes', { query: { page_size: 10 } })]);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Auto-fix' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Auto-fix pull requests" description="depguard opens a pull request that upgrades a vulnerable package to its fixed version. Only the manifest and lockfile change; install scripts never run." />
        <AutoFixForm initial={settings} recent={recent.items} canEdit={canWrite(role)} />
      </div>
    </>
  );
}
