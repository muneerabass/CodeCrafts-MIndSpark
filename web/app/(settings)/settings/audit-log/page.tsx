import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { AuditEntry, List } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { AuditTable } from './table';

export const metadata = { title: 'Audit log' };

export default async function AuditLogPage({ searchParams }: { searchParams: SearchParams }) {
  const { role } = await requireOrg();
  const sp = await searchParams;
  const header = <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Audit log' }]} actions={null} />;
  if (!canWrite(role))
    return (
      <>
        {header}
        <p className="p-6 text-sm text-muted-foreground">Only owners and admins can see the audit log.</p>
      </>
    );
  const data = await api<List<AuditEntry>>('/audit-log', { query: listQuery(sp, ['actor', 'action', 'from', 'to'], 50) });
  return (
    <>
      {header}
      <div className="mx-auto w-full max-w-6xl px-6 pt-6">
        <SectionHeader title="Audit log" description="Every change to settings, policy, keys, members and scans, with who made it. Kept for one year." />
      </div>
      <div className="mx-auto w-full max-w-6xl">
        <FilterBar
          filters={[
            { type: 'text', key: 'actor', label: 'Who', placeholder: 'email' },
            { type: 'text', key: 'action', label: 'Action', placeholder: 'policy, member, api-keys…' },
            { type: 'daterange' },
          ]}
        />
        <AuditTable data={data.items} total={data.total} />
      </div>
    </>
  );
}
