import { api, one, type SearchParams } from '@/lib/api';
import type { AdminInstallation, AdminTenant, List } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { InstallationsTable } from '../tables';

export const metadata = { title: 'GitHub installations' };

export default async function AdminInstallationsPage({ searchParams }: { searchParams: SearchParams }) {
  const status = one((await searchParams).status);
  const [inst, tenants] = await Promise.all([
    api<List<AdminInstallation>>('/admin/installations', { query: { status } }),
    api<List<AdminTenant>>('/admin/tenants'),
  ]);
  const domain = new Map(tenants.items.map((t) => [t.tenant_id, t.domain]));
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Admin', href: '/admin' }, { label: 'GitHub installations' }]}
        info="Installations from organizations that are not linked to a tenant stay pending and are never scanned."
        actions={null}
      />
      <FilterBar filters={[{ type: 'select', key: 'status', label: 'Status', options: [{ value: 'pending', label: 'Pending' }, { value: 'active', label: 'Active' }] }]} />
      <InstallationsTable
        data={inst.items.map((i) => ({ ...i, tenant_domain: i.tenant_id ? domain.get(i.tenant_id) ?? null : null }))}
        tenants={tenants.items.filter((t) => !t.disabled_at).map((t) => ({ id: t.tenant_id, domain: t.domain }))}
      />
    </>
  );
}
