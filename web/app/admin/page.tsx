import { inArray, and, eq } from 'drizzle-orm';
import { Building2 } from 'lucide-react';
import { api } from '@/lib/api';
import { db, schema } from '@/lib/db';
import { authBypass } from '@/lib/session';
import type { AdminTenant, List } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { CreateTenantDialog, TenantsTable, type TenantRow } from './tables';

export const metadata = { title: 'Tenants' };

export default async function AdminTenantsPage() {
  const { items } = await api<List<AdminTenant>>('/admin/tenants');
  const ids = items.map((t) => t.tenant_id);

  let rows: TenantRow[] = items.map((t) => ({ ...t, name: t.domain.split('.')[0], created_at: null, owner_invite: null }));
  if (!authBypass && ids.length) {
    const [orgs, invites] = await Promise.all([
      db.select({ id: schema.organization.id, name: schema.organization.name, createdAt: schema.organization.createdAt }).from(schema.organization).where(inArray(schema.organization.id, ids)),
      db
        .select({ orgId: schema.invitation.organizationId, email: schema.invitation.email })
        .from(schema.invitation)
        .where(and(inArray(schema.invitation.organizationId, ids), eq(schema.invitation.role, 'owner'), eq(schema.invitation.status, 'pending'))),
    ]);
    const byId = new Map(orgs.map((o) => [o.id, o]));
    const inviteBy = new Map(invites.map((i) => [i.orgId, i.email]));
    rows = rows.map((r) => {
      const o = byId.get(r.tenant_id);
      return { ...r, name: o?.name ?? r.name, created_at: o?.createdAt.toISOString() ?? null, owner_invite: inviteBy.get(r.tenant_id) ?? null };
    });
  }

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Admin', href: '/admin' }, { label: 'Tenants' }]}
        info="Tenants are organizations. Create one, invite its owner by email, or disable it."
        actions={<CreateTenantDialog suffix={process.env.TENANT_DOMAIN_SUFFIX ?? 'depguard.dev'} />}
      />
      <TenantsTable
        data={rows}
        empty={
          <EmptyState icon={Building2} title="No tenants yet" className="py-8">
            Create the first tenant and invite its owner.
          </EmptyState>
        }
      />
    </>
  );
}
