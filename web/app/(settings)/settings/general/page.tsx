import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { Settings } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { CopyButton } from '@/components/client';
import { Card, CardContent } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { TenantNameForm } from '../client';

export const metadata = { title: 'General settings' };

export default async function GeneralPage() {
  const ctx = await requireOrg();
  const s = await api<Settings>('/settings');
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'General' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Tenant Details" description="Identity of this tenant (organization) in depguard" />
        <Card>
          <CardContent className="grid gap-6">
            <div className="grid gap-2">
              <Label htmlFor="tenant-domain">Tenant</Label>
              <div className="flex items-center gap-1 rounded-md bg-muted pr-1">
                <input id="tenant-domain" readOnly value={s.domain} className="min-w-0 flex-1 bg-transparent px-3 py-2 text-sm text-muted-foreground outline-none" />
                <CopyButton value={s.domain} />
              </div>
            </div>
            <TenantNameForm name={ctx.org.name} canEdit={canWrite(ctx.role)} />
          </CardContent>
        </Card>
      </div>
    </>
  );
}
