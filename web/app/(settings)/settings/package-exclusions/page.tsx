import { Plus } from 'lucide-react';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { Exclusion, List } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ExclusionDialog, ExclusionsTable } from '../client';
import { ECOSYSTEMS } from '@/lib/format';

export const metadata = { title: 'Malicious package exclusions' };

export default async function ExclusionsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const data = await api<List<Exclusion>>('/exclusions', { query: listQuery(sp, ['ecosystem', 'name', 'version', 'status', 'expiry_before'], 10) });
  const can = canWrite(role);
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Malicious Package Exclusion' }]}
        info="Exclusions let Package Analysis skip packages you have reviewed. They never override a package verified as malicious."
        actions={null}
      />
      <div className="mx-auto w-full max-w-6xl p-6">
        <SectionHeader
          title="Malicious Package Exclusions"
          description="Packages that Package Analysis should not flag for this tenant"
          actions={
            can && (
              <ExclusionDialog
                trigger={
                  <Button>
                    <Plus /> Create Exclusion
                  </Button>
                }
              />
            )
          }
        />
        <Card className="gap-0 overflow-hidden py-0">
          <FilterBar
            filters={[
              { type: 'select', key: 'ecosystem', label: 'Ecosystem', options: ECOSYSTEMS },
              { type: 'text', key: 'name', label: 'Package Name' },
              { type: 'text', key: 'version', label: 'Version' },
              { type: 'select', key: 'status', label: 'Status', options: [{ value: 'active', label: 'Active' }, { value: 'expired', label: 'Expired' }] },
              { type: 'date', key: 'expiry_before', label: 'Expiry Date' },
            ]}
          />
          <ExclusionsTable data={data.items} total={data.total} canEdit={can} />
        </Card>
      </div>
    </>
  );
}
