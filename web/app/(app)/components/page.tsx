import { api, listQuery, type SearchParams } from '@/lib/api';
import { DIRECT_OPTIONS, ECOSYSTEMS } from '@/lib/format';
import type { ComponentRow, List } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ComponentsTable } from './table';

export const metadata = { title: 'Components' };

export default async function ComponentsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const data = await api<List<ComponentRow>>('/components', { query: listQuery(sp, ['name', 'version', 'ecosystem', 'from', 'to', 'has_vulns', 'has_violations', 'direct']) });
  return (
    <>
      <PageHeader crumbs={[{ label: 'Components' }]} info="Every open source package found across all projects, one row per name and version." actions={null} />
      <FilterBar
        filters={[
          { type: 'text', key: 'name', label: 'Name', placeholder: 'Package name' },
          { type: 'text', key: 'version', label: 'Version' },
          { type: 'select', key: 'ecosystem', label: 'Ecosystem', options: ECOSYSTEMS },
          { type: 'select', key: 'direct', label: 'Dependency', options: DIRECT_OPTIONS },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      />
      <ComponentsTable data={data.items} total={data.total} />
    </>
  );
}
