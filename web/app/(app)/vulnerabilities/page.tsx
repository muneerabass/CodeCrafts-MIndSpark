import { api, listQuery, type SearchParams } from '@/lib/api';
import type { List, VulnerabilityRow } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { VulnerabilitiesTable } from './table';

export const metadata = { title: 'Vulnerabilities' };

export default async function VulnerabilitiesPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const data = await api<List<VulnerabilityRow>>('/vulnerabilities', { query: listQuery(sp, ['risk', 'id', 'from', 'to']) });
  return (
    <>
      <PageHeader crumbs={[{ label: 'Vulnerabilities' }]} info="Known advisories (OSV, GitHub, CVE) that affect at least one component in your projects." actions={null} />
      <FilterBar
        filters={[
          { type: 'select', key: 'risk', label: 'Risk', options: [{ value: 'CRITICAL', label: 'Critical' }, { value: 'HIGH', label: 'High' }, { value: 'MEDIUM', label: 'Medium' }, { value: 'LOW', label: 'Low' }] },
          { type: 'text', key: 'id', label: 'Vulnerability ID', placeholder: 'GHSA-…, CVE-…, MAL-…' },
          { type: 'daterange' },
        ]}
      />
      <VulnerabilitiesTable data={data.items} total={data.total} />
    </>
  );
}
