import { api, listQuery, type SearchParams } from '@/lib/api';
import type { List, PackageAnalysis, Project } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { AnalysesTable } from './table';

export const metadata = { title: 'Package Analysis' };

export default async function PackageAnalysisPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const [data, projects] = await Promise.all([
    api<List<PackageAnalysis>>('/package-analyses', { query: listQuery(sp, ['project_id', 'version', 'from', 'to', 'status', 'verified']) }),
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
  ]);
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Package Analysis' }]}
        info="Malware verdicts for packages added by your scans: known-malicious advisories plus heuristic analysis of new packages. Suspicious results stay unverified until an admin reviews them."
        actions={null}
      />
      <FilterBar
        filters={[
          { type: 'select', key: 'project_id', label: 'Project', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
          { type: 'daterange' },
          { type: 'select', key: 'status', label: 'Status', options: [{ value: 'clean', label: 'Clean' }, { value: 'suspicious', label: 'Suspicious' }, { value: 'malicious', label: 'Malicious' }] },
          { type: 'toggle', key: 'verified', label: 'Verification Status' },
        ]}
      />
      <AnalysesTable data={data.items} total={data.total} />
    </>
  );
}
