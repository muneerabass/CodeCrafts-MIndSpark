import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { List, Project, ScanRow } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { ScansTable } from './table';

export const metadata = { title: 'Scans' };

export default async function ScansPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const [data, projects] = await Promise.all([
    api<List<ScanRow>>('/scans', { query: listQuery(sp, ['project_id', 'version', 'trigger', 'status', 'from', 'to', 'has_vulns', 'has_violations']) }),
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
  ]);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Scans' }]} info="Each time depguard analysed a project: on pull requests, pushes, manual runs and CLI uploads." actions={null} />
      <FilterBar
        filters={[
          { type: 'select', key: 'project_id', label: 'Projects', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
          { type: 'select', key: 'trigger', label: 'Trigger', options: [{ value: 'pull_request', label: 'Pull request' }, { value: 'push', label: 'Push' }, { value: 'manual', label: 'Manual' }, { value: 'cli', label: 'CLI' }] },
          { type: 'select', key: 'status', label: 'Status', options: [{ value: 'queued', label: 'Queued' }, { value: 'running', label: 'Running' }, { value: 'success', label: 'Success' }, { value: 'failed', label: 'Failed' }] },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      >
        <ScanRepoDialog disabled={!canWrite(role)} />
      </FilterBar>
      <ScansTable data={data.items} total={data.total} />
    </>
  );
}
