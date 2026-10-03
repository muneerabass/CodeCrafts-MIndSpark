import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { List, Project, ScanRow } from '@/lib/types';
import { Bug, CircleX, FileChartLine, ScanLine } from 'lucide-react';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { ScansTable } from './table';

export const metadata = { title: 'Scans' };

export default async function ScansPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const count = (q: Record<string, string>) => api<List<ScanRow>>('/scans', { query: { ...q, page_size: 10 } }).then((l) => l.total);
  const [data, projects, total, withVulns, withViolations, failed] = await Promise.all([
    api<List<ScanRow>>('/scans', { query: listQuery(sp, ['project_id', 'version', 'trigger', 'status', 'from', 'to', 'has_vulns', 'has_violations']) }),
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
    count({}),
    count({ has_vulns: 'true' }),
    count({ has_violations: 'true' }),
    count({ status: 'failed' }),
  ]);
  const share = (n: number) => (total ? n / total : 0);
  const tiles: StatTile[] = [
    { label: 'Scans', value: total, icon: ScanLine, href: '/scans', active: !sp.has_vulns && !sp.has_violations && !sp.status, tone: 'primary' },
    { label: 'Found vulnerabilities', value: withVulns, icon: Bug, href: '/scans?has_vulns=true', active: sp.has_vulns === 'true', tone: 'red', share: share(withVulns) },
    {
      label: 'Found policy violations',
      value: withViolations,
      icon: FileChartLine,
      href: '/scans?has_violations=true',
      active: sp.has_violations === 'true',
      tone: 'amber',
      share: share(withViolations),
    },
    { label: 'Failed to run', value: failed, icon: CircleX, href: '/scans?status=failed', active: sp.status === 'failed', tone: 'red', share: share(failed) },
  ];
  return (
    <>
      <PageHeader crumbs={[{ label: 'Scans' }]} info="Each time depguard analysed a project: on pull requests, pushes, manual runs and CLI uploads." actions={null} />
      <PageIntro title="Scans" description="Every analysis depguard ran: pull requests, pushes, manual runs and CLI uploads.">
        <ScanRepoDialog disabled={!canWrite(role)} />
      </PageIntro>
      <StatTiles label="Scan summary" tiles={tiles} />
      <FilterBar
        filters={[
          { type: 'select', key: 'project_id', label: 'Projects', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
          {
            type: 'select',
            key: 'trigger',
            label: 'Trigger',
            options: [
              { value: 'pull_request', label: 'Pull request' },
              { value: 'push', label: 'Push' },
              { value: 'manual', label: 'Manual' },
              { value: 'cli', label: 'CLI' },
            ],
          },
          {
            type: 'select',
            key: 'status',
            label: 'Status',
            options: [
              { value: 'queued', label: 'Queued' },
              { value: 'running', label: 'Running' },
              { value: 'success', label: 'Success' },
              { value: 'failed', label: 'Failed' },
            ],
          },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      />
      <ScansTable data={data.items} total={data.total} />
    </>
  );
}
