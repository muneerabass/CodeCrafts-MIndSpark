import { Bug, FileChartLine, FolderGit2 } from 'lucide-react';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { List, Project } from '@/lib/types';
import { EmptyState, PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { ProjectGrid, ProjectsTable, ViewToggle } from './tables';

export const metadata = { title: 'Projects' };

export default async function ProjectsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const count = (q: Record<string, string>) => api<List<Project>>('/projects', { query: { ...q, page_size: 10 } }).then((l) => l.total);
  const [data, total, withVulns, withViolations] = await Promise.all([
    api<List<Project>>('/projects', { query: listQuery(sp, ['name', 'source', 'from', 'to', 'has_vulns', 'has_violations']) }),
    count({}),
    count({ has_vulns: 'true' }),
    count({ has_violations: 'true' }),
  ]);
  const share = (n: number) => (total ? n / total : 0);
  const tiles: StatTile[] = [
    { label: 'Projects', value: total, icon: FolderGit2, href: '/projects', active: !sp.has_vulns && !sp.has_violations, tone: 'primary' },
    { label: 'With vulnerabilities', value: withVulns, icon: Bug, href: '/projects?has_vulns=true', active: sp.has_vulns === 'true', tone: 'red', share: share(withVulns) },
    {
      label: 'With policy violations',
      value: withViolations,
      icon: FileChartLine,
      href: '/projects?has_violations=true',
      active: sp.has_violations === 'true',
      tone: 'amber',
      share: share(withViolations),
    },
  ];
  const empty = (
    <EmptyState icon={FolderGit2} title="No projects yet" className="py-8">
      Connect a repository or upload a scan from CI and it will show up here.
    </EmptyState>
  );
  return (
    <>
      <PageHeader crumbs={[{ label: 'Projects' }]} info="Every repository or CLI project depguard has scanned, with its versions (branches) and current findings." actions={null} />
      <PageIntro title="Projects" description="Every repository depguard watches, with its health and current findings.">
        <ScanRepoDialog disabled={!canWrite(role)} />
      </PageIntro>
      <StatTiles label="Project summary" tiles={tiles} />
      <FilterBar
        filters={[
          { type: 'text', key: 'name', label: 'Projects', placeholder: 'Repository name' },
          {
            type: 'select',
            key: 'source',
            label: 'Source',
            options: [
              { value: 'github', label: 'GitHub' },
              { value: 'gitlab', label: 'GitLab' },
              { value: 'bitbucket', label: 'Bitbucket' },
              { value: 'cli', label: 'CLI' },
              { value: 'container', label: 'Container image' },
            ],
          },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      >
        <ViewToggle />
      </FilterBar>
      {sp.view === 'table' ? <ProjectsTable data={data.items} total={data.total} empty={empty} /> : <ProjectGrid data={data.items} total={data.total} empty={empty} />}
    </>
  );
}
