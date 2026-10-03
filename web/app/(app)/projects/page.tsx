import { FolderGit2 } from 'lucide-react';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { List, Project } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { ProjectsTable } from './tables';

export const metadata = { title: 'Projects' };

export default async function ProjectsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const data = await api<List<Project>>('/projects', { query: listQuery(sp, ['name', 'source', 'from', 'to', 'has_vulns', 'has_violations']) });
  return (
    <>
      <PageHeader crumbs={[{ label: 'Projects' }]} info="Every repository or CLI project depguard has scanned, with its versions (branches) and current findings." actions={null} />
      <FilterBar
        filters={[
          { type: 'text', key: 'name', label: 'Projects', placeholder: 'Repository name' },
          { type: 'select', key: 'source', label: 'Source', options: [{ value: 'github', label: 'GitHub' }, { value: 'gitlab', label: 'GitLab' }, { value: 'bitbucket', label: 'Bitbucket' }, { value: 'cli', label: 'CLI' }] },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      >
        <ScanRepoDialog disabled={!canWrite(role)} />
      </FilterBar>
      <ProjectsTable
        data={data.items}
        total={data.total}
        empty={
          <EmptyState icon={FolderGit2} title="No projects yet" className="py-8">
            Connect a repository or upload a scan from CI and it will show up here.
          </EmptyState>
        }
      />
    </>
  );
}
