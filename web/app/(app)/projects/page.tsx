import Link from 'next/link';
import { Bug, FileChartLine, FolderGit2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { List, Project } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { ProjectGrid, ProjectsTable, ViewToggle } from './tables';

export const metadata = { title: 'Projects' };

export default async function ProjectsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const { role } = await requireOrg();
  const count = (q: Record<string, string>) => api<List<Project>>('/projects', { query: { ...q, page_size: 1 } }).then((l) => l.total);
  const [data, total, withVulns, withViolations] = await Promise.all([
    api<List<Project>>('/projects', { query: listQuery(sp, ['name', 'source', 'from', 'to', 'has_vulns', 'has_violations']) }),
    count({}),
    count({ has_vulns: 'true' }),
    count({ has_violations: 'true' }),
  ]);
  const tiles = [
    { label: 'Projects', value: total, icon: FolderGit2, href: '/projects', active: !sp.has_vulns && !sp.has_violations, tone: 'text-primary bg-primary/10 ring-primary/25' },
    {
      label: 'With vulnerabilities',
      value: withVulns,
      icon: Bug,
      href: '/projects?has_vulns=true',
      active: sp.has_vulns === 'true',
      tone: 'text-red-600 dark:text-red-400 bg-red-500/10 ring-red-500/25',
    },
    {
      label: 'With policy violations',
      value: withViolations,
      icon: FileChartLine,
      href: '/projects?has_violations=true',
      active: sp.has_violations === 'true',
      tone: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 ring-amber-500/25',
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
      <div className="flex flex-wrap items-end justify-between gap-4 px-4 pt-6 pb-2 md:px-6">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
          <p className="text-sm text-muted-foreground">Every repository depguard watches, with its health and current findings.</p>
        </div>
        <ScanRepoDialog disabled={!canWrite(role)} />
      </div>
      <nav aria-label="Project summary" className="grid grid-cols-3 gap-2 border-b px-4 pt-2 pb-4 sm:gap-3 md:px-6">
        {tiles.map((t) => (
          <Link
            key={t.label}
            href={t.href}
            aria-current={t.active ? 'true' : undefined}
            className={cn('flex items-center gap-3 rounded-xl border bg-card p-2.5 transition-colors hover:border-primary/40 sm:p-3', t.active && 'border-primary/50 bg-primary/5')}
          >
            <span className={cn('hidden size-10 shrink-0 items-center justify-center rounded-lg ring-1 sm:flex', t.tone)}>
              <t.icon className="size-5" aria-hidden />
            </span>
            <span>
              <span className="block text-2xl leading-none font-semibold tabular-nums">{t.value.toLocaleString('en-GB')}</span>
              <span className="mt-1 block text-xs text-muted-foreground">{t.label}</span>
            </span>
            {total > 0 && t.label !== 'Projects' && <span className="ml-auto hidden text-xs text-muted-foreground tabular-nums md:inline">{Math.round((t.value / total) * 100)}%</span>}
          </Link>
        ))}
      </nav>
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
