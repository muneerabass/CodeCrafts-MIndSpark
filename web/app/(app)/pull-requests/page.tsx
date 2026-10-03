import Link from 'next/link';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { requireOrg } from '@/lib/session';
import type { List, Project, PRSummaryCounts, PullRequest } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { PullRequestsTable, UrgencyPill } from '@/components/pull-requests';
import { LEVELS, PR_STATE_OPTIONS, levelLabel } from '@/lib/pr';
import { cn } from '@/lib/utils';

export const metadata = { title: 'Pull Requests' };

export default async function PullRequestsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  await requireOrg();
  const [data, summary, projects] = await Promise.all([
    api<List<PullRequest>>('/pull-requests', { query: listQuery(sp, ['state', 'level', 'project_id', 'author', 'q', 'label', 'sort']) }),
    api<PRSummaryCounts>('/pull-requests/summary'),
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
  ]);
  const level = typeof sp.level === 'string' ? sp.level : '';
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Pull Requests' }]}
        info="Every pull request of your connected repositories, reviewed for vulnerable or malicious dependencies, license problems and security issues in the code, ranked by how urgently it needs fixing."
        actions={null}
      />
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3" aria-label="Open pull requests by urgency">
        <span className="mr-1 text-sm text-muted-foreground">
          <span className="font-semibold text-foreground tabular-nums">{summary.open}</span> open
        </span>
        {LEVELS.map((l) => (
          <Link
            key={l}
            href={level === l ? '/pull-requests' : `/pull-requests?level=${l}`}
            aria-current={level === l}
            className={cn('inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-sm hover:bg-muted', level === l && 'ring-2 ring-primary')}
          >
            <UrgencyPill level={l} />
            <span className="font-semibold tabular-nums">{summary.by_level[l] ?? 0}</span>
            <span className="sr-only">{levelLabel[l]} pull requests</span>
          </Link>
        ))}
      </div>
      <FilterBar
        filters={[
          { type: 'select', key: 'state', label: 'State', options: PR_STATE_OPTIONS },
          { type: 'select', key: 'level', label: 'Urgency', options: LEVELS.map((l) => ({ value: l, label: levelLabel[l] })) },
          { type: 'select', key: 'project_id', label: 'Projects', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'author', label: 'Author', placeholder: 'GitHub login' },
          { type: 'text', key: 'q', label: 'Search', placeholder: 'Title, repo or #number' },
          { type: 'select', key: 'sort', label: 'Sort', options: [{ value: 'urgency', label: 'Most urgent' }, { value: 'updated', label: 'Recently updated' }] },
        ]}
      />
      <PullRequestsTable data={data.items} total={data.total} />
    </>
  );
}
