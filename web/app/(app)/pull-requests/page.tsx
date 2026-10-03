import Link from 'next/link';
import { api, listQuery, type SearchParams } from '@/lib/api';
import { requireOrg } from '@/lib/session';
import type { List, Project, PRSummaryCounts, PullRequest } from '@/lib/types';
import { PageHeader, PageIntro } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { PullRequestsTable } from '@/components/pull-requests';
import { LEVELS, PR_STATE_OPTIONS, levelLabel } from '@/lib/pr';
import { cn } from '@/lib/utils';

export const metadata = { title: 'Pull Requests' };

const levelBar: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-amber-500',
  low: 'bg-sky-500',
  clean: 'bg-emerald-500',
  pending: 'bg-muted-foreground/40',
};

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
      <PageIntro title="Pull Requests" description="Every pull request of your repositories, most urgent first." />
      <nav className="grid grid-cols-3 gap-2 border-b px-4 pt-2 pb-4 sm:grid-cols-6 md:px-6" aria-label="Open pull requests by urgency">
        {LEVELS.map((l) => (
          <Link
            key={l}
            href={level === l ? '/pull-requests' : `/pull-requests?level=${l}`}
            aria-current={level === l ? 'true' : undefined}
            className={cn('relative overflow-hidden rounded-xl border bg-card p-3 transition-colors hover:border-primary/40', level === l && 'border-primary/60 bg-primary/5')}
          >
            <span className={cn('absolute inset-x-0 top-0 h-0.5', levelBar[l])} aria-hidden />
            <span className="block text-2xl leading-none font-semibold tabular-nums">{summary.by_level[l] ?? 0}</span>
            <span className="mt-1 block text-xs text-muted-foreground">{levelLabel[l]}</span>
            <span className="sr-only">{levelLabel[l]} pull requests</span>
          </Link>
        ))}
      </nav>
      <FilterBar
        filters={[
          { type: 'select', key: 'state', label: 'State', options: PR_STATE_OPTIONS },
          { type: 'select', key: 'level', label: 'Urgency', options: LEVELS.map((l) => ({ value: l, label: levelLabel[l] })) },
          { type: 'select', key: 'project_id', label: 'Projects', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'author', label: 'Author', placeholder: 'GitHub login' },
          { type: 'text', key: 'q', label: 'Search', placeholder: 'Title, repo or #number' },
          {
            type: 'select',
            key: 'sort',
            label: 'Sort',
            options: [
              { value: 'urgency', label: 'Most urgent' },
              { value: 'updated', label: 'Recently updated' },
            ],
          },
        ]}
      />
      <PullRequestsTable data={data.items} total={data.total} />
    </>
  );
}
