'use client';

import Link from 'next/link';
import { Bot, GitMerge, GitPullRequest, GitPullRequestClosed, GitPullRequestDraft } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { fmtDateTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import { levelLabel } from '@/lib/pr';
import type { PullRequest, UrgencyLevel } from '@/lib/types';

const levelStyle: Record<UrgencyLevel, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-amber-400 text-amber-950',
  low: 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200',
  clean: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200',
  pending: 'bg-muted text-muted-foreground',
};
/** Urgency level with its 0-100 score. */
export function UrgencyPill({ level, score }: { level: UrgencyLevel; score?: number }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold whitespace-nowrap', levelStyle[level])} title="Urgency: how soon this PR should be fixed">
      {levelLabel[level]}
      {score !== undefined && level !== 'clean' && level !== 'pending' && <span className="tabular-nums opacity-80">{score}</span>}
    </span>
  );
}

export function PRStateIcon({ state, draft }: { state: PullRequest['state']; draft: boolean }) {
  if (state === 'merged') return <GitMerge className="size-4 text-violet-600" aria-label="Merged" />;
  if (state === 'closed') return <GitPullRequestClosed className="size-4 text-red-600" aria-label="Closed" />;
  if (draft) return <GitPullRequestDraft className="size-4 text-muted-foreground" aria-label="Draft" />;
  return <GitPullRequest className="size-4 text-emerald-600" aria-label="Open" />;
}

const labelTone = (l: string) =>
  ['malware', 'blocked', 'secrets'].includes(l)
    ? 'border-red-300 text-red-700 dark:border-red-900 dark:text-red-300'
    : ['urgent', 'vulnerable', 'security'].includes(l)
      ? 'border-orange-300 text-orange-700 dark:border-orange-900 dark:text-orange-300'
      : l === 'clean'
        ? 'border-emerald-300 text-emerald-700 dark:border-emerald-900 dark:text-emerald-300'
        : 'text-muted-foreground';

export function PRLabels({ labels, max = 4 }: { labels: string[]; max?: number }) {
  if (!labels.length) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {labels.slice(0, max).map((l) => (
        <span key={l} className={cn('rounded-full border px-1.5 py-px text-[11px] whitespace-nowrap', labelTone(l))}>
          {l}
        </span>
      ))}
      {labels.length > max && <span className="text-[11px] text-muted-foreground">+{labels.length - max}</span>}
    </span>
  );
}

export const prHref = (pr: PullRequest) => (pr.project ? `/pull-requests/${pr.project.id}/${pr.number}` : pr.html_url);

const cols = (showRepo: boolean): ColumnDef<PullRequest, unknown>[] => [
  { header: 'Urgency', cell: ({ row }) => <UrgencyPill level={row.original.urgency_level} score={row.original.urgency} /> },
  {
    header: 'Pull Request',
    cell: ({ row }) => {
      const pr = row.original;
      return (
        <div className="flex min-w-0 items-start gap-2">
          <PRStateIcon state={pr.state} draft={pr.draft} />
          <div className="min-w-0">
            <Link href={prHref(pr)} className="font-medium hover:text-primary hover:underline">
              {pr.title || `#${pr.number}`}
            </Link>
            <div className="text-xs text-muted-foreground">
              {showRepo && <span>{pr.repo_full_name} </span>}#{pr.number} · {pr.author_login || 'unknown'} · {pr.head_ref} → {pr.base_ref}
            </div>
          </div>
        </div>
      );
    },
  },
  {
    header: 'Why',
    cell: ({ row }) => {
      const r = row.original.reasons;
      if (!r.length) return <span className="text-xs text-muted-foreground">{row.original.urgency_level === 'pending' ? 'Review in progress' : 'No issues found'}</span>;
      return (
        <ul className="max-w-md space-y-0.5 text-xs whitespace-normal">
          {r.slice(0, 2).map((x, i) => (
            <li key={i} className="line-clamp-1" title={x.text}>
              {x.text}
            </li>
          ))}
          {r.length > 2 && <li className="text-muted-foreground">+{r.length - 2} more</li>}
        </ul>
      );
    },
  },
  {
    header: 'Findings',
    cell: ({ row }) => {
      const s = row.original.scan;
      const rv = row.original.review;
      return (
        <div className="flex flex-wrap items-center gap-2 text-xs whitespace-nowrap">
          {s ? (
            <>
              {s.malicious > 0 && <span className="font-semibold text-red-700">{s.malicious} malware</span>}
              <span>{s.vulns} vulns</span>
              <span>{s.violations} violations</span>
            </>
          ) : (
            <span className="text-muted-foreground">not scanned</span>
          )}
          {rv && rv.findings > 0 && (
            <span className="inline-flex items-center gap-1">
              <Bot className="size-3.5" aria-hidden />
              {rv.findings} code
            </span>
          )}
        </div>
      );
    },
  },
  { header: 'Labels', cell: ({ row }) => <PRLabels labels={row.original.labels} /> },
  { header: 'Updated', cell: ({ row }) => <span className="whitespace-nowrap text-xs">{fmtDateTime(row.original.gh_updated_at)}</span> },
];

export function PullRequestsTable({ data, total, showRepo = true }: { data: PullRequest[]; total: number; showRepo?: boolean }) {
  return <DataTable columns={cols(showRepo)} data={data} total={total} empty="No pull requests match. Pull requests appear here once the GitHub App is installed on the repository." />;
}
