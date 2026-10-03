'use client';

import Link from 'next/link';
import { Bot, Bug, CheckCircle2, ChevronRight, FileChartLine, GitMerge, GitPullRequest, GitPullRequestClosed, GitPullRequestDraft, Skull, TriangleAlert } from 'lucide-react';
import { Pagination } from '@/components/data-table';
import { fmtDate, fmtDateTime } from '@/lib/format';
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

const scoreTile: Record<UrgencyLevel, string> = {
  critical: 'bg-red-500/15 text-red-600 ring-red-500/30 dark:text-red-400',
  high: 'bg-orange-500/15 text-orange-600 ring-orange-500/30 dark:text-orange-400',
  medium: 'bg-amber-500/15 text-amber-700 ring-amber-500/30 dark:text-amber-400',
  low: 'bg-sky-500/15 text-sky-600 ring-sky-500/30 dark:text-sky-400',
  clean: 'bg-emerald-500/15 text-emerald-600 ring-emerald-500/30 dark:text-emerald-400',
  pending: 'bg-muted text-muted-foreground ring-border',
};

/** "3h ago", "2d ago", or the date for older items. */
export function ago(v: string | null | undefined) {
  if (!v) return '';
  const m = Math.round((Date.now() - new Date(v).getTime()) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  if (m < 60 * 24) return `${Math.round(m / 60)}h ago`;
  if (m < 60 * 24 * 30) return `${Math.round(m / 1440)}d ago`;
  return fmtDate(v);
}

function Counter({ icon: Icon, n, label, cls }: { icon: typeof Bug; n: number; label: string; cls?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1 tabular-nums', n ? cls : 'text-muted-foreground/60')} title={`${n} ${label}`}>
      <Icon className="size-3.5" aria-hidden />
      {n}
      <span className="sr-only">{label}</span>
    </span>
  );
}

function PRRow({ pr, showRepo }: { pr: PullRequest; showRepo: boolean }) {
  const s = pr.scan;
  const reason = pr.reasons[0]?.text ?? (pr.urgency_level === 'pending' ? 'Review in progress' : 'No issues found');
  const scored = pr.urgency_level !== 'pending';
  return (
    <li className="group relative flex items-center gap-4 px-4 py-3 transition-colors hover:bg-muted/40">
      <span className={cn('flex size-12 shrink-0 flex-col items-center justify-center rounded-xl ring-1', scoreTile[pr.urgency_level])} title="Urgency: how soon this PR should be fixed">
        <span className="text-base leading-none font-semibold tabular-nums">{scored && pr.urgency_level !== 'clean' ? pr.urgency : pr.urgency_level === 'clean' ? '✓' : '…'}</span>
        <span className="mt-0.5 text-[9px] font-semibold tracking-wide uppercase">{levelLabel[pr.urgency_level]}</span>
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <PRStateIcon state={pr.state} draft={pr.draft} />
          <Link href={prHref(pr)} className="truncate font-medium outline-none after:absolute after:inset-0 group-hover:text-primary focus-visible:after:ring-2 focus-visible:after:ring-ring">
            {pr.title || `#${pr.number}`}
          </Link>
        </div>
        <div className="mt-0.5 flex flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
          {showRepo && <span className="font-medium text-foreground/80">{pr.repo_full_name}</span>}
          <span>#{pr.number}</span>
          <span aria-hidden>·</span>
          <span>{pr.author_login || 'unknown'}</span>
          <span aria-hidden className="hidden sm:inline">
            ·
          </span>
          <code className="hidden rounded bg-muted px-1 text-[11px] sm:inline">{pr.head_ref}</code>
        </div>
        <div className={cn('mt-1 flex items-center gap-1.5 text-xs', pr.reasons.length ? 'text-foreground/80' : 'text-muted-foreground')}>
          {pr.reasons.length ? <TriangleAlert className="size-3.5 shrink-0 text-amber-500" aria-hidden /> : <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" aria-hidden />}
          <span className="truncate" title={reason}>
            {reason}
          </span>
          {pr.reasons.length > 1 && <span className="shrink-0 text-muted-foreground">+{pr.reasons.length - 1}</span>}
        </div>
      </div>
      <div className="hidden shrink-0 flex-col items-end gap-1.5 md:flex">
        {s ? (
          <div className="flex items-center gap-3 text-xs">
            {s.malicious > 0 && <Counter icon={Skull} n={s.malicious} label="malware" cls="font-semibold text-red-600 dark:text-red-400" />}
            <Counter icon={Bug} n={s.vulns} label="vulnerabilities" cls="text-red-600 dark:text-red-400" />
            <Counter icon={FileChartLine} n={s.violations} label="policy violations" cls="text-amber-600 dark:text-amber-400" />
            <Counter icon={Bot} n={pr.review?.findings ?? 0} label="code findings" cls="text-orange-600 dark:text-orange-400" />
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Not scanned yet</span>
        )}
        <PRLabels labels={pr.labels.filter((l) => !l.startsWith('size/'))} max={3} />
      </div>
      <span className="hidden w-16 shrink-0 text-right text-xs text-muted-foreground lg:block" title={fmtDateTime(pr.gh_updated_at)} suppressHydrationWarning>
        {ago(pr.gh_updated_at)}
      </span>
      <ChevronRight className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" aria-hidden />
    </li>
  );
}

export function PullRequestsTable({ data, total, showRepo = true }: { data: PullRequest[]; total: number; showRepo?: boolean }) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1">
        {data.length ? (
          <ul className="divide-y" aria-label="Pull requests">
            {data.map((pr) => (
              <PRRow key={pr.id} pr={pr} showRepo={showRepo} />
            ))}
          </ul>
        ) : (
          <div className="flex flex-col items-center gap-2 px-4 py-16 text-center text-sm text-muted-foreground">
            <GitPullRequest className="size-8" aria-hidden />
            No pull requests match. Pull requests appear here once the GitHub App is installed on the repository.
          </div>
        )}
      </div>
      <Pagination total={total} />
    </div>
  );
}
