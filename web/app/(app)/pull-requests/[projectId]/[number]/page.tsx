import Link from 'next/link';
import { AlertTriangle, Bot, CheckCircle2, ExternalLink, FileCode2, GitCommitHorizontal, History, ListChecks, MessagesSquare, Wrench } from 'lucide-react';
import { apiOr404 } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import { fmtDateTime } from '@/lib/format';
import type { PRDetail, PRReviewFinding } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { CopyButton } from '@/components/client';
import { RiskBadge } from '@/components/badges';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { PRLabels, PRStateIcon, UrgencyPill } from '@/components/pull-requests';
import { cn } from '@/lib/utils';
import { PRActions } from './actions';

export async function generateMetadata({ params }: { params: Promise<{ number: string }> }) {
  return { title: `Pull request #${(await params).number}` };
}

const banner: Record<string, string> = {
  critical: 'border-red-300 bg-red-50 text-red-950 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100',
  high: 'border-orange-300 bg-orange-50 text-orange-950 dark:border-orange-900 dark:bg-orange-950/40 dark:text-orange-100',
  medium: 'border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100',
  low: 'border-sky-200 bg-sky-50 text-sky-950 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-100',
  clean: 'border-emerald-200 bg-emerald-50 text-emerald-950 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-100',
  pending: 'bg-muted',
};
const verdict: Record<string, string> = {
  critical: 'Fix before merging — critical risk',
  high: 'Fix before merging',
  medium: 'Review before merging',
  low: 'Minor findings',
  clean: 'No issues found',
  pending: 'Review in progress',
};
const CHECKS = [
  ['malware', 'Malware'],
  ['vulnerability', 'Vulnerabilities'],
  ['license', 'Licenses'],
  ['suspicious', 'Suspicious packages'],
] as const;
const checkStyle: Record<string, string> = {
  pass: 'border-emerald-300 text-emerald-700 dark:border-emerald-900 dark:text-emerald-300',
  warn: 'border-amber-300 text-amber-700 dark:border-amber-900 dark:text-amber-300',
  fail: 'border-red-300 text-red-700 dark:border-red-900 dark:text-red-300',
};
const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
const aiStatusText: Record<string, string> = {
  queued: 'AI security review queued.',
  running: 'AI security review running…',
  skipped: 'AI security review skipped',
  rate_limited: 'AI security review delayed',
  failed: 'AI security review failed',
};

const md = (s: string) => s.replaceAll('`', '').replaceAll('**', '').replace(/\\([_*[\]()#!|~{}\\])/g, '$1');

export default async function PullRequestPage({ params }: { params: Promise<{ projectId: string; number: string }> }) {
  const { projectId, number } = await params;
  const { role } = await requireOrg();
  const pr = await apiOr404<PRDetail>(`/projects/${encodeURIComponent(projectId)}/pull-requests/${encodeURIComponent(number)}`);
  const fixes = pr.summary?.fixes ?? [];
  const findings = [...(pr.review?.findings ?? [])].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  const fileURL = (f: PRReviewFinding) => `https://github.com/${pr.repo_full_name}/blob/${pr.head_sha}/${f.file}${f.line ? `#L${f.line}` : ''}`;
  const open = pr.state === 'open';

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Pull Requests', href: '/pull-requests' }, { label: `${pr.repo_full_name} #${pr.number}` }]}
        info="The depguard review of one pull request: dependency changes, code security findings, history and actions."
        actions={
          <Button asChild variant="outline" size="sm">
            <a href={pr.html_url} target="_blank" rel="noreferrer">
              Open on GitHub <ExternalLink />
            </a>
          </Button>
        }
      />
      <div className="mx-auto w-full max-w-6xl space-y-5 p-4 md:p-6">
        <section className="space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <PRStateIcon state={pr.state} draft={pr.draft} />
            <span className="capitalize">{pr.draft && open ? 'draft' : pr.state}</span>
            <span>·</span>
            {pr.project ? (
              <Link href={`/projects/${pr.project.id}?tab=pull-requests`} className="hover:underline">
                {pr.repo_full_name}
              </Link>
            ) : (
              pr.repo_full_name
            )}
            <span>·</span>
            <span>
              {pr.author_login} wants to merge <code className="rounded bg-muted px-1">{pr.head_ref}</code> into <code className="rounded bg-muted px-1">{pr.base_ref}</code>
            </span>
          </div>
          <h1 className="text-2xl font-semibold">
            {pr.title} <span className="font-normal text-muted-foreground">#{pr.number}</span>
          </h1>
          <PRLabels labels={pr.labels} max={12} />
        </section>

        <section className={cn('rounded-xl border p-4', banner[pr.urgency_level])} aria-label="Urgency">
          <div className="flex flex-wrap items-center gap-3">
            <UrgencyPill level={pr.urgency_level} score={pr.urgency} />
            <span className="text-lg font-semibold">{verdict[pr.urgency_level]}</span>
            {pr.scan?.conclusion === 'failure' && <span className="text-sm opacity-80">· the depguard check is failing</span>}
          </div>
          {pr.reasons.length > 0 && (
            <ul className="mt-2 list-disc space-y-0.5 pl-5 text-sm">
              {pr.reasons.map((r, i) => (
                <li key={i}>{r.text}</li>
              ))}
            </ul>
          )}
        </section>

        <div className="grid gap-5 lg:grid-cols-[1fr_22rem]">
          <div className="min-w-0 space-y-5">
            {pr.summary && (
              <div className="flex flex-wrap gap-2" aria-label="Dependency checks">
                {CHECKS.map(([k, label]) => {
                  const st = pr.summary?.checks[k] ?? 'pass';
                  return (
                    <span key={k} className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold uppercase', checkStyle[st] ?? checkStyle.pass)}>
                      {st === 'pass' ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />} {label}
                    </span>
                  );
                })}
                <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold uppercase', findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? checkStyle.fail : findings.length ? checkStyle.warn : checkStyle.pass)}>
                  <Bot className="size-3.5" /> Code review
                </span>
              </div>
            )}

            <Card className="gap-3">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Wrench className="size-4 text-primary" aria-hidden /> Fix before merging
                  <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium tabular-nums text-muted-foreground">{fixes.length}</span>
                </CardTitle>
                <CardDescription>
                  {pr.summary?.no_changes ? 'No dependency changes in this pull request.' : `${pr.summary?.packages ?? 0} new or changed packages checked.`}{' '}
                  {pr.latest_scan_id && (
                    <Link href={`/scans/${pr.latest_scan_id}`} className="text-primary hover:underline">
                      Full scan report →
                    </Link>
                  )}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {fixes.length === 0 ? (
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <CheckCircle2 className="size-4 text-emerald-600" /> No dependency issues to fix.
                  </p>
                ) : (
                  <ol className="space-y-3">
                    {fixes.map((f, i) => (
                      <li key={i} className="flex items-start gap-3 text-sm">
                        <RiskBadge risk={f.severity} />
                        <div className="min-w-0 flex-1">
                          <div className="font-medium">
                            {md(f.title)} {f.blocking && <span className="ml-1 rounded bg-red-100 px-1.5 py-px text-[11px] font-semibold text-red-800 dark:bg-red-950 dark:text-red-200">blocking</span>}
                          </div>
                          {f.command && (
                            <div className="mt-1 flex items-center gap-1 rounded-md bg-muted px-2 py-1 font-mono text-xs">
                              <span className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap">{f.command}</span>
                              <CopyButton value={f.command} />
                            </div>
                          )}
                          {f.note && <p className="mt-1 text-xs text-muted-foreground">{md(f.note)}</p>}
                        </div>
                      </li>
                    ))}
                  </ol>
                )}
              </CardContent>
            </Card>

            <Card className="gap-3">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <FileCode2 className="size-4 text-primary" aria-hidden /> Code security review
                  <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium tabular-nums text-muted-foreground">{findings.length}</span>
                </CardTitle>
                <CardDescription>
                  Rule-based checks on every change{pr.review?.ai_status === 'done' ? ` plus an AI security review (${pr.review.ai_model})` : ''}.
                  {pr.review && ` ${pr.review.files_reviewed} files reviewed${pr.review.truncated ? ' (large diff: the first part was reviewed)' : ''}.`}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {pr.review && pr.review.ai_status !== 'done' && (
                  <p className={cn('rounded-md border p-2 text-xs', pr.review.ai_status === 'rate_limited' || pr.review.ai_status === 'failed' ? 'border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100' : 'bg-muted text-muted-foreground')}>
                    {aiStatusText[pr.review.ai_status]}
                    {pr.review.ai_note ? `: ${pr.review.ai_note}.` : ''} The rule-based review below is complete.
                  </p>
                )}
                {pr.review?.ai_summary && <p className="text-sm">{pr.review.ai_summary}</p>}
                {findings.length === 0 ? (
                  <p className="flex items-center gap-2 text-sm text-muted-foreground">
                    <CheckCircle2 className="size-4 text-emerald-600" /> No security issues found in the code changes.
                  </p>
                ) : (
                  <ul className="divide-y">
                    {findings.map((f, i) => (
                      <li key={i} className="space-y-1 py-3 text-sm">
                        <div className="flex flex-wrap items-center gap-2">
                          <RiskBadge risk={f.severity} />
                          <span className="font-medium">{f.title}</span>
                          <span className="rounded border px-1.5 py-px text-[11px] text-muted-foreground">{f.source === 'ai' ? 'AI' : 'Rule'}</span>
                          {f.category && <span className="text-xs text-muted-foreground">{f.category}</span>}
                        </div>
                        <a href={fileURL(f)} target="_blank" rel="noreferrer" className="inline-block font-mono text-xs text-primary hover:underline">
                          {f.file}
                          {f.line ? `:${f.line}` : ''}
                        </a>
                        {f.explanation && <p className="text-muted-foreground">{f.explanation}</p>}
                        {f.suggestion && (
                          <p className="rounded-md border-l-2 border-primary bg-accent/50 px-2 py-1 text-xs">
                            <span className="font-medium">Fix: </span>
                            {f.suggestion}
                          </p>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>

            <Card className="gap-3">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="size-4 text-primary" aria-hidden /> Review history
                </CardTitle>
              </CardHeader>
              <CardContent>
                {pr.history.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Not scanned yet.</p>
                ) : (
                  <ul className="space-y-2 text-sm">
                    {pr.history.map((h) => (
                      <li key={h.id} className="flex flex-wrap items-center gap-2">
                        <GitCommitHorizontal className="size-4 text-muted-foreground" />
                        <code className="text-xs">{h.head_sha.slice(0, 10)}</code>
                        <span className={cn('text-xs font-medium', h.conclusion === 'failure' ? 'text-red-600' : h.conclusion === 'neutral' ? 'text-amber-600' : 'text-emerald-600')}>
                          {h.status !== 'success' ? h.status : h.conclusion === 'failure' ? 'blocked' : h.conclusion === 'neutral' ? 'warnings' : 'passed'}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {h.malicious > 0 && `${h.malicious} malware · `}
                          {h.vulns} vulns · {h.violations} violations · {fmtDateTime(h.created_at)}
                        </span>
                        <Link href={`/scans/${h.id}`} className="ml-auto text-xs text-primary hover:underline">
                          Report
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="space-y-5">
            <Card className="gap-3 lg:sticky lg:top-16">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <MessagesSquare className="size-4 text-primary" aria-hidden /> Comment &amp; act
                </CardTitle>
                <CardDescription>Posted to the pull request on GitHub by the depguard app, with your name.</CardDescription>
              </CardHeader>
              <CardContent>
                <PRActions projectId={projectId} number={pr.number} canEdit={canWrite(role)} open={open} />
              </CardContent>
            </Card>
            <Card className="gap-3">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ListChecks className="size-4 text-primary" aria-hidden /> Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                {pr.activity.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No actions yet.</p>
                ) : (
                  <ol className="space-y-3 text-sm" aria-label="Activity">
                    {pr.activity.map((a) => (
                      <li key={a.id} className="space-y-0.5">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className="font-medium">{{ comment: 'Comment', request_changes: 'Requested changes', rescan: 'Rescan', ai_review: 'AI review re-run', accept_risk: 'Accepted risk' }[a.kind] ?? a.kind}</span>
                          <span className={cn(a.status === 'failed' ? 'text-red-600' : a.status === 'queued' ? 'text-amber-600' : 'text-emerald-600')}>{a.status}</span>
                          <span className="text-muted-foreground">
                            {a.actor} · {fmtDateTime(a.created_at)}
                          </span>
                        </div>
                        {a.body && <p className="line-clamp-3 text-muted-foreground">{a.body}</p>}
                        {a.error && <p className="text-xs text-red-600">{a.error}</p>}
                      </li>
                    ))}
                  </ol>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </>
  );
}
