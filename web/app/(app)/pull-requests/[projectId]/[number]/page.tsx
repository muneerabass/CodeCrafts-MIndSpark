import Link from 'next/link';
import { ArrowRight, Bot, Bug, KeyRound, CheckCircle2, ChevronRight, ExternalLink, FileCode2, GitCommitHorizontal, History, ListChecks, MessagesSquare, Scale, ShieldAlert, Skull, Wrench } from 'lucide-react';
import { apiOr404 } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import { fmtDateTime } from '@/lib/format';
import type { PRDetail, PRReviewFinding } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { CopyButton } from '@/components/client';
import { RiskBadge } from '@/components/badges';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { PRLabels, PRStateIcon } from '@/components/pull-requests';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { levelLabel } from '@/lib/pr';
import { cn } from '@/lib/utils';
import { PRActions } from './actions';

export async function generateMetadata({ params }: { params: Promise<{ number: string }> }) {
  return { title: `Pull request #${(await params).number}` };
}

type Tone = { text: string; soft: string; bar: string };
const tone: Record<string, Tone> = {
  critical: { text: 'text-red-600 dark:text-red-400', soft: 'bg-red-500/10 ring-red-500/25', bar: 'bg-red-500' },
  high: { text: 'text-orange-600 dark:text-orange-400', soft: 'bg-orange-500/10 ring-orange-500/25', bar: 'bg-orange-500' },
  medium: { text: 'text-amber-600 dark:text-amber-400', soft: 'bg-amber-500/10 ring-amber-500/25', bar: 'bg-amber-500' },
  low: { text: 'text-sky-600 dark:text-sky-400', soft: 'bg-sky-500/10 ring-sky-500/25', bar: 'bg-sky-500' },
  clean: { text: 'text-emerald-600 dark:text-emerald-400', soft: 'bg-emerald-500/10 ring-emerald-500/25', bar: 'bg-emerald-500' },
  pending: { text: 'text-muted-foreground', soft: 'bg-muted ring-border', bar: 'bg-muted-foreground' },
};
const verdict: Record<string, string> = {
  critical: 'Fix before merging',
  high: 'Fix before merging',
  medium: 'Review before merging',
  low: 'Minor findings',
  clean: 'No issues found',
  pending: 'Review in progress',
};
const stateTone: Record<string, Tone> = { fail: tone.critical, warn: tone.medium, pass: tone.clean };
const stateWord: Record<string, string> = { fail: 'Failed', warn: 'Warnings', pass: 'Passed' };
const CHECKS = [
  ['malware', 'Malware', Skull],
  ['vulnerability', 'Vulnerabilities', Bug],
  ['license', 'Licenses', Scale],
  ['suspicious', 'Suspicious', ShieldAlert],
] as const;
const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
const sevEdge: Record<string, string> = { critical: 'border-l-red-500', high: 'border-l-orange-500', medium: 'border-l-amber-500', low: 'border-l-sky-500' };
const aiStatusText: Record<string, string> = {
  queued: 'AI security review queued',
  running: 'AI security review running',
  skipped: 'AI security review skipped',
  rate_limited: 'AI security review delayed',
  failed: 'AI security review failed',
};
const activityLabel: Record<string, string> = { comment: 'Comment', request_changes: 'Requested changes', rescan: 'Rescan', ai_review: 'AI review re-run', accept_risk: 'Accepted risk' };
const stateBadge: Record<string, string> = {
  open: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
  draft: 'bg-muted text-muted-foreground',
  merged: 'bg-violet-500/15 text-violet-700 dark:text-violet-300',
  closed: 'bg-red-500/15 text-red-700 dark:text-red-300',
};

const md = (s: string) =>
  s
    .replaceAll('`', '')
    .replaceAll('**', '')
    .replace(/\\([_*[\]()#!|~{}\\])/g, '$1');

function Count({ n }: { n: number }) {
  return (
    <span className="ml-1.5 rounded-full bg-muted px-1.5 text-[11px] font-medium tabular-nums text-muted-foreground group-data-[state=active]:bg-primary/15 group-data-[state=active]:text-primary">
      {n}
    </span>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-10 text-center text-sm text-muted-foreground">
      <CheckCircle2 className="size-7 text-emerald-600 dark:text-emerald-400" aria-hidden />
      {children}
    </div>
  );
}

export default async function PullRequestPage({ params }: { params: Promise<{ projectId: string; number: string }> }) {
  const { projectId, number } = await params;
  const { role } = await requireOrg();
  const pr = await apiOr404<PRDetail>(`/projects/${encodeURIComponent(projectId)}/pull-requests/${encodeURIComponent(number)}`);
  const fixes = pr.summary?.fixes ?? [];
  const findings = [...(pr.review?.findings ?? [])].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
  const fileURL = (f: PRReviewFinding) => `https://github.com/${pr.repo_full_name}/blob/${pr.head_sha}/${f.file}${f.line ? `#L${f.line}` : ''}`;
  const open = pr.state === 'open';
  const state = pr.draft && open ? 'draft' : pr.state;
  const t = tone[pr.urgency_level] ?? tone.pending;
  const codeState = findings.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'fail' : findings.length ? 'warn' : 'pass';
  const secrets = findings.filter((f) => f.category === 'secrets');
  const secretState = secrets.some((f) => f.severity === 'critical') ? 'fail' : secrets.length ? 'warn' : 'pass';
  const checks = [
    ...CHECKS.map(([k, label, icon]) => ({ label, icon, st: pr.summary?.checks[k] ?? 'pass' })),
    { label: 'Secrets', icon: KeyRound, st: secretState },
    { label: 'Code review', icon: Bot, st: codeState },
  ];
  const firstTab = fixes.length ? 'fixes' : findings.length ? 'code' : 'history';

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
        {/* Overview */}
        <section className="overflow-hidden rounded-xl border bg-card" aria-label="Overview">
          <div className={cn('h-1', t.bar)} aria-hidden />
          <div className="grid gap-5 p-5 md:grid-cols-[1fr_15rem]">
            <div className="min-w-0 space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                <span className={cn('inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium capitalize', stateBadge[state])}>
                  <PRStateIcon state={pr.state} draft={pr.draft} /> {state}
                </span>
                {pr.project ? (
                  <Link href={`/projects/${pr.project.id}?tab=pull-requests`} className="hover:text-foreground hover:underline">
                    {pr.repo_full_name}
                  </Link>
                ) : (
                  <span>{pr.repo_full_name}</span>
                )}
              </div>
              <h1 className="text-2xl leading-tight font-semibold tracking-tight">
                {pr.title} <span className="font-normal text-muted-foreground">#{pr.number}</span>
              </h1>
              <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                <span className="flex size-6 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary uppercase">{pr.author_login.charAt(0)}</span>
                <span className="font-medium text-foreground">{pr.author_login}</span>
                <span>wants to merge</span>
                <code className="rounded-md bg-muted px-1.5 py-0.5 text-xs">{pr.head_ref}</code>
                <ArrowRight className="size-3.5" aria-label="into" />
                <code className="rounded-md bg-muted px-1.5 py-0.5 text-xs">{pr.base_ref}</code>
              </div>
              <PRLabels labels={pr.labels} max={12} />
            </div>
            <div className={cn('flex flex-col justify-center rounded-xl p-4 ring-1', t.soft)} aria-label="Urgency">
              <span className="text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">Urgency</span>
              <span className="mt-1 flex items-baseline gap-1">
                <span className={cn('text-4xl font-semibold tabular-nums', t.text)}>{pr.urgency_level === 'pending' ? '–' : pr.urgency}</span>
                <span className="text-sm text-muted-foreground">/100</span>
              </span>
              <span className={cn('text-sm font-semibold', t.text)}>
                {levelLabel[pr.urgency_level]} · {verdict[pr.urgency_level]}
              </span>
              <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-background/60">
                <div className={cn('h-full rounded-full', t.bar)} style={{ width: `${Math.max(3, pr.urgency)}%` }} />
              </div>
              {pr.scan?.conclusion === 'failure' && <span className="mt-2 text-xs text-muted-foreground">The depguard check is failing</span>}
            </div>
          </div>
          {pr.reasons.length > 0 && (
            <div className="border-t bg-muted/30 px-5 py-3">
              <h2 className="mb-2 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">Why it ranks here</h2>
              <ol className="grid gap-2 lg:grid-cols-3">
                {pr.reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <span className={cn('mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ring-1', t.soft, t.text)}>{i + 1}</span>
                    <span className="min-w-0">{r.text}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </section>

        {/* Checks */}
        <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6" aria-label="Checks">
          {checks.map((c) => {
            const ct = stateTone[c.st] ?? stateTone.pass;
            return (
              <div key={c.label} className="flex items-center gap-3 rounded-xl border bg-card p-3">
                <span className={cn('flex size-9 shrink-0 items-center justify-center rounded-lg ring-1', ct.soft)}>
                  <c.icon className={cn('size-[18px]', ct.text)} aria-hidden />
                </span>
                <span className="min-w-0">
                  <span className="block truncate text-xs text-muted-foreground">{c.label}</span>
                  <span className={cn('block text-sm font-semibold', ct.text)}>{stateWord[c.st] ?? 'Passed'}</span>
                </span>
              </div>
            );
          })}
        </section>

        <div className="grid gap-5 lg:grid-cols-[1fr_22rem]">
          <Tabs defaultValue={firstTab} className="min-w-0 gap-4">
            <TabsList className="max-w-full justify-start overflow-x-auto [&>button]:shrink-0">
              <TabsTrigger value="fixes" className="group">
                <Wrench /> Fix before merging <Count n={fixes.length} />
              </TabsTrigger>
              <TabsTrigger value="code" className="group">
                <FileCode2 /> Code review <Count n={findings.length} />
              </TabsTrigger>
              <TabsTrigger value="history" className="group">
                <History /> History <Count n={pr.history.length} />
              </TabsTrigger>
            </TabsList>

            <TabsContent value="fixes" className="space-y-3">
              <p className="text-sm text-muted-foreground">
                {pr.summary?.no_changes ? 'No dependency changes in this pull request.' : `${pr.summary?.packages ?? 0} new or changed packages checked.`}{' '}
                {pr.latest_scan_id && (
                  <Link href={`/scans/${pr.latest_scan_id}`} className="text-primary hover:underline">
                    Full scan report →
                  </Link>
                )}
              </p>
              {fixes.length === 0 ? (
                <Empty>No dependency issues to fix.</Empty>
              ) : (
                <ol className="space-y-2.5">
                  {fixes.map((f, i) => (
                    <li key={i} className={cn('rounded-xl border border-l-4 bg-card p-3.5', sevEdge[f.severity] ?? 'border-l-border')}>
                      <div className="flex flex-wrap items-center gap-2">
                        <RiskBadge risk={f.severity} />
                        {f.blocking && <span className="rounded-md bg-red-500/15 px-1.5 py-0.5 text-[11px] font-semibold text-red-700 dark:text-red-300">Blocking</span>}
                        <span className="text-xs text-muted-foreground capitalize">{f.kind}</span>
                      </div>
                      <p className="mt-1.5 text-sm font-medium">{md(f.title)}</p>
                      {f.command && (
                        <div className="mt-2 flex items-center gap-1 rounded-lg border bg-muted/60 py-1 pr-1 pl-3 font-mono text-xs">
                          <span className="text-muted-foreground select-none">$</span>
                          <span className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap">{f.command}</span>
                          <CopyButton value={f.command} />
                        </div>
                      )}
                      {f.note && <p className="mt-1.5 text-xs text-muted-foreground">{md(f.note)}</p>}
                    </li>
                  ))}
                </ol>
              )}
            </TabsContent>

            <TabsContent value="code" className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Rule-based checks{pr.review?.ai_status === 'done' ? ` and an AI security review (${pr.review.ai_model})` : ''}
                {pr.review ? ` · ${pr.review.files_reviewed} files reviewed${pr.review.truncated ? ' (first part of a large diff)' : ''}` : ''}
              </p>
              {pr.review && pr.review.ai_status !== 'done' && (
                <p
                  className={cn(
                    'flex items-start gap-2 rounded-lg border p-2.5 text-xs',
                    pr.review.ai_status === 'rate_limited' || pr.review.ai_status === 'failed' ? 'border-amber-500/30 bg-amber-500/10' : 'bg-muted text-muted-foreground',
                  )}
                >
                  <Bot className="size-4 shrink-0" aria-hidden />
                  <span>
                    <span className="font-medium">{aiStatusText[pr.review.ai_status]}</span>
                    {pr.review.ai_note ? `: ${pr.review.ai_note}.` : '.'} The rule-based review is complete.
                  </span>
                </p>
              )}
              {pr.review?.ai_summary && (
                <p className="rounded-lg border bg-card p-3 text-sm">
                  <span className="font-medium">Summary: </span>
                  {pr.review.ai_summary}
                </p>
              )}
              {findings.length === 0 ? (
                <Empty>No security issues found in the code changes.</Empty>
              ) : (
                <ul className="space-y-2">
                  {findings.map((f, i) => (
                    <li key={i}>
                      <details open={i === 0} className={cn('group/f rounded-xl border border-l-4 bg-card', sevEdge[f.severity] ?? 'border-l-border')}>
                        <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 p-3 [&::-webkit-details-marker]:hidden">
                          <ChevronRight className="size-4 shrink-0 text-muted-foreground transition-transform group-open/f:rotate-90" aria-hidden />
                          <RiskBadge risk={f.severity} />
                          <span className="text-sm font-medium">{f.title}</span>
                          <span className="rounded border px-1.5 py-px text-[11px] text-muted-foreground">{f.source === 'ai' ? 'AI' : 'Rule'}</span>
                          <span className="ml-auto font-mono text-xs text-muted-foreground">
                            {f.file}
                            {f.line ? `:${f.line}` : ''}
                          </span>
                        </summary>
                        <div className="space-y-2 border-t px-3 py-3 pl-9 text-sm">
                          <a href={fileURL(f)} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline">
                            {f.file}
                            {f.line ? `:${f.line}` : ''}
                          </a>
                          {f.category && <span className="ml-2 text-xs text-muted-foreground">{f.category}</span>}
                          {f.explanation && <p className="text-muted-foreground">{f.explanation}</p>}
                          {f.suggestion && (
                            <p className="rounded-lg border-l-2 border-primary bg-primary/5 px-3 py-2 text-xs">
                              <span className="font-semibold">How to fix: </span>
                              {f.suggestion}
                            </p>
                          )}
                        </div>
                      </details>
                    </li>
                  ))}
                </ul>
              )}
            </TabsContent>

            <TabsContent value="history">
              {pr.history.length === 0 ? (
                <p className="text-sm text-muted-foreground">Not scanned yet.</p>
              ) : (
                <ol className="relative space-y-3 border-l pl-5">
                  {pr.history.map((h) => {
                    const word = h.status !== 'success' ? h.status : h.conclusion === 'failure' ? 'Blocked' : h.conclusion === 'neutral' ? 'Warnings' : 'Passed';
                    const ht = h.conclusion === 'failure' ? tone.critical : h.conclusion === 'neutral' ? tone.medium : tone.clean;
                    return (
                      <li key={h.id} className="relative rounded-xl border bg-card p-3">
                        <span className={cn('absolute top-4 -left-[27px] size-3 rounded-full ring-4 ring-background', ht.bar)} aria-hidden />
                        <div className="flex flex-wrap items-center gap-2 text-sm">
                          <GitCommitHorizontal className="size-4 text-muted-foreground" aria-hidden />
                          <code className="text-xs">{h.head_sha.slice(0, 7)}</code>
                          <span className={cn('text-xs font-semibold capitalize', ht.text)}>{word}</span>
                          <span className="text-xs text-muted-foreground">{fmtDateTime(h.created_at)}</span>
                          <Link href={`/scans/${h.id}`} className="ml-auto text-xs font-medium text-primary hover:underline">
                            Report →
                          </Link>
                        </div>
                        <div className="mt-1.5 flex flex-wrap gap-3 text-xs text-muted-foreground">
                          {h.malicious > 0 && <span className="font-medium text-red-600 dark:text-red-400">{h.malicious} malware</span>}
                          <span>{h.vulns} vulnerabilities</span>
                          <span>{h.violations} violations</span>
                        </div>
                      </li>
                    );
                  })}
                </ol>
              )}
            </TabsContent>
          </Tabs>

          <div className="space-y-5">
            <Card className="gap-3 lg:sticky lg:top-16">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <MessagesSquare className="size-4 text-primary" aria-hidden /> Comment &amp; act
                </CardTitle>
                <CardDescription>Posted on GitHub by the depguard app, with your name.</CardDescription>
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
                      <li key={a.id} className="flex gap-3">
                        <span className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full bg-primary/15 text-[11px] font-semibold text-primary uppercase">{a.actor.charAt(0)}</span>
                        <div className="min-w-0 flex-1 space-y-0.5">
                          <div className="flex flex-wrap items-center gap-x-2 text-xs">
                            <span className="font-medium">{activityLabel[a.kind] ?? a.kind}</span>
                            <span
                              className={cn(
                                'rounded px-1 font-medium',
                                a.status === 'failed' ? 'bg-red-500/15 text-red-600' : a.status === 'queued' ? 'bg-amber-500/15 text-amber-600' : 'bg-emerald-500/15 text-emerald-600',
                              )}
                            >
                              {a.status}
                            </span>
                          </div>
                          <div className="truncate text-xs text-muted-foreground">
                            {a.actor} · {fmtDateTime(a.created_at)}
                          </div>
                          {a.body && <p className="line-clamp-3 rounded-lg bg-muted/50 px-2 py-1.5 text-muted-foreground">{a.body}</p>}
                          {a.error && <p className="text-xs text-red-600">{a.error}</p>}
                        </div>
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
