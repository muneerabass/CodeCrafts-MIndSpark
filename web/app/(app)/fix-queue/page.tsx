import Link from 'next/link';
import { AlarmClock, CalendarClock, ListOrdered, Target, Wrench } from 'lucide-react';
import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { FixPR, FixQueue, List } from '@/lib/types';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { DueBadge, RiskBadge } from '@/components/badges';
import { EcosystemTile } from '@/components/icons';
import { CopyButton } from '@/components/client';
import { FixButton } from '@/components/fix-button';
import { JiraButton } from '@/components/jira-button';
import { jiraState } from '@/lib/jira';
import { cn } from '@/lib/utils';

export const metadata = { title: 'Fix first' };

const edge: Record<string, string> = { CRITICAL: 'border-l-red-500', HIGH: 'border-l-orange-500', MEDIUM: 'border-l-amber-400', LOW: 'border-l-sky-400' };

export default async function FixQueuePage() {
  const { role } = await requireOrg();
  const [q, fixes] = await Promise.all([api<FixQueue>('/fix-queue'), api<List<FixPR>>('/fixes', { query: { page_size: 50 } })]);
  const edit = canWrite(role);
  const jira = await jiraState(edit);
  const top = q.items.slice(0, 5);
  const topShare = top.length ? top[top.length - 1].share : 0;
  const fixOf = (name: string, version: string, project: string, manifest: string) =>
    fixes.items.find((f) => f.name === name && f.from_version === version && f.project_id === project && f.manifest_path === manifest && f.status !== 'closed');

  const tiles: StatTile[] = [
    { label: 'Packages to fix', value: q.total, icon: ListOrdered, tone: 'primary', href: '/fix-queue' },
    { label: 'Past fix deadline', value: q.summary.overdue, icon: AlarmClock, tone: 'red', href: '/vulnerabilities?overdue=1' },
    { label: 'Due this week', value: q.summary.due_soon, icon: CalendarClock, tone: 'amber', href: '/fix-queue' },
    { label: 'Have a fixed version', value: q.summary.fixable, icon: Wrench, tone: 'sky', href: '/fix-queue' },
  ];

  return (
    <>
      <PageHeader crumbs={[{ label: 'Fix first' }]} info="Every vulnerable package across your projects, ranked by how much risk fixing it removes: severity, number of advisories and projects, and active exploitation." actions={null} />
      <PageIntro title="Fix first" description="One ranked list across all projects. Start at the top: each fix removes the most risk for the least work." />
      <StatTiles label="Fix queue summary" tiles={tiles} />
      <div className="mx-auto w-full max-w-6xl space-y-4 p-4 md:p-6">
        {q.items.length === 0 ? (
          <p className="rounded-xl border bg-card p-8 text-center text-sm text-muted-foreground">No known vulnerabilities in your current dependencies. Nothing to fix.</p>
        ) : (
          <>
            <section aria-label="Biggest wins" className="rounded-xl border bg-gradient-to-r from-primary/10 to-transparent p-5">
              <p className="flex items-center gap-2 text-sm font-medium text-primary">
                <Target className="size-4" aria-hidden /> Biggest wins
              </p>
              <p className="mt-1 text-lg font-semibold">
                {top.length === q.total
                  ? `Fixing these ${q.total} package${q.total === 1 ? '' : 's'} removes all of your known vulnerability risk.`
                  : `Fix the top ${top.length} packages to remove ${topShare}% of your known vulnerability risk.`}
              </p>
              <div className="mt-3 h-2 overflow-hidden rounded-full bg-muted" role="img" aria-label={`${topShare}% of risk`}>
                <div className="h-full rounded-full bg-primary" style={{ width: `${topShare}%` }} />
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                Deadlines: critical {q.sla.critical || '–'} days · high {q.sla.high || '–'} · medium {q.sla.medium || '–'} · low {q.sla.low || '–'}.{' '}
                <Link href="/settings/preferences#deadlines" className="text-primary hover:underline">
                  Change
                </Link>
              </p>
            </section>

            <ol className="space-y-3">
              {q.items.map((it, i) => (
                <li key={`${it.ecosystem}/${it.name}@${it.version}`} className={cn('overflow-hidden rounded-xl border border-l-4 bg-card', edge[it.risk] ?? 'border-l-border')}>
                  <div className="flex flex-wrap items-center gap-3 p-4">
                    <span className="w-6 text-center text-lg font-semibold text-muted-foreground tabular-nums">{i + 1}</span>
                    <EcosystemTile name={it.ecosystem} />
                    <div className="min-w-0 flex-1 basis-48">
                      <p className="flex flex-wrap items-baseline gap-x-2">
                        <span className="font-semibold">{it.name}</span>
                        <span className="font-mono text-sm text-muted-foreground">
                          {it.version} {it.fixed_in && <>→ <span className="text-emerald-600 dark:text-emerald-400">{it.fixed_in}</span></>}
                        </span>
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {it.advisories.length} advisor{it.advisories.length === 1 ? 'y' : 'ies'} · {new Set(it.projects.map((p) => p.id)).size} project
                        {new Set(it.projects.map((p) => p.id)).size === 1 ? '' : 's'}
                        {it.epss != null && ` · ${(it.epss * 100).toFixed(1)}% exploit chance (EPSS)`}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 max-sm:w-full">
                      {it.kev && <span className="rounded-md bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-700 dark:text-red-300">Actively exploited</span>}
                      <RiskBadge risk={it.risk} />
                      <DueBadge due={it.due_at} overdue={it.overdue} />
                      <span className="ml-auto w-24 text-right" title="Share of total risk removed by fixing everything up to this row">
                        <span className="block text-xl leading-none font-semibold tabular-nums">{it.share}%</span>
                        <span className="text-[10px] tracking-wide text-muted-foreground uppercase">risk removed</span>
                      </span>
                    </div>
                  </div>
                  <div className="grid gap-3 border-t bg-muted/30 px-4 py-3 md:grid-cols-[1fr_auto] md:items-start">
                    <div className="space-y-2">
                      <div className="flex flex-wrap gap-1.5">
                        {it.advisories.map((a) => (
                          <Link key={a.id} href={`/vulnerabilities/${encodeURIComponent(a.id)}`} className="rounded-md bg-background px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-border hover:text-primary">
                            {a.id}
                          </Link>
                        ))}
                      </div>
                      {it.command && (
                        <p className="flex items-center gap-1 font-mono text-xs">
                          <span className="text-muted-foreground">$</span> {it.command}
                          <CopyButton value={it.command} />
                        </p>
                      )}
                      <JiraButton refKind="package" refId={`${it.ecosystem}/${it.name}@${it.version}`} link={jira.find('package', `${it.ecosystem}/${it.name}@${it.version}`)} enabled={jira.enabled} />
                    </div>
                    <ul className="space-y-1.5 text-sm" aria-label={`Projects using ${it.name}`}>
                      {it.projects.map((p) => (
                        <li key={p.id + p.manifest_path} className="flex flex-wrap items-center gap-2 md:justify-end">
                          <Link href={`/projects/${p.id}`} className="font-medium hover:text-primary hover:underline">
                            {p.name}
                          </Link>
                          <span className="font-mono text-xs text-muted-foreground">{p.manifest_path}</span>
                          {it.fixed_in && (
                            <FixButton
                              projectId={p.id}
                              pkg={{ ecosystem: it.ecosystem, name: it.name, version: it.version, manifest_path: p.manifest_path }}
                              fix={fixOf(it.name, it.version, p.id, p.manifest_path)}
                              canEdit={edit}
                            />
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
    </>
  );
}
