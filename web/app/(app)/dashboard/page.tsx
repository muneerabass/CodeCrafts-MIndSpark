import Link from 'next/link';
import {
  AlarmClock,
  ArrowRight,
  ArrowUpRight,
  Bug,
  ChartColumnStacked,
  CheckCheck,
  CircleCheck,
  FileChartLine,
  FolderGit2,
  GitFork,
  GitPullRequest,
  Hexagon,
  Info,
  Route,
  Scale,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Sparkles,
  Trophy,
  Zap,
} from 'lucide-react';
import { api, one, type SearchParams } from '@/lib/api';
import { requireOrg } from '@/lib/session';
import type { Dashboard, FixQueue, List, PullRequest } from '@/lib/types';
import { UrgencyPill } from '@/components/pull-requests';
import { PageHeader } from '@/components/page';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { CountUp, RangeSelect, RiskDonut, ScoreGauge, Sparkline, Spotlight, ViolationChecks, ViolationsOverTime, VulnsOverTime } from './charts';

export const metadata = { title: 'Dashboard' };

const n = (v: number) => v.toLocaleString('en-GB');
const plural = (v: number, one: string, many = one + 's') => `${n(v)} ${v === 1 ? one : many}`;
const RED = '#ef4444';
const AMBER = '#f59e0b';
const GREEN = '#10b981';
const VIOLET = 'var(--primary)';

/**
 * Posture score: 100 minus capped penalties, so one category can't hide another.
 * ponytail: fixed weights; make them policy-driven if teams ask to tune them.
 */
function posture(d: Dashboard) {
  const r = d.vulns_by_risk ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const parts = [
    { label: 'Malicious packages', pts: Math.min(40, d.malicious * 20) },
    { label: 'Critical vulnerabilities', pts: Math.min(25, r.critical * 5) },
    { label: 'High vulnerabilities', pts: Math.min(15, r.high * 1.5) },
    { label: 'Past fix deadline', pts: Math.min(10, (d.overdue ?? 0) * 2) },
    { label: 'Policy violations', pts: Math.min(10, d.violations * 0.2) },
  ].map((p) => ({ ...p, pts: Math.round(p.pts) }));
  const score = Math.max(0, 100 - parts.reduce((a, p) => a + p.pts, 0));
  const grade = score >= 85 ? { word: 'Strong', color: GREEN } : score >= 65 ? { word: 'Fair', color: AMBER } : score >= 40 ? { word: 'At risk', color: '#f97316' } : { word: 'Critical', color: RED };
  return { score, parts, ...grade };
}

export default async function DashboardPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const range = ['7d', '30d', '90d'].includes(one(sp.range) ?? '') ? one(sp.range)! : '30d';
  const [{ user }, d, prs, fq] = await Promise.all([
    requireOrg(),
    api<Dashboard>('/dashboard', { query: { range } }),
    api<List<PullRequest>>('/pull-requests', { query: { page_size: 10 } }),
    api<FixQueue>('/fix-queue').catch(() => null),
  ]);
  const attention = prs.items.filter((p) => p.urgency_level !== 'clean' && p.urgency_level !== 'pending').slice(0, 5);
  const p = posture(d);
  const byRisk = d.vulns_by_risk ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const fixes = (fq?.items ?? []).filter((i) => i.fixed_in).slice(0, 3);
  const win = fixes.at(-1)?.share ?? 0;

  // Next actions, most urgent first.
  const actions = [
    d.malicious && { tone: RED, icon: Skull, text: `Remove ${plural(d.malicious, 'malicious package')}`, href: '/package-analysis?status=malicious' },
    d.overdue && { tone: RED, icon: AlarmClock, text: `${plural(d.overdue, 'fix', 'fixes')} past the deadline`, href: '/vulnerabilities?overdue=1' },
    attention.length && { tone: AMBER, icon: GitPullRequest, text: `Review ${plural(attention.length, 'risky pull request')}`, href: '/pull-requests' },
    fixes[0] && { tone: VIOLET, icon: Zap, text: `Upgrade ${fixes[0].name} to ${fixes[0].fixed_in}`, href: '/fix-queue' },
  ].filter(Boolean) as { tone: string; icon: typeof Bug; text: string; href: string }[];

  const vulnSeries = d.vulns_over_time.map((x) => x.critical + x.high + x.medium + x.low);
  const kpis = [
    { label: 'Malicious Packages', value: d.malicious, icon: Skull, href: '/package-analysis?status=malicious', color: d.malicious ? RED : GREEN, note: d.malicious ? 'Remove them before the next build' : 'No known malware', pulse: d.malicious > 0 },
    { label: 'Total Vulnerabilities', value: d.vulnerabilities, icon: Bug, href: '/vulnerabilities', color: d.vulnerabilities ? '#f97316' : GREEN, note: `${n(vulnSeries.reduce((a, b) => a + b, 0))} new in this period`, spark: vulnSeries },
    { label: 'Policy Violations', value: d.violations, icon: FileChartLine, href: '/policy/violations', color: d.violations ? AMBER : GREEN, note: 'Packages that break your policy', spark: d.violations_over_time.map((x) => x.count) },
    { label: 'Suspicious Packages', value: d.suspicious, icon: ShieldAlert, href: '/package-analysis?status=suspicious', color: d.suspicious ? AMBER : GREEN, note: `${plural(d.suspicious_findings ?? 0, 'suspicious finding')}` },
  ];
  const inventory = [
    { label: 'Projects', value: d.projects, icon: FolderGit2, href: '/projects' },
    { label: 'Components', value: d.components, icon: Hexagon, href: '/components' },
    { label: 'Transitive Vulnerabilities', value: d.transitive_vulnerabilities ?? 0, icon: GitFork, href: '/components?direct=false&has_vulns=true', bad: true },
    { label: 'Attack Paths', value: d.attack_paths ?? 0, icon: Route, href: '/projects', bad: true },
    { label: 'Suspicious Findings', value: d.suspicious_findings ?? 0, icon: ScanSearch, href: '/package-analysis?view=suspicious', bad: true },
    { label: 'License Issues', value: d.license_issues ?? 0, icon: Scale, href: '/policy/violations?category=license', bad: true },
  ];
  const onTime = d.fixed?.resolved ? Math.round((d.fixed.on_time / d.fixed.resolved) * 100) : null;
  const topMax = Math.max(1, ...d.top_projects.map((x) => x.vulns));
  const first = user.name.split(' ')[0] || user.name;
  const today = new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' });

  return (
    <>
      <PageHeader crumbs={[{ label: 'Dashboard' }]} />
      <div className="mx-auto w-full max-w-7xl space-y-5 p-4 md:p-8">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <p className="text-xs font-medium tracking-wider text-muted-foreground uppercase">{today}</p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight md:text-3xl">Welcome back, {first}</h1>
            <p className="text-sm text-muted-foreground">Here is where your software supply chain stands right now.</p>
          </div>
          <RangeSelect />
        </div>

        {/* Posture + biggest win */}
        <div className="grid gap-5 lg:grid-cols-12">
          <section aria-label="Security posture" className="relative flex flex-col justify-center overflow-hidden rounded-2xl border bg-card p-5 md:p-6 lg:col-span-8">
            <div aria-hidden className="pointer-events-none absolute -top-24 -left-16 size-72 rounded-full opacity-30 blur-3xl" style={{ background: p.color }} />
            <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(var(--border)_1px,transparent_1px)] [mask-image:linear-gradient(to_bottom,black,transparent)] [background-size:18px_18px] opacity-60" />
            <div className="relative flex flex-col items-center gap-6 sm:flex-row sm:items-center">
              <div className="flex flex-col items-center gap-2">
                <ScoreGauge score={p.score} color={p.color} />
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button type="button" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
                      <Info className="size-3.5" aria-hidden /> How this is scored
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-64">
                    <p className="mb-1 font-medium">100 minus capped penalties</p>
                    <ul className="space-y-0.5">
                      {p.parts.map((x) => (
                        <li key={x.label} className="flex justify-between gap-4">
                          <span>{x.label}</span>
                          <span className="tabular-nums">−{x.pts}</span>
                        </li>
                      ))}
                    </ul>
                  </TooltipContent>
                </Tooltip>
              </div>
              <div className="min-w-0 flex-1 text-center sm:text-left">
                <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold" style={{ color: p.color, background: `color-mix(in oklab, ${p.color} 14%, transparent)` }}>
                  <span className="relative flex size-2">
                    {p.score < 85 && <span className="absolute inline-flex size-full animate-ping rounded-full opacity-60" style={{ background: p.color }} />}
                    <span className="relative inline-flex size-2 rounded-full" style={{ background: p.color }} />
                  </span>
                  Posture: {p.word}
                </span>
                <h2 className="mt-2 text-xl font-semibold tracking-tight">
                  {d.malicious > 0 ? 'Malicious packages in your dependencies' : actions.length ? 'A few things need you' : 'All clear'}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  {plural(d.vulnerabilities, 'vulnerability', 'vulnerabilities')} and {plural(d.violations, 'policy violation')} across {plural(d.projects, 'project')}.
                </p>
                {actions.length > 0 ? (
                  <ul className="mt-4 grid gap-2 sm:grid-cols-2" aria-label="Next actions">
                    {actions.map((a) => (
                      <li key={a.text}>
                        <Link href={a.href} className="group flex items-center gap-2.5 rounded-xl border bg-background/60 px-3 py-2 text-left text-sm backdrop-blur transition-colors hover:border-primary/40 hover:bg-background">
                          <span className="flex size-7 shrink-0 items-center justify-center rounded-lg" style={{ color: a.tone, background: `color-mix(in oklab, ${a.tone} 14%, transparent)` }}>
                            <a.icon className="size-4" aria-hidden />
                          </span>
                          <span className="min-w-0 flex-1 leading-snug">{a.text}</span>
                          <ArrowRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" aria-hidden />
                        </Link>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-4 inline-flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="size-4" aria-hidden /> No malware, deadlines or risky pull requests.
                  </p>
                )}
              </div>
            </div>
          </section>

          <Card className="relative gap-4 overflow-hidden rounded-2xl lg:col-span-4">
            <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-40 bg-gradient-to-b from-primary/15 to-transparent" />
            <CardHeader className="relative">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                <Sparkles className="size-4 text-primary" aria-hidden /> Biggest win
              </CardTitle>
            </CardHeader>
            <CardContent className="relative space-y-4">
              {fixes.length ? (
                <>
                  <div>
                    <div className="text-5xl font-semibold tracking-tight tabular-nums">
                      <CountUp value={Math.round(win)} suffix="%" />
                    </div>
                    <p className="text-sm text-muted-foreground">of open risk removed by {plural(fixes.length, 'upgrade')}</p>
                  </div>
                  <div className="flex h-2 gap-1" aria-hidden>
                    {Array.from({ length: 10 }, (_, i) => (
                      <span key={i} className={cn('flex-1 rounded-full transition-colors', i < Math.round(win / 10) ? 'bg-primary' : 'bg-muted')} />
                    ))}
                  </div>
                  <ol className="space-y-1.5">
                    {fixes.map((f, i) => (
                      <li key={`${f.name}@${f.version}`} className="flex items-center gap-2 text-sm">
                        <span className="flex size-5 shrink-0 items-center justify-center rounded-md bg-primary/10 text-[11px] font-semibold text-primary tabular-nums">{i + 1}</span>
                        <span className="min-w-0 flex-1 truncate font-mono text-[13px]">{f.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {f.version} → <span className="font-medium text-foreground">{f.fixed_in}</span>
                        </span>
                      </li>
                    ))}
                  </ol>
                  <Button asChild size="sm" className="w-full">
                    <Link href="/fix-queue">
                      What to fix first <ArrowRight className="size-3.5" aria-hidden />
                    </Link>
                  </Button>
                </>
              ) : (
                <div className="flex flex-col items-center gap-2 py-6 text-center">
                  <CircleCheck className="size-8 text-emerald-600 dark:text-emerald-400" aria-hidden />
                  <p className="text-sm text-muted-foreground">Nothing with a known fix is waiting.</p>
                  <Link href="/fix-queue" className="text-sm text-primary hover:underline">
                    What to fix first
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* KPIs */}
        <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
          {kpis.map((k) => (
            <Spotlight key={k.label} href={k.href} glow={k.color} className="flex flex-col p-4 sm:p-5">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-medium text-muted-foreground sm:text-sm">{k.label}</span>
                <span className="relative flex size-9 items-center justify-center rounded-xl" style={{ color: k.color, background: `color-mix(in oklab, ${k.color} 13%, transparent)` }}>
                  {k.pulse && <span className="absolute inset-0 animate-ping rounded-xl opacity-30" style={{ background: k.color }} />}
                  <k.icon className="relative size-[18px]" aria-hidden />
                </span>
              </div>
              <div className="mt-2 text-3xl font-semibold tracking-tight tabular-nums sm:text-4xl">
                <CountUp value={k.value} />
              </div>
              {k.spark && (
                <div className="mt-1 -mx-1">
                  <Sparkline data={k.spark} color={k.color} id={k.label.replace(/\W/g, '')} />
                </div>
              )}
              <p className="mt-auto pt-2 text-xs text-muted-foreground">{k.note}</p>
            </Spotlight>
          ))}
        </div>

        {/* Inventory */}
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6" aria-label="Inventory">
          {inventory.map((k) => {
            const hot = k.bad && k.value > 0;
            return (
              <li key={k.label}>
                <Link href={k.href} className="group flex h-full items-center gap-3 rounded-xl border bg-card px-3.5 py-3 transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-sm">
                  <span className={cn('flex size-8 shrink-0 items-center justify-center rounded-lg', hot ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400' : 'bg-primary/10 text-primary')}>
                    <k.icon className="size-4" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <div className="text-lg leading-tight font-semibold tabular-nums">
                      <CountUp value={k.value} />
                    </div>
                    <div className="truncate text-[11px] leading-tight text-muted-foreground" title={k.label}>
                      {k.label}
                    </div>
                  </div>
                </Link>
              </li>
            );
          })}
        </ul>

        {/* Trend + mix */}
        <div className="grid gap-5 lg:grid-cols-12">
          <ChartCard className="lg:col-span-8" icon={ChartColumnStacked} title="Vulnerabilities by Risk" description="New vulnerabilities found each day. Click a level to hide or show it.">
            <VulnsOverTime data={d.vulns_over_time} />
          </ChartCard>
          <Card className="min-w-0 rounded-2xl lg:col-span-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <IconChip icon={Bug} />
                Open by risk
              </CardTitle>
              <CardDescription>Every open vulnerability, by how severe it is</CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <RiskDonut data={byRisk} />
              <div className="grid grid-cols-3 gap-2 border-t pt-4 text-center" aria-label="Fix deadlines">
                <Link href="/vulnerabilities?overdue=1" className="rounded-lg p-1.5 transition-colors hover:bg-muted">
                  <div className={cn('text-xl font-semibold tabular-nums', d.overdue ? 'text-red-600 dark:text-red-400' : '')}>{n(d.overdue ?? 0)}</div>
                  <div className="text-[11px] text-muted-foreground">overdue</div>
                </Link>
                <Link href="/fix-queue" className="rounded-lg p-1.5 transition-colors hover:bg-muted">
                  <div className={cn('text-xl font-semibold tabular-nums', d.due_soon ? 'text-amber-600 dark:text-amber-400' : '')}>{n(d.due_soon ?? 0)}</div>
                  <div className="text-[11px] text-muted-foreground">due this week</div>
                </Link>
                <div className="p-1.5" title={`${d.fixed?.on_time ?? 0} of ${d.fixed?.resolved ?? 0} vulnerabilities fixed in the selected range met their deadline`}>
                  <div className="text-xl font-semibold tabular-nums">{onTime === null ? '–' : `${onTime}%`}</div>
                  <div className="text-[11px] text-muted-foreground">fixed on time</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* PRs + projects */}
        <div className="grid gap-5 lg:grid-cols-12">
          <Card className="min-w-0 rounded-2xl lg:col-span-7">
            <CardHeader>
              <CardTitle className="flex flex-wrap items-center gap-3">
                <IconChip icon={GitPullRequest} />
                Pull requests needing attention
                <Link href="/pull-requests" className="ml-auto inline-flex items-center gap-1 text-sm font-normal text-primary hover:underline">
                  All pull requests <ArrowRight className="size-3.5" aria-hidden />
                </Link>
              </CardTitle>
              <CardDescription>Open pull requests ranked by how urgently they need fixing</CardDescription>
            </CardHeader>
            <CardContent>
              {attention.length === 0 ? (
                <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-10 text-center">
                  <CircleCheck className="size-8 text-emerald-600 dark:text-emerald-400" aria-hidden />
                  <p className="text-sm text-muted-foreground">No open pull request needs attention right now.</p>
                </div>
              ) : (
                <ul className="space-y-2" aria-label="Pull requests needing attention">
                  {attention.map((pr) => (
                    <li key={pr.id}>
                      <Link
                        href={pr.project ? `/pull-requests/${pr.project.id}/${pr.number}` : pr.html_url}
                        className="group relative flex items-start gap-3 overflow-hidden rounded-xl border p-3 transition-colors hover:border-primary/40 hover:bg-muted/40"
                      >
                        <UrgencyPill level={pr.urgency_level} score={pr.urgency} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium group-hover:text-primary">{pr.title}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {pr.repo_full_name} #{pr.number}
                            {pr.author_login && ` · ${pr.author_login}`}
                          </div>
                          {pr.reasons[0] && <div className="mt-1 truncate text-xs text-muted-foreground">{pr.reasons[0].text}</div>}
                        </div>
                        <ArrowUpRight className="mt-1 size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
                        <span aria-hidden className="absolute bottom-0 left-0 h-0.5 bg-gradient-to-r from-red-500 via-orange-500 to-amber-400" style={{ width: `${pr.urgency}%` }} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="min-w-0 rounded-2xl lg:col-span-5">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <IconChip icon={Trophy} />
                Top Vulnerable Projects
              </CardTitle>
              <CardDescription>Projects carrying the most known vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              {d.top_projects.length === 0 ? (
                <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-10 text-center">
                  <ShieldCheck className="size-8 text-emerald-600 dark:text-emerald-400" aria-hidden />
                  <p className="text-sm text-muted-foreground">No project has known vulnerabilities.</p>
                </div>
              ) : (
                <ol className="space-y-3.5">
                  {d.top_projects.slice(0, 6).map((x, i) => (
                    <li key={x.id}>
                      <Link href={`/projects/${x.id}`} className="group block">
                        <div className="mb-1.5 flex items-center gap-2 text-sm">
                          <span className={cn('flex size-5 items-center justify-center rounded-md text-[11px] font-semibold tabular-nums', i === 0 ? 'bg-red-500/15 text-red-600 dark:text-red-400' : 'bg-muted text-muted-foreground')}>{i + 1}</span>
                          <span className="min-w-0 flex-1 truncate font-medium group-hover:text-primary">{x.name}</span>
                          <span className="text-xs text-muted-foreground tabular-nums">{plural(x.vulns, 'vuln')}</span>
                        </div>
                        <div className="ml-7 h-2 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-gradient-to-r from-orange-400 to-red-500 transition-[width] duration-700 group-hover:brightness-110"
                            style={{ width: `${Math.max(4, (x.vulns / topMax) * 100)}%`, opacity: 1 - i * 0.1 }}
                          />
                        </div>
                      </Link>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-5 lg:grid-cols-2">
          <ChartCard icon={FileChartLine} title="Policy Violations Count" description="How many violations your scans found each day">
            <ViolationsOverTime data={d.violations_over_time} />
          </ChartCard>
          <ChartCard icon={CheckCheck} title="Policy Violation Checks" description="Which kinds of rule fail most often. Click a bar to see them.">
            <ViolationChecks data={d.violations_by_check} />
          </ChartCard>
        </div>
      </div>
    </>
  );
}

function IconChip({ icon: Icon }: { icon: typeof Bug }) {
  return (
    <span className="flex size-9 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-primary/20">
      <Icon className="size-[18px] text-primary" aria-hidden />
    </span>
  );
}

function ChartCard({ icon, title, description, className, children }: { icon: typeof Bug; title: string; description: string; className?: string; children: React.ReactNode }) {
  return (
    <Card className={cn('min-w-0 rounded-2xl', className)}>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <IconChip icon={icon} />
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}
