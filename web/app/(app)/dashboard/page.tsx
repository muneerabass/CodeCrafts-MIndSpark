import Link from 'next/link';
import {
  ArrowRight,
  Bug,
  ChartColumnStacked,
  CheckCheck,
  CircleCheck,
  FileChartLine,
  FolderGit2,
  GitFork,
  GitPullRequest,
  Hexagon,
  Route,
  Scale,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Trophy,
  TriangleAlert,
} from 'lucide-react';
import { api, one, type SearchParams } from '@/lib/api';
import { requireOrg } from '@/lib/session';
import type { Dashboard, List, PullRequest } from '@/lib/types';
import { UrgencyPill } from '@/components/pull-requests';
import { PageHeader } from '@/components/page';
import { Logo } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { RangeSelect, ViolationChecks, ViolationsOverTime, VulnsOverTime } from './charts';

export const metadata = { title: 'Dashboard' };

type Tone = 'red' | 'amber' | 'green' | 'primary';
const tones: Record<Tone, { icon: string; chip: string; bar: string }> = {
  red: { icon: 'text-red-600 dark:text-red-400', chip: 'bg-red-500/10 ring-red-500/25', bar: 'bg-red-500' },
  amber: { icon: 'text-amber-600 dark:text-amber-400', chip: 'bg-amber-500/10 ring-amber-500/25', bar: 'bg-amber-500' },
  green: { icon: 'text-emerald-600 dark:text-emerald-400', chip: 'bg-emerald-500/10 ring-emerald-500/25', bar: 'bg-emerald-500' },
  primary: { icon: 'text-primary', chip: 'bg-primary/10 ring-primary/25', bar: 'bg-primary' },
};

const n = (v: number) => v.toLocaleString('en-GB');
const plural = (v: number, one: string, many = one + 's') => `${n(v)} ${v === 1 ? one : many}`;

export default async function DashboardPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const range = ['7d', '30d', '90d'].includes(one(sp.range) ?? '') ? one(sp.range)! : '30d';
  const [{ user }, d, prs] = await Promise.all([requireOrg(), api<Dashboard>('/dashboard', { query: { range } }), api<List<PullRequest>>('/pull-requests', { query: { page_size: 10 } })]);
  const attention = prs.items.filter((p) => p.urgency_level !== 'clean' && p.urgency_level !== 'pending').slice(0, 5);

  // A zero turns a risk tile green.
  const risk = (v: number, t: Tone): Tone => (v ? t : 'green');
  const primary = [
    {
      label: 'Malicious Packages',
      value: d.malicious,
      icon: Skull,
      href: '/package-analysis?status=malicious',
      tone: risk(d.malicious, 'red'),
      note: d.malicious ? 'Remove them before the next build' : 'No known malware',
    },
    {
      label: 'Total Vulnerabilities',
      value: d.vulnerabilities,
      icon: Bug,
      href: '/vulnerabilities',
      tone: risk(d.vulnerabilities, 'red'),
      note: `${n(d.transitive_vulnerabilities ?? 0)} in transitive dependencies`,
    },
    { label: 'Policy Violations', value: d.violations, icon: FileChartLine, href: '/policy/violations', tone: risk(d.violations, 'amber'), note: 'Packages that break your policy' },
    {
      label: 'Suspicious Packages',
      value: d.suspicious,
      icon: ShieldAlert,
      href: '/package-analysis?status=suspicious',
      tone: risk(d.suspicious, 'amber'),
      note: 'Typosquats, install scripts, unusual code',
    },
  ];
  const inventory = [
    { label: 'Projects', value: d.projects, icon: FolderGit2, href: '/projects', tone: 'primary' as Tone },
    { label: 'Components', value: d.components, icon: Hexagon, href: '/components', tone: 'primary' as Tone },
    {
      label: 'Transitive Vulnerabilities',
      value: d.transitive_vulnerabilities ?? 0,
      icon: GitFork,
      href: '/components?direct=false&has_vulns=true',
      tone: risk(d.transitive_vulnerabilities ?? 0, 'red'),
    },
    { label: 'Attack Paths', value: d.attack_paths ?? 0, icon: Route, href: '/projects', tone: risk(d.attack_paths ?? 0, 'red') },
    { label: 'Suspicious Findings', value: d.suspicious_findings ?? 0, icon: ScanSearch, href: '/package-analysis?view=suspicious', tone: risk(d.suspicious_findings ?? 0, 'amber') },
    { label: 'License Issues', value: d.license_issues ?? 0, icon: Scale, href: '/policy/violations?category=license', tone: risk(d.license_issues ?? 0, 'amber') },
  ];

  const posture =
    d.malicious > 0
      ? {
          tone: 'red' as Tone,
          icon: Skull,
          title: 'Malicious packages in your dependencies',
          text: `${plural(d.malicious, 'malicious package')} found. Remove them and rotate any credentials they could reach.`,
          cta: { label: 'Review malicious packages', href: '/package-analysis?status=malicious' },
        }
      : d.vulnerabilities > 0 || d.violations > 0
        ? {
            tone: 'amber' as Tone,
            icon: TriangleAlert,
            title: 'Action needed',
            text: `${plural(d.vulnerabilities, 'vulnerability', 'vulnerabilities')} and ${plural(d.violations, 'policy violation')} across ${plural(d.projects, 'project')}.`,
            cta: { label: 'Review vulnerabilities', href: '/vulnerabilities' },
          }
        : {
            tone: 'green' as Tone,
            icon: ShieldCheck,
            title: 'All clear',
            text: `No known malware, vulnerabilities or policy violations across ${plural(d.projects, 'project')}.`,
            cta: { label: 'View projects', href: '/projects' },
          };
  const pt = tones[posture.tone];
  const topMax = Math.max(1, ...d.top_projects.map((p) => p.vulns));

  return (
    <>
      <PageHeader crumbs={[{ label: 'Dashboard' }]} />
      <div className="mx-auto w-full max-w-7xl space-y-6 p-4 md:p-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <Logo className="size-11 shrink-0" />
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Welcome back, {user.name.split(' ')[0] || user.name}</h1>
              <p className="text-sm text-muted-foreground">Here is where your software supply chain stands right now.</p>
            </div>
          </div>
          <RangeSelect />
        </div>

        {/* Posture */}
        <section aria-label="Security posture" className={cn('relative overflow-hidden rounded-xl border bg-card p-5 ring-1 ring-inset md:p-6', pt.chip)}>
          <div className={cn('absolute inset-y-0 left-0 w-1', pt.bar)} aria-hidden />
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
            <div className="flex min-w-0 flex-1 items-start gap-4 sm:items-center">
              <span className={cn('flex size-12 shrink-0 items-center justify-center rounded-xl bg-background ring-1', pt.chip)}>
                <posture.icon className={cn('size-6', pt.icon)} aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="text-lg font-semibold">{posture.title}</h2>
                <p className="text-sm text-muted-foreground">
                  {posture.text}
                  {attention.length > 0 && ` ${plural(attention.length, 'open pull request')} ${attention.length === 1 ? 'needs' : 'need'} attention.`}
                </p>
              </div>
            </div>
            <Button asChild variant="outline" className="self-start bg-background sm:self-auto">
              <Link href={posture.cta.href}>
                {posture.cta.label} <ArrowRight className="size-4" aria-hidden />
              </Link>
            </Button>
          </div>
        </section>

        {/* Risk */}
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {primary.map((k) => {
            const t = tones[k.tone];
            return (
              <Link key={k.label} href={k.href} className="group rounded-xl focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
                <Card className="relative h-full gap-3 overflow-hidden py-5 transition-all group-hover:-translate-y-0.5 group-hover:border-primary/40 group-hover:shadow-md">
                  <div className={cn('absolute inset-x-0 top-0 h-0.5', t.bar)} aria-hidden />
                  <CardHeader className="px-5">
                    <CardTitle className="flex items-center justify-between gap-3 text-sm font-medium text-muted-foreground">
                      {k.label}
                      <span className={cn('flex size-9 items-center justify-center rounded-lg ring-1', t.chip)}>
                        <k.icon className={cn('size-[18px]', t.icon)} aria-hidden />
                      </span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1 px-5">
                    <div className="text-4xl font-semibold tracking-tight tabular-nums">{n(k.value)}</div>
                    <p className="text-xs text-muted-foreground">{k.note}</p>
                  </CardContent>
                </Card>
              </Link>
            );
          })}
        </div>

        {/* Inventory */}
        <Card className="py-0">
          <ul className="grid grid-cols-2 divide-border sm:grid-cols-3 lg:grid-cols-6 [&>li]:border-border max-lg:[&>li]:border-b lg:divide-x" aria-label="Inventory">
            {inventory.map((k) => {
              const t = tones[k.tone];
              return (
                <li key={k.label}>
                  <Link href={k.href} className="flex h-full items-center gap-3 p-4 transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none">
                    <k.icon className={cn('size-5 shrink-0', t.icon)} aria-hidden />
                    <div className="min-w-0">
                      <div className="text-xl font-semibold tabular-nums">{n(k.value)}</div>
                      <div className="text-xs leading-tight text-muted-foreground">{k.label}</div>
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Card>

        <div className="grid gap-4 lg:grid-cols-5">
          <Card className="min-w-0 lg:col-span-3">
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
                <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center">
                  <CircleCheck className="size-8 text-emerald-600 dark:text-emerald-400" aria-hidden />
                  <p className="text-sm text-muted-foreground">No open pull request needs attention right now.</p>
                </div>
              ) : (
                <ul className="space-y-2" aria-label="Pull requests needing attention">
                  {attention.map((p) => (
                    <li key={p.id}>
                      <Link
                        href={p.project ? `/pull-requests/${p.project.id}/${p.number}` : p.html_url}
                        className="group flex items-start gap-3 rounded-lg border p-3 transition-colors hover:border-primary/40 hover:bg-muted/40"
                      >
                        <UrgencyPill level={p.urgency_level} score={p.urgency} />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-medium group-hover:text-primary">{p.title}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            {p.repo_full_name} #{p.number}
                            {p.author_login && ` · ${p.author_login}`}
                          </div>
                          {p.reasons[0] && <div className="mt-1 truncate text-xs text-muted-foreground">{p.reasons[0].text}</div>}
                        </div>
                        <ArrowRight className="mt-1 size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card className="min-w-0 lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                <IconChip icon={Trophy} />
                Top Vulnerable Projects
              </CardTitle>
              <CardDescription>Projects carrying the most known vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              {d.top_projects.length === 0 ? (
                <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed py-10 text-center">
                  <ShieldCheck className="size-8 text-emerald-600 dark:text-emerald-400" aria-hidden />
                  <p className="text-sm text-muted-foreground">No project has known vulnerabilities.</p>
                </div>
              ) : (
                <ol className="space-y-3">
                  {d.top_projects.slice(0, 6).map((p, i) => (
                    <li key={p.id}>
                      <Link href={`/projects/${p.id}`} className="group block">
                        <div className="mb-1 flex items-center gap-2 text-sm">
                          <span className="w-4 text-xs text-muted-foreground tabular-nums">{i + 1}</span>
                          <span className="min-w-0 flex-1 truncate font-medium group-hover:text-primary">{p.name}</span>
                          <span className="text-xs text-muted-foreground tabular-nums">{plural(p.vulns, 'vuln')}</span>
                        </div>
                        <div className="ml-6 h-1.5 overflow-hidden rounded-full bg-muted">
                          <div className={cn('h-full rounded-full', i === 0 ? 'bg-red-500' : 'bg-orange-500/80')} style={{ width: `${Math.max(4, (p.vulns / topMax) * 100)}%` }} />
                        </div>
                      </Link>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </div>

        <ChartCard icon={ChartColumnStacked} title="Vulnerabilities by Risk" description="Open vulnerabilities over time, split by risk level">
          <VulnsOverTime data={d.vulns_over_time} />
        </ChartCard>
        <div className="grid gap-4 lg:grid-cols-2">
          <ChartCard icon={FileChartLine} title="Policy Violations Count" description="How many violations your scans found each day">
            <ViolationsOverTime data={d.violations_over_time} />
          </ChartCard>
          <ChartCard icon={CheckCheck} title="Policy Violation Checks" description="Which kinds of rule are failing most often">
            <ViolationChecks data={d.violations_by_check} />
          </ChartCard>
        </div>
      </div>
    </>
  );
}

function IconChip({ icon: Icon }: { icon: typeof Bug }) {
  return (
    <span className="flex size-9 items-center justify-center rounded-lg bg-primary/10 ring-1 ring-primary/25">
      <Icon className="size-[18px] text-primary" aria-hidden />
    </span>
  );
}

function ChartCard({ icon, title, description, children }: { icon: typeof Bug; title: string; description: string; children: React.ReactNode }) {
  return (
    <Card className="min-w-0">
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
