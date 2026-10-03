import Link from 'next/link';
import { Bug, ChartColumnStacked, CheckCheck, FileChartLine, FolderGit2, GitFork, Hexagon, Route, Scale, ScanSearch, ShieldAlert, Skull, Trophy } from 'lucide-react';
import { api, one, type SearchParams } from '@/lib/api';
import { requireOrg } from '@/lib/session';
import type { Dashboard } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { Logo } from '@/components/icons';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { RangeSelect, TopProjects, ViolationChecks, ViolationsOverTime, VulnsOverTime } from './charts';

export const metadata = { title: 'Dashboard' };

export default async function DashboardPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const range = ['7d', '30d', '90d'].includes(one(sp.range) ?? '') ? one(sp.range)! : '30d';
  const [{ user }, d] = await Promise.all([requireOrg(), api<Dashboard>('/dashboard', { query: { range } })]);

  const kpis = [
    { label: 'Projects', value: d.projects, icon: FolderGit2, href: '/projects', tone: 'text-primary' },
    { label: 'Components', value: d.components, icon: Hexagon, href: '/components', tone: 'text-primary' },
    { label: 'Suspicious Packages', value: d.suspicious, icon: ShieldAlert, href: '/package-analysis?status=suspicious', tone: 'text-amber-600' },
    { label: 'Malicious Packages', value: d.malicious, icon: Skull, href: '/package-analysis?status=malicious', tone: 'text-red-600' },
    { label: 'Policy Violations', value: d.violations, icon: FileChartLine, href: '/policy/violations', tone: 'text-amber-600' },
    { label: 'Total Vulnerabilities', value: d.vulnerabilities, icon: Bug, href: '/vulnerabilities', tone: 'text-red-600' },
    { label: 'Transitive Vulnerabilities', value: d.transitive_vulnerabilities ?? 0, icon: GitFork, href: '/components?direct=false&has_vulns=true', tone: 'text-red-600' },
    { label: 'Attack Paths', value: d.attack_paths ?? 0, icon: Route, href: '/projects', tone: 'text-red-600' },
    { label: 'Suspicious Findings', value: d.suspicious_findings ?? 0, icon: ScanSearch, href: '/package-analysis?view=suspicious', tone: 'text-amber-600' },
    { label: 'License Issues', value: d.license_issues ?? 0, icon: Scale, href: '/policy/violations?category=license', tone: 'text-amber-600' },
  ];

  return (
    <>
      <PageHeader crumbs={[{ label: 'Dashboard' }]} />
      <div className="mx-auto w-full max-w-7xl space-y-8 p-4 md:p-8">
        <Logo className="size-12" />
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold">Welcome back, {user.name.split(' ')[0] || user.name}</h1>
            <p className="text-muted-foreground">Here is where your software supply chain stands right now.</p>
          </div>
          <RangeSelect />
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {kpis.map((k) => (
            <Link key={k.label} href={k.href} className="group rounded-xl focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none">
              <Card className="h-full transition-colors group-hover:border-primary/40">
                <CardHeader>
                  <CardTitle className="flex items-center gap-3 text-base font-normal text-muted-foreground">
                    <span className="flex size-9 items-center justify-center rounded-lg border bg-background">
                      <k.icon className={`size-5 ${k.tone}`} aria-hidden />
                    </span>
                    {k.label}
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-4xl font-semibold tabular-nums">{k.value.toLocaleString('en-GB')}</CardContent>
              </Card>
            </Link>
          ))}
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <ChartCard icon={FileChartLine} title="Policy Violations Count" description="How many violations your scans found each day">
            <ViolationsOverTime data={d.violations_over_time} />
          </ChartCard>
          <ChartCard icon={CheckCheck} title="Policy Violation Checks" description="Which kinds of rule are failing most often">
            <ViolationChecks data={d.violations_by_check} />
          </ChartCard>
          <ChartCard icon={ChartColumnStacked} title="Vulnerabilities by Risk" description="Open vulnerabilities over time, split by risk level">
            <VulnsOverTime data={d.vulns_over_time} />
          </ChartCard>
          <ChartCard icon={Trophy} title="Top Vulnerable Projects" description="Projects carrying the most known vulnerabilities">
            <TopProjects data={d.top_projects} />
          </ChartCard>
        </div>
      </div>
    </>
  );
}

function ChartCard({ icon: Icon, title, description, children }: { icon: typeof Bug; title: string; description: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <span className="flex size-9 items-center justify-center rounded-lg border bg-background">
            <Icon className="size-5 text-primary" aria-hidden />
          </span>
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}
