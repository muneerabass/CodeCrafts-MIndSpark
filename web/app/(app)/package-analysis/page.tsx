import Link from 'next/link';
import { api, listQuery, one, type SearchParams } from '@/lib/api';
import type { List, PackageAnalysis, Project, Violation } from '@/lib/types';
import { PackageSearch, ScanSearch, ShieldAlert, Skull } from 'lucide-react';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { cn } from '@/lib/utils';
import { SEVERITY_OPTIONS } from '@/lib/format';
import { AnalysesTable, SuspiciousTable } from './table';

export const metadata = { title: 'Package Analysis' };

const VIEWS = [
  { key: 'analyses', label: 'Malware analysis' },
  { key: 'suspicious', label: 'Suspicious findings' },
] as const;
const RULES = ['typosquat', 'unmaintained', 'deprecated', 'new-package', 'no-source-repo', 'unusual-behaviour'];

export default async function PackageAnalysisPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const view = one(sp.view) === 'suspicious' ? 'suspicious' : 'analyses';
  const n = <T,>(path: string, q: Record<string, string>) => api<List<T>>(path, { query: { ...q, page_size: 10 } }).then((l) => l.total);
  const [projects, analysed, malicious, suspicious, findings] = await Promise.all([
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
    n<PackageAnalysis>('/package-analyses', {}),
    n<PackageAnalysis>('/package-analyses', { status: 'malicious' }),
    n<PackageAnalysis>('/package-analyses', { status: 'suspicious' }),
    n<Violation>('/policy/violations', { category: 'suspicious' }),
  ]);
  const projectOpts = projects.items.map((p) => ({ value: p.id, label: p.name }));
  const status = one(sp.status);
  const tiles: StatTile[] = [
    { label: 'Packages analysed', value: analysed, icon: PackageSearch, href: '/package-analysis', active: view === 'analyses' && !status, tone: 'primary' },
    { label: 'Malicious', value: malicious, icon: Skull, href: '/package-analysis?status=malicious', active: status === 'malicious', tone: 'red' },
    { label: 'Suspicious verdicts', value: suspicious, icon: ShieldAlert, href: '/package-analysis?status=suspicious', active: status === 'suspicious', tone: 'amber' },
    { label: 'Suspicious findings', value: findings, icon: ScanSearch, href: '/package-analysis?view=suspicious', active: view === 'suspicious', tone: 'orange' },
  ];
  const counts = { analyses: analysed, suspicious: findings };
  const nav = (
    <nav className="inline-flex gap-1 rounded-lg border bg-muted/50 p-1" aria-label="Package analysis views">
      {VIEWS.map((v) => (
        <Link
          key={v.key}
          href={v.key === 'analyses' ? '?' : `?view=${v.key}`}
          aria-current={v.key === view ? 'page' : undefined}
          className={cn(
            'inline-flex items-center gap-2 rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground',
            v.key === view && 'bg-background font-medium text-foreground shadow-xs',
          )}
        >
          {v.label}
          <span className={cn('rounded-full px-1.5 text-[11px] tabular-nums', v.key === view ? 'bg-primary/15 text-primary' : 'bg-muted')}>{counts[v.key]}</span>
        </Link>
      ))}
    </nav>
  );
  const top = (
    <>
      <PageIntro title="Package Analysis" description="Malware verdicts for every scanned package, and packages that look suspicious." />
      <StatTiles label="Package analysis summary" tiles={tiles} />
      <div className="border-b px-4 py-2 md:px-6">{nav}</div>
    </>
  );
  const header = (
    <PageHeader
      crumbs={[{ label: 'Package Analysis' }]}
      info="Malware verdicts for scanned packages (known-malicious advisories plus heuristic analysis), and suspicious-package findings: lookalike names, unmaintained or deprecated packages, brand-new versions and unusual install-time behaviour."
      actions={null}
    />
  );

  if (view === 'suspicious') {
    const data = await api<List<Violation>>('/policy/violations', { query: { ...listQuery(sp, ['rule', 'project_id', 'severity']), category: 'suspicious' } });
    return (
      <>
        {header}
        {top}
        <FilterBar
          filters={[
            { type: 'select', key: 'rule', label: 'Rule', options: RULES.map((r) => ({ value: r, label: r })) },
            { type: 'select', key: 'severity', label: 'Severity', options: SEVERITY_OPTIONS },
            { type: 'select', key: 'project_id', label: 'Project', options: projectOpts },
          ]}
        />
        <SuspiciousTable data={data.items} total={data.total} />
      </>
    );
  }

  const data = await api<List<PackageAnalysis>>('/package-analyses', { query: listQuery(sp, ['project_id', 'version', 'from', 'to', 'status', 'verified']) });
  return (
    <>
      {header}
      {top}
      <FilterBar
        filters={[
          { type: 'select', key: 'project_id', label: 'Project', options: projectOpts },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
          { type: 'daterange' },
          {
            type: 'select',
            key: 'status',
            label: 'Status',
            options: [
              { value: 'clean', label: 'Clean' },
              { value: 'suspicious', label: 'Suspicious' },
              { value: 'malicious', label: 'Malicious' },
            ],
          },
          { type: 'toggle', key: 'verified', label: 'Verification Status' },
        ]}
      />
      <AnalysesTable data={data.items} total={data.total} />
    </>
  );
}
