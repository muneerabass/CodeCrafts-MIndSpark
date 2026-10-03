import Link from 'next/link';
import { api, listQuery, one, type SearchParams } from '@/lib/api';
import type { List, PackageAnalysis, Project, Violation } from '@/lib/types';
import { PageHeader } from '@/components/page';
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
  const projects = await api<List<Project>>('/projects', { query: { page_size: 50 } });
  const projectOpts = projects.items.map((p) => ({ value: p.id, label: p.name }));
  const nav = (
    <nav className="flex gap-1 rounded-lg bg-muted p-1" aria-label="Package analysis views">
      {VIEWS.map((v) => (
        <Link key={v.key} href={v.key === 'analyses' ? '?' : `?view=${v.key}`} aria-current={v.key === view ? 'page' : undefined} className={cn('rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground', v.key === view && 'bg-background font-medium text-foreground shadow-xs')}>
          {v.label}
        </Link>
      ))}
    </nav>
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
        <div className="border-b px-4 py-2">{nav}</div>
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
      <div className="border-b px-4 py-2">{nav}</div>
      <FilterBar
        filters={[
          { type: 'select', key: 'project_id', label: 'Project', options: projectOpts },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
          { type: 'daterange' },
          { type: 'select', key: 'status', label: 'Status', options: [{ value: 'clean', label: 'Clean' }, { value: 'suspicious', label: 'Suspicious' }, { value: 'malicious', label: 'Malicious' }] },
          { type: 'toggle', key: 'verified', label: 'Verification Status' },
        ]}
      />
      <AnalysesTable data={data.items} total={data.total} />
    </>
  );
}
