import Link from 'next/link';
import { Bug, ExternalLink, FileChartLine, GitBranch, Hexagon, ShieldCheck } from 'lucide-react';
import { api, apiOr404, listQuery, one, type SearchParams } from '@/lib/api';
import { fmtDateTime } from '@/lib/format';
import type { List, ProjectDetail, VersionComponent, VersionScan, VersionSummary, Violation, VulnRow } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { Chip } from '@/components/badges';
import { GitHubIcon, SourceIcon } from '@/components/icons';
import { ToggleFilter } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { VersionComponentsTable, VersionScansTable, VersionSelect, VersionVulnsTable } from '../tables';
import { ViolationsTable } from '../../policy/violations/table';

const TABS = [
  { key: 'components', label: 'Components' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'violations', label: 'Violations' },
  { key: 'scans', label: 'Scans' },
] as const;

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `Project ${(await params).id}` };
}

export default async function ProjectPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: SearchParams }) {
  const { id } = await params;
  const sp = await searchParams;
  const project = await apiOr404<ProjectDetail>(`/projects/${encodeURIComponent(id)}`);
  const version = project.versions.find((v) => v.id === one(sp.version)) ?? project.versions[0];
  const tab = TABS.find((t) => t.key === one(sp.tab))?.key ?? 'components';

  const actions = (
    <>
      {project.url && (
        <Button asChild variant="secondary" size="sm">
          <a href={project.url} target="_blank" rel="noreferrer">
            <GitHubIcon /> <span className="hidden sm:inline">See it on GitHub</span> <ExternalLink />
          </a>
        </Button>
      )}
      {version && <VersionSelect versions={project.versions} value={version.id} />}
    </>
  );

  if (!version) {
    return (
      <>
        <PageHeader crumbs={[{ label: 'Projects', href: '/projects' }, { label: project.id }]} actions={actions} />
        <EmptyState icon={GitBranch} title="No versions scanned yet">
          This project exists but has no completed scans. Trigger a scan from the Projects page.
        </EmptyState>
      </>
    );
  }

  const base = `/projects/${encodeURIComponent(id)}/versions/${encodeURIComponent(version.id)}`;
  const summary = await api<VersionSummary>(`${base}/summary`);
  const q = listQuery(sp, ['has_vulns', 'has_violations'], 10);
  const tabHref = (t: string) => `?${new URLSearchParams({ version: version.id, tab: t })}`;

  return (
    <>
      <PageHeader crumbs={[{ label: 'Projects', href: '/projects' }, { label: project.id }]} info="Findings for one branch of this project. Switch branches with the selector on the right." actions={actions} />
      <div className="border-b bg-muted/30 px-6 py-5">
        <div className="flex flex-wrap items-center gap-2">
          <SourceIcon source={project.source} className="size-5" />
          <h1 className="text-xl font-semibold">{project.name}</h1>
          <Chip>{version.name}</Chip>
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Last updated <span className="text-foreground">{fmtDateTime(summary.updated_at)}</span>
        </p>
      </div>
      <dl className="grid grid-cols-2 border-b bg-muted/30 md:grid-cols-4">
        <Stat icon={Hexagon} label="Components" value={summary.components} />
        <Stat icon={Bug} label="Vulnerabilities" value={summary.vulns} tone="text-red-600" />
        <Stat icon={FileChartLine} label="Violations" value={summary.violations} tone="text-amber-600" />
        <Stat icon={GitBranch} label="Versions Available" value={summary.versions_available} />
      </dl>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2">
        <nav className="flex gap-1 rounded-lg bg-muted p-1" aria-label="Project sections">
          {TABS.map((t) => (
            <Link
              key={t.key}
              href={tabHref(t.key)}
              aria-current={t.key === tab ? 'page' : undefined}
              className={cn('rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground', t.key === tab && 'bg-background font-medium text-foreground shadow-xs')}
            >
              {t.label}
            </Link>
          ))}
        </nav>
        {tab === 'components' && (
          <div className="flex items-center">
            <ToggleFilter k="has_vulns" label="Has Vulnerabilities" />
            <ToggleFilter k="has_violations" label="Has Policy Violations" />
          </div>
        )}
      </div>
      <TabBody tab={tab} base={base} q={q} />
    </>
  );
}

async function TabBody({ tab, base, q }: { tab: string; base: string; q: Record<string, string> }) {
  if (tab === 'vulnerabilities') {
    const d = await api<List<VulnRow>>(`${base}/vulnerabilities`, { query: q });
    return <VersionVulnsTable data={d.items} total={d.total} empty={<EmptyState icon={ShieldCheck} title="No known vulnerabilities" className="py-8">None of this version&apos;s components match a published advisory.</EmptyState>} />;
  }
  if (tab === 'violations') {
    const d = await api<List<Violation>>(`${base}/violations`, { query: q });
    if (!d.total)
      return (
        <EmptyState icon={ShieldCheck} title="No policy violations found in this project">
          Every component in this version passes your security and license policy.
        </EmptyState>
      );
    return <ViolationsTable data={d.items} total={d.total} hideProject />;
  }
  if (tab === 'scans') {
    const d = await api<List<VersionScan>>(`${base}/scans`, { query: q });
    return <VersionScansTable data={d.items} total={d.total} />;
  }
  const d = await api<List<VersionComponent>>(`${base}/components`, { query: q });
  return <VersionComponentsTable data={d.items} total={d.total} />;
}

function Stat({ icon: Icon, label, value, tone }: { icon: typeof Bug; label: string; value: number; tone?: string }) {
  return (
    <div className="flex flex-col items-center gap-1 px-4 py-4">
      <dt className="flex items-center gap-2 text-sm text-muted-foreground">
        <Icon className={cn('size-4 text-primary', tone)} aria-hidden /> {label}
      </dt>
      <dd className="text-2xl font-semibold tabular-nums">{value.toLocaleString('en-GB')}</dd>
    </div>
  );
}
