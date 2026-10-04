import Link from 'next/link';
import { Bug, ExternalLink, FileChartLine, GitBranch, Hexagon, Route, ShieldCheck } from 'lucide-react';
import { api, apiOr404, listQuery, one, type SearchParams } from '@/lib/api';
import { fmtDateTime } from '@/lib/format';
import type { LicenseReport, List, PathGraph, ProjectDetail, PullRequest, ProjectSettings, VaultMemberSelf, VaultState, VersionComponent, VersionScan, VersionSummary, Violation, VulnRow } from '@/lib/types';
import { canWrite, requireOrg } from '@/lib/session';
import { DIRECT_OPTIONS, usageLabel } from '@/lib/format';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { AttackPaths } from './attack-paths';
import { LicenseDistribution, LicenseFindingsTable, ProjectLicenseForm } from './licenses';
import { EmptyState, PageHeader } from '@/components/page';
import { ExportMenu } from './export-menu';
import { VaultPanel } from './vault';
import { Chip } from '@/components/badges';
import { GitHubIcon, SourceIcon } from '@/components/icons';
import { PopoverFilter, ToggleFilter } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { VersionComponentsTable, VersionScansTable, VersionSelect, VersionVulnsTable } from '../tables';
import { ViolationsTable } from '../../policy/violations/table';
import { PullRequestsTable } from '@/components/pull-requests';
import { FilterBar } from '@/components/data-table';
import { LEVELS, PR_STATE_OPTIONS, levelLabel } from '@/lib/pr';

const TABS = [
  { key: 'components', label: 'Components' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'violations', label: 'Violations' },
  { key: 'scans', label: 'Scans' },
  { key: 'pull-requests', label: 'Pull Requests' },
  { key: 'paths', label: 'Attack Paths' },
  { key: 'licenses', label: 'Licenses' },
  { key: 'secrets', label: 'Secrets' },
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
      {version && <ExportMenu projectId={project.id} versionId={version.id} />}
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
  const q = listQuery(sp, ['has_vulns', 'has_violations', 'direct', 'state', 'level'], 10);
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
            <PopoverFilter f={{ type: 'select', key: 'direct', label: 'Dependency', options: DIRECT_OPTIONS }} />
          </div>
        )}
      </div>
      <TabBody tab={tab} base={base} q={q} project={project} />
    </>
  );
}

async function TabBody({ tab, base, q, project }: { tab: string; base: string; q: Record<string, string>; project: ProjectDetail }) {
  if (tab === 'secrets') {
    const [ctx, vault, me] = await Promise.all([requireOrg(), api<VaultState>(`/projects/${encodeURIComponent(project.id)}/vault`), api<{ member: VaultMemberSelf | null }>('/vault/me')]);
    return <VaultPanel projectId={project.id} initial={vault} initialMe={me.member} userId={ctx.user.id} canEdit={canWrite(ctx.role)} />;
  }
  if (tab === 'pull-requests') {
    const prs = await api<List<PullRequest>>(`/projects/${encodeURIComponent(project.id)}/pull-requests`, { query: q });
    return (
      <>
        <FilterBar
          filters={[
            { type: 'select', key: 'state', label: 'State', options: PR_STATE_OPTIONS },
            { type: 'select', key: 'level', label: 'Urgency', options: LEVELS.map((l) => ({ value: l, label: levelLabel[l] })) },
          ]}
        />
        <PullRequestsTable data={prs.items} total={prs.total} showRepo={false} />
      </>
    );
  }
  if (tab === 'paths') {
    const g = await api<PathGraph>(`${base}/paths`);
    if (!g.paths.length && !g.nodes.length)
      return (
        <EmptyState icon={Route} title="No attack paths">
          No vulnerable, malicious or suspicious package is reachable from this version, or its lockfile has no dependency graph.
        </EmptyState>
      );
    return <AttackPaths graph={g} appName={project.name} />;
  }
  if (tab === 'licenses') {
    const [{ role }, settings, lic] = await Promise.all([requireOrg(), api<ProjectSettings>(`/projects/${encodeURIComponent(project.id)}/settings`), api<LicenseReport>(`${base}/licenses`)]);
    const conflicts = lic.findings.filter((f) => f.rule === 'license-conflict' || f.rule === 'license-incompatible');
    return (
      <div className="grid gap-4 p-4 lg:grid-cols-[22rem_1fr]">
        <Card className="self-start">
          <CardHeader>
            <CardTitle className="text-base">Project license</CardTitle>
          </CardHeader>
          <CardContent>
            <ProjectLicenseForm key={`${settings.license}-${settings.usage_model}`} projectId={project.id} settings={settings} canEdit={canWrite(role)} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">License distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <LicenseDistribution data={lic.distribution} />
          </CardContent>
        </Card>
        <Card className="gap-0 overflow-hidden py-0 lg:col-span-2">
          <CardHeader className="border-b py-4">
            <CardTitle>License findings ({lic.findings.length})</CardTitle>
            <p className="text-sm text-muted-foreground">
              Evaluated for a <span className="font-medium text-foreground">{lic.project_license ?? 'unknown'}</span> project used as <span className="font-medium text-foreground">{usageLabel(lic.usage_model).toLowerCase()}</span>.
            </p>
          </CardHeader>
          <LicenseFindingsTable data={lic.findings} />
        </Card>
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Conflicts ({conflicts.length})</CardTitle>
          </CardHeader>
          <CardContent>
            {conflicts.length ? (
              <ul className="space-y-2 text-sm">
                {conflicts.map((f, i) => (
                  <li key={i} className="rounded-md border p-3">
                    <span className="font-medium">
                      {f.component.name}@{f.component.version}
                    </span>{' '}
                    <span className="font-mono text-xs">({String(f.details.license ?? '?')})</span> conflicts with{' '}
                    {Array.isArray(f.details.conflicts_with) ? (
                      <span className="font-medium">
                        {f.details.conflicts_with.length} other dependenc{f.details.conflicts_with.length === 1 ? 'y' : 'ies'}:{' '}
                        <span className="font-mono text-xs font-normal">
                          {(f.details.conflicts_with as string[]).slice(0, 5).join(', ')}
                          {f.details.conflicts_with.length > 5 ? ` and ${f.details.conflicts_with.length - 5} more` : ''}
                        </span>
                      </span>
                    ) : (
                      <span className="font-medium">{String(f.details.other ?? `your ${f.details.project_license ?? 'project'} license`)}</span>
                    )}
                    {f.details.other_license ? <span className="font-mono text-xs"> ({String(f.details.other_license)})</span> : null}
                    <p className="mt-1 text-muted-foreground">{String(f.details.explanation ?? f.summary)}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No license conflicts.</p>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }
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
