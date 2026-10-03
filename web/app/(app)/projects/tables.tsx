'use client';

import Link from 'next/link';
import { ArrowRight, ExternalLink, GitBranch, Hexagon, LayoutGrid, List as ListIcon, MoreHorizontal, FolderOpen } from 'lucide-react';
import { DataTable, Pagination, type ColumnDef } from '@/components/data-table';
import { Chip, DependencyBadge, RiskBadge, ScanStatus, ViolationCount, VulnCount, triggerLabel } from '@/components/badges';
import { Ecosystem, GitHubIcon, SourceIcon } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { parseAsInteger, parseAsString, parseAsStringLiteral, useQueryState, useQueryStates } from 'nuqs';
import { fmtDate } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { Project, VersionComponent, VersionScan, VulnRow } from '@/lib/types';

type TableProps<T> = { data: T[]; total: number; empty?: React.ReactNode };

const sourceLabel: Record<string, string> = { github: 'GitHub', gitlab: 'GitLab', bitbucket: 'Bitbucket', cli: 'CLI upload' };

function health(p: Project) {
  return p.vulns
    ? { label: 'At risk', cls: 'text-red-700 dark:text-red-300 bg-red-500/10 ring-red-500/25', dot: 'bg-red-500', bar: 'from-red-500 to-orange-500' }
    : p.violations
      ? { label: 'Needs review', cls: 'text-amber-700 dark:text-amber-300 bg-amber-500/10 ring-amber-500/25', dot: 'bg-amber-500', bar: 'from-amber-500 to-yellow-400' }
      : { label: 'Healthy', cls: 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 ring-emerald-500/25', dot: 'bg-emerald-500', bar: 'from-emerald-500 to-teal-400' };
}

function Health({ p }: { p: Project }) {
  const h = health(p);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ${h.cls}`}>
      <span className={`size-1.5 rounded-full ${h.dot}`} aria-hidden />
      {h.label}
    </span>
  );
}

function RepoName({ name }: { name: string }) {
  const i = name.lastIndexOf('/');
  return (
    <>
      {i > 0 && <span className="text-muted-foreground">{name.slice(0, i + 1)}</span>}
      <span className="font-semibold">{name.slice(i + 1)}</span>
    </>
  );
}

const projectCols: ColumnDef<Project, unknown>[] = [
  {
    header: 'Repository Name',
    cell: ({ row }) => {
      const p = row.original;
      return (
        <div className="flex items-center gap-3">
          <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-background">
            <SourceIcon source={p.source} />
          </span>
          <div className="min-w-0">
            <Link href={`/projects/${p.id}`} className="block truncate hover:text-primary hover:underline">
              <RepoName name={p.name} />
            </Link>
            <div className="text-xs text-muted-foreground">{sourceLabel[p.source] ?? p.source}</div>
          </div>
        </div>
      );
    },
  },
  { header: 'Health', cell: ({ row }) => <Health p={row.original} /> },
  {
    header: 'No. of Versions',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5">
        <GitBranch className="size-4 text-muted-foreground" />
        {row.original.versions}
      </span>
    ),
  },
  {
    header: 'No. of Components',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5">
        <Hexagon className="size-4 text-muted-foreground" />
        {row.original.components.toLocaleString('en-GB')}
      </span>
    ),
  },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Created At', cell: ({ row }) => fmtDate(row.original.created_at) },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`Actions for ${row.original.name}`}>
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link href={`/projects/${row.original.id}`}>
              <FolderOpen /> Open project
            </Link>
          </DropdownMenuItem>
          {row.original.url && (
            <DropdownMenuItem asChild>
              <a href={row.original.url} target="_blank" rel="noreferrer">
                <GitHubIcon /> See it on {row.original.source === 'github' ? 'GitHub' : 'source host'} <ExternalLink className="ml-auto" />
              </a>
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    ),
  },
];

export function ProjectsTable(p: TableProps<Project>) {
  return <DataTable columns={projectCols} {...p} />;
}

export function ViewToggle() {
  const [view, setView] = useQueryState('view', parseAsStringLiteral(['grid', 'table']).withDefault('grid').withOptions({ shallow: false }));
  const opts = [
    { id: 'grid', label: 'Grid view', icon: LayoutGrid },
    { id: 'table', label: 'Table view', icon: ListIcon },
  ] as const;
  return (
    <div className="inline-flex rounded-lg border bg-background p-0.5" role="group" aria-label="View">
      {opts.map((o) => (
        <button
          key={o.id}
          type="button"
          aria-label={o.label}
          aria-pressed={view === o.id}
          title={o.label}
          onClick={() => setView(o.id === 'grid' ? null : o.id)}
          className={cn('rounded-md p-1.5 text-muted-foreground transition-colors hover:text-foreground', view === o.id && 'bg-primary/15 text-primary hover:text-primary')}
        >
          <o.icon className="size-4" />
        </button>
      ))}
    </div>
  );
}

const sourceName = (s: string) => sourceLabel[s] ?? s;

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="bg-card px-3 py-2.5">
      <dt className="truncate text-[11px] text-muted-foreground">{label}</dt>
      <dd className={cn('text-lg font-semibold tabular-nums', tone)}>{value.toLocaleString('en-GB')}</dd>
    </div>
  );
}

function ProjectCard({ p }: { p: Project }) {
  const h = health(p);
  return (
    <article className="group relative flex flex-col overflow-hidden rounded-xl border bg-card shadow-xs transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-lg">
      <div className={cn('h-1 bg-gradient-to-r', h.bar)} aria-hidden />
      <div className="flex items-start gap-3 p-4">
        <span className="flex size-10 shrink-0 items-center justify-center rounded-lg border bg-background">
          <SourceIcon source={p.source} className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-sm">
            <Link href={`/projects/${p.id}`} className="outline-none after:absolute after:inset-0 after:rounded-xl focus-visible:after:ring-2 focus-visible:after:ring-ring">
              <RepoName name={p.name} />
            </Link>
          </h3>
          <p className="truncate text-xs text-muted-foreground">
            {sourceName(p.source)} · added {fmtDate(p.created_at)}
          </p>
        </div>
        <Health p={p} />
      </div>
      <dl className="grid grid-cols-4 gap-px border-y bg-border">
        <Stat label="Vulnerabilities" value={p.vulns} tone={p.vulns ? 'text-red-600 dark:text-red-400' : undefined} />
        <Stat label="Violations" value={p.violations} tone={p.violations ? 'text-amber-600 dark:text-amber-400' : undefined} />
        <Stat label="Components" value={p.components} />
        <Stat label="Branches" value={p.versions} />
      </dl>
      <div className="flex items-center justify-between px-4 py-2.5 text-sm">
        <span className="inline-flex items-center gap-1 font-medium text-primary">
          Open project <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden />
        </span>
        {p.url && (
          <a href={p.url} target="_blank" rel="noreferrer" className="relative z-10 inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
            <SourceIcon source={p.source} className="size-3.5" /> {sourceName(p.source)} <ExternalLink className="size-3" aria-hidden />
          </a>
        )}
      </div>
    </article>
  );
}

export function ProjectGrid({ data, total, empty }: TableProps<Project>) {
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 p-4">
        {data.length ? (
          <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3" aria-label="Projects">
            {data.map((p) => (
              <ProjectCard key={p.id} p={p} />
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-dashed">{empty}</div>
        )}
      </div>
      <Pagination total={total} />
    </div>
  );
}

const componentCols: ColumnDef<VersionComponent, unknown>[] = [
  { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
  { header: 'Version', cell: ({ row }) => <Chip>{row.original.version}</Chip> },
  { header: 'Classification', cell: ({ row }) => row.original.type || 'Library' },
  { header: 'Dependency', cell: ({ row }) => <DependencyBadge {...row.original} /> },
  { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.ecosystem} /> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Created At', cell: ({ row }) => fmtDate(row.original.created_at) },
  { header: 'Updated At', cell: ({ row }) => fmtDate(row.original.updated_at) },
];
export function VersionComponentsTable(p: TableProps<VersionComponent>) {
  return <DataTable columns={componentCols} defaultPageSize={10} {...p} />;
}

const vulnCols: ColumnDef<VulnRow, unknown>[] = [
  {
    header: 'ID',
    cell: ({ row }) => (
      <Link href={`/vulnerabilities/${encodeURIComponent(row.original.id)}`} className="font-mono text-sm hover:text-primary hover:underline">
        {row.original.id}
      </Link>
    ),
  },
  { header: 'Summary', cell: ({ row }) => <span className="line-clamp-1 max-w-2xl">{row.original.summary}</span> },
  { header: 'Risk', cell: ({ row }) => <RiskBadge risk={row.original.risk} /> },
  { header: 'Published', cell: ({ row }) => fmtDate(row.original.published) },
  { header: 'Modified', cell: ({ row }) => fmtDate(row.original.modified) },
];
export function VersionVulnsTable(p: TableProps<VulnRow>) {
  return <DataTable columns={vulnCols} defaultPageSize={10} {...p} />;
}

const scanCols: ColumnDef<VersionScan, unknown>[] = [
  { header: 'Trigger', cell: ({ row }) => <Chip>{triggerLabel(row.original.trigger)}</Chip> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Scan Date', cell: ({ row }) => fmtDate(row.original.created_at) },
  { header: 'Status', cell: ({ row }) => <ScanStatus status={row.original.status} /> },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Link href={`/scans/${row.original.id}`} className="text-sm font-medium text-primary hover:underline">
        Open Report
      </Link>
    ),
  },
];
export function VersionScansTable(p: TableProps<VersionScan>) {
  return <DataTable columns={scanCols} defaultPageSize={10} {...p} />;
}

export function VersionSelect({ versions, value }: { versions: { id: string; name: string }[]; value: string }) {
  const [, set] = useQueryStates({ version: parseAsString, page: parseAsInteger }, { shallow: false });
  return (
    <Select value={value} onValueChange={(v) => set({ version: v, page: null })}>
      <SelectTrigger size="sm" className="min-w-32" aria-label="Branch / version">
        <GitBranch className="size-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent align="end">
        {versions.map((v) => (
          <SelectItem key={v.id} value={v.id}>
            {v.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
