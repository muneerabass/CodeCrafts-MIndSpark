'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Check, ChevronDown, Download, GitBranch, GitCommitHorizontal, GitPullRequest, Play, Search, Skull, Terminal, Workflow } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { DependencyBadge, RiskBadge, ScanStatus, ViolationCount, VulnCount, triggerLabel } from '@/components/badges';
import { EcosystemTile } from '@/components/icons';
import { ago, fmtDateTime } from '@/lib/format';
import type { ScanPackage, ScanRow } from '@/lib/types';

const triggerIcon: Record<string, typeof GitBranch> = { pull_request: GitPullRequest, push: GitCommitHorizontal, manual: Play, cli: Terminal, ci: Workflow };

const cols: ColumnDef<ScanRow, unknown>[] = [
  {
    header: 'Scanned Project',
    cell: ({ row }) => {
      const r = row.original;
      const i = r.project.name.lastIndexOf('/');
      return (
        <div className="min-w-0">
          <Link href={`/projects/${r.project.id}`} className="block truncate hover:text-primary hover:underline">
            {i > 0 && <span className="text-muted-foreground">{r.project.name.slice(0, i + 1)}</span>}
            <span className="font-semibold">{r.project.name.slice(i + 1)}</span>
          </Link>
          <span className="mt-0.5 inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
            <GitBranch className="size-3" aria-hidden />
            {r.version}
          </span>
        </div>
      );
    },
  },
  {
    header: 'Trigger',
    cell: ({ row }) => {
      const Icon = triggerIcon[row.original.trigger] ?? Play;
      return (
        <span className="inline-flex items-center gap-1.5 text-sm">
          <span className="flex size-7 items-center justify-center rounded-md border bg-background">
            <Icon className="size-3.5 text-muted-foreground" aria-hidden />
          </span>
          {triggerLabel(row.original.trigger)}
        </span>
      );
    },
  },
  { header: 'Status', cell: ({ row }) => <ScanStatus status={row.original.status} /> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  {
    header: 'Scan Date',
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground" title={fmtDateTime(row.original.created_at)} suppressHydrationWarning>
        {ago(row.original.created_at)}
      </span>
    ),
  },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Button asChild variant="outline" size="sm" className="h-8">
        <Link href={`/scans/${row.original.id}`}>
          Open Report <ArrowRight className="size-3.5" aria-hidden />
        </Link>
      </Button>
    ),
  },
];

export function ScansTable({ data, total }: { data: ScanRow[]; total: number }) {
  return <DataTable columns={cols} data={data} total={total} />;
}

const changeTone: Record<string, string> = {
  added: 'bg-emerald-500/10 text-emerald-700 ring-emerald-500/25 dark:text-emerald-300',
  updated: 'bg-sky-500/10 text-sky-700 ring-sky-500/25 dark:text-sky-300',
  removed: 'bg-red-500/10 text-red-700 ring-red-500/25 dark:text-red-300',
};

function Issues({ p }: { p: ScanPackage }) {
  const vulns = [...p.vulns].sort((a, b) => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].indexOf(a.risk.toUpperCase()) - ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].indexOf(b.risk.toUpperCase()));
  const rules = [...new Map(p.violations.map((v) => [v.rule_name, v])).values()];
  if (!p.malware && !vulns.length && !rules.length && !p.risky_license)
    return (
      <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
        <Check className="size-3.5" aria-hidden /> No issues
      </span>
    );
  return (
    <div className="flex max-w-md flex-wrap gap-1.5">
      {p.malware && (
        <span className="inline-flex items-center gap-1 rounded-md bg-red-500/15 px-1.5 py-0.5 text-xs font-semibold text-red-700 dark:text-red-300">
          <Skull className="size-3.5" aria-hidden /> Malware
        </span>
      )}
      {vulns.slice(0, 2).map((v) => (
        <Link key={v.id} href={`/vulnerabilities/${encodeURIComponent(v.id)}`} title={v.summary} className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs hover:underline">
          <RiskBadge risk={v.risk} /> <span className="font-mono">{v.id}</span>
        </Link>
      ))}
      {vulns.length > 2 && <span className="self-center text-xs text-muted-foreground">+{vulns.length - 2} advisories</span>}
      {rules.map((v) => (
        <span key={v.rule_name} title={v.summary} className="rounded-md bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-700 ring-1 ring-amber-500/20 dark:text-amber-300">
          {v.rule_name}
        </span>
      ))}
      {p.risky_license && !rules.some((r) => r.category === 'license') && <span className="rounded-md bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-700 dark:text-amber-300">Risky license</span>}
    </div>
  );
}

const pkgCols: ColumnDef<ScanPackage, unknown>[] = [
  {
    header: 'Package',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2.5">
        <EcosystemTile name={row.original.component.ecosystem} />
        <span className="min-w-0">
          <span className="block font-semibold">
            {row.original.component.name} <span className="font-mono text-xs font-normal text-muted-foreground">{row.original.component.version}</span>
          </span>
          <span className="block font-mono text-[11px] text-muted-foreground">{row.original.manifest_path}</span>
        </span>
      </span>
    ),
  },
  {
    header: 'Dependency',
    cell: ({ row }) => (
      <div className="flex flex-col items-start gap-1">
        <DependencyBadge {...row.original} />
        {row.original.direct === false && row.original.via.length > 1 && (
          <span className="max-w-56 truncate font-mono text-[11px] text-muted-foreground" title={`via ${row.original.via.slice(0, -1).join(' → ')}`}>
            via {row.original.via.slice(0, -1).join(' → ')}
          </span>
        )}
      </div>
    ),
  },
  {
    header: 'Change',
    cell: ({ row }) => (
      <span className={cn('rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1', changeTone[row.original.change] ?? 'bg-muted text-muted-foreground ring-border')}>
        {row.original.change}
      </span>
    ),
  },
  { header: 'Issues', cell: ({ row }) => <Issues p={row.original} /> },
];

const hasIssue = (p: ScanPackage) => p.malware || p.vulns.length > 0 || p.violations.length > 0 || p.risky_license;
const FILTERS = [
  { key: 'all', label: 'All', test: () => true },
  { key: 'issues', label: 'With issues', test: hasIssue },
  { key: 'added', label: 'Added', test: (p: ScanPackage) => p.change === 'added' },
  { key: 'updated', label: 'Updated', test: (p: ScanPackage) => p.change === 'updated' },
] as const;

const PKG_PAGE = 50;
export function ScanPackagesTable({ data }: { data: ScanPackage[] }) {
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]['key']>('all');
  const [q, setQ] = useState('');
  const f = FILTERS.find((x) => x.key === filter)!;
  const shown = data.filter((p) => f.test(p) && (!q || p.component.name.toLowerCase().includes(q.toLowerCase())));
  const pages = Math.max(1, Math.ceil(shown.length / PKG_PAGE));
  const at = Math.min(page, pages - 1);
  return (
    <>
      <div className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <div className="inline-flex rounded-lg border bg-muted/50 p-0.5" role="group" aria-label="Show packages">
          {FILTERS.map((x) => (
            <button
              key={x.key}
              type="button"
              aria-pressed={filter === x.key}
              onClick={() => {
                setFilter(x.key);
                setPage(0);
              }}
              className={cn(
                'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground',
                filter === x.key && 'bg-background font-medium text-foreground shadow-xs',
              )}
            >
              {x.label} <span className="tabular-nums opacity-70">{data.filter(x.test).length}</span>
            </button>
          ))}
        </div>
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(0);
            }}
            placeholder="Search packages"
            aria-label="Search packages"
            className="h-8 pl-8"
          />
        </div>
      </div>
      <DataTable columns={pkgCols} data={shown.slice(at * PKG_PAGE, (at + 1) * PKG_PAGE)} empty={data.length ? 'No packages match.' : 'No package changes in this scan.'} />
      {pages > 1 && (
        <div className="flex items-center justify-between border-t px-4 py-3 text-sm text-muted-foreground">
          <span className="tabular-nums">
            {at * PKG_PAGE + 1}–{Math.min(shown.length, (at + 1) * PKG_PAGE)} of {shown.length}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" disabled={at === 0} onClick={() => setPage(at - 1)}>
              Previous
            </Button>
            <Button variant="ghost" size="sm" disabled={at >= pages - 1} onClick={() => setPage(at + 1)}>
              Next
            </Button>
          </div>
        </div>
      )}
    </>
  );
}

export function DownloadReport({ id }: { id: string }) {
  const href = (f: string) => `/api/scans/${encodeURIComponent(id)}/report?format=${f}`;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <Download /> Download report <ChevronDown />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {[
          ['md', 'Markdown (.md)'],
          ['json', 'JSON (.json)'],
          ['html', 'HTML (.html)'],
        ].map(([f, label]) => (
          <DropdownMenuItem key={f} asChild>
            <a href={href(f)} download>
              {label}
            </a>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
