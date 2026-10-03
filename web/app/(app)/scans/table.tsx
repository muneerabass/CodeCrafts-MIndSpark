'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Check, ChevronDown, Download, GitBranch, GitCommitHorizontal, GitPullRequest, Play, Terminal, Workflow, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, DependencyBadge, RiskBadge, ScanStatus, ViolationCount, VulnCount, triggerLabel } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
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

const yes = (bad: boolean, label: string) =>
  bad ? (
    <span className="inline-flex items-center gap-1 text-red-600" title={label}>
      <X className="size-4" aria-hidden /> <span className="sr-only">{label}: </span>Yes
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-emerald-600" title={label}>
      <Check className="size-4" aria-hidden /> <span className="sr-only">{label}: </span>No
    </span>
  );

const pkgCols: ColumnDef<ScanPackage, unknown>[] = [
  {
    header: 'Package',
    cell: ({ row }) => (
      <div className="flex flex-col gap-0.5">
        <span className="inline-flex items-center gap-2 font-medium">
          <Ecosystem name={row.original.component.ecosystem} /> {row.original.component.name} <Chip>{row.original.component.version}</Chip>
        </span>
        <span className="font-mono text-xs text-muted-foreground">{row.original.manifest_path}</span>
      </div>
    ),
  },
  {
    header: 'Dependency',
    cell: ({ row }) => (
      <div className="flex flex-col gap-1">
        <DependencyBadge {...row.original} />
        {row.original.direct === false && row.original.via.length > 1 && (
          <span className="max-w-56 font-mono text-[11px] text-muted-foreground" title="Introduced via">
            via {row.original.via.slice(0, -1).join(' → ')}
          </span>
        )}
      </div>
    ),
  },
  { header: 'Change', cell: ({ row }) => <Chip>{row.original.change}</Chip> },
  { header: 'Malware', cell: ({ row }) => yes(row.original.malware, 'Malware') },
  { header: 'Vulnerable', cell: ({ row }) => yes(row.original.vulnerable, 'Vulnerable') },
  { header: 'Risky License', cell: ({ row }) => yes(row.original.risky_license, 'Risky license') },
  {
    header: 'Findings',
    cell: ({ row }) => (
      <ul className="flex max-w-md flex-col gap-1">
        {row.original.vulns.map((v) => (
          <li key={v.id} className="flex items-center gap-2 text-xs">
            <RiskBadge risk={v.risk} />
            <Link className="font-mono hover:underline" href={`/vulnerabilities/${encodeURIComponent(v.id)}`}>
              {v.id}
            </Link>
          </li>
        ))}
        {row.original.violations.map((v, i) => (
          <li key={`${v.rule_name}-${i}`} className="text-xs whitespace-normal text-amber-700">
            {v.rule_name}: {v.summary}
          </li>
        ))}
        {!row.original.vulns.length && !row.original.violations.length && <li className="text-xs text-muted-foreground">—</li>}
      </ul>
    ),
  },
];

const PKG_PAGE = 50;
export function ScanPackagesTable({ data }: { data: ScanPackage[] }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(data.length / PKG_PAGE));
  return (
    <>
      <DataTable columns={pkgCols} data={data.slice(page * PKG_PAGE, (page + 1) * PKG_PAGE)} empty="No package changes in this scan." />
      {pages > 1 && (
        <div className="flex items-center justify-between border-t px-4 py-3 text-sm text-muted-foreground">
          <span className="tabular-nums">
            {page * PKG_PAGE + 1}–{Math.min(data.length, (page + 1) * PKG_PAGE)} of {data.length}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
              Previous
            </Button>
            <Button variant="ghost" size="sm" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>
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
