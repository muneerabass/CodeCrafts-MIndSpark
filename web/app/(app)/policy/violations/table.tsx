'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { RiskBadge } from '@/components/badges';
import { Button } from '@/components/ui/button';
import { ArrowRight, Bug, ChevronRight, FileChartLine, GitBranch, Scale, ScanSearch, Skull, Star, Wrench } from 'lucide-react';
import { cn } from '@/lib/utils';
import { EcosystemTile } from '@/components/icons';
import { ago, fmtDate, titleCase } from '@/lib/format';
import type { Violation } from '@/lib/types';

const catIcon: Record<string, typeof Bug> = { vulnerability: Bug, malware: Skull, license: Scale, suspicious: ScanSearch, popularity: Star, maintenance: Wrench };
const sevTile: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-600 ring-red-500/25 dark:text-red-400',
  high: 'bg-orange-500/15 text-orange-600 ring-orange-500/25 dark:text-orange-400',
  medium: 'bg-amber-500/15 text-amber-700 ring-amber-500/25 dark:text-amber-400',
  low: 'bg-sky-500/15 text-sky-600 ring-sky-500/25 dark:text-sky-400',
};

function Details({ v }: { v: Violation }) {
  const rows = Object.entries(v.details ?? {})
    .filter(([, x]) => x != null && x !== '' && (typeof x !== 'object' || Array.isArray(x)))
    .map(([k, x]) => [k, Array.isArray(x) ? x.join(', ') : String(x)] as const);
  if (!rows.length) return null;
  return (
    <details className="group/d mt-1 text-xs">
      <summary className="inline-flex cursor-pointer list-none items-center gap-1 text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
        <ChevronRight className="size-3 transition-transform group-open/d:rotate-90" aria-hidden /> Details
      </summary>
      <dl className="mt-1 grid max-w-md grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-md bg-muted/50 p-2">
        {rows.map(([k, x]) => (
          <div key={k} className="contents">
            <dt className="text-muted-foreground">{titleCase(k)}</dt>
            <dd className="break-words">{x}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

const cols = (hideProject: boolean): ColumnDef<Violation, unknown>[] => [
  {
    header: 'Violation',
    cell: ({ row }) => {
      const v = row.original;
      const Icon = catIcon[v.category] ?? FileChartLine;
      return (
        <div className="flex max-w-lg items-start gap-3">
          <span className={cn('mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg ring-1', sevTile[v.severity ?? ''] ?? 'bg-muted ring-border')} title={titleCase(v.category)}>
            <Icon className="size-4" aria-hidden />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2">
              <span className="font-semibold">{v.rule_name}</span>
              <span className="text-xs text-muted-foreground">{titleCase(v.category)}</span>
            </div>
            <p className="line-clamp-1 text-sm text-muted-foreground" title={v.summary}>
              {v.summary}
            </p>
            <Details v={v} />
          </div>
        </div>
      );
    },
  },
  {
    header: 'Severity',
    cell: ({ row }) => (
      <span className="inline-flex flex-col items-start gap-1">
        {row.original.severity ? <RiskBadge risk={row.original.severity} /> : '—'}
        <span className="text-[11px] text-muted-foreground">{row.original.blocking === false ? 'Report only' : 'Blocks'}</span>
      </span>
    ),
  },
  {
    header: 'Component',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2">
        <EcosystemTile name={row.original.component.ecosystem} className="size-7 text-[10px]" />
        <span className="min-w-0">
          <span className="block font-medium">{row.original.component.name}</span>
          <span className="block font-mono text-xs text-muted-foreground">{row.original.component.version}</span>
        </span>
      </span>
    ),
  },
  ...(hideProject
    ? []
    : ([
        {
          header: 'Project',
          cell: ({ row }) =>
            row.original.project ? (
              <span className="min-w-0">
                <Link className="block font-medium hover:text-primary hover:underline" href={`/projects/${row.original.project.id}`}>
                  {row.original.project.name}
                </Link>
                {row.original.version && (
                  <span className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
                    <GitBranch className="size-3" aria-hidden />
                    {row.original.version}
                  </span>
                )}
              </span>
            ) : (
              '—'
            ),
        },
      ] satisfies ColumnDef<Violation, unknown>[])),
  {
    header: 'Detected',
    cell: ({ row }) => (
      <span className="text-sm whitespace-nowrap text-muted-foreground" title={fmtDate(row.original.created_at)} suppressHydrationWarning>
        {ago(row.original.created_at)}
      </span>
    ),
  },
  {
    id: 'scan',
    header: () => <span className="sr-only">Scan</span>,
    cell: ({ row }) =>
      row.original.scan_id ? (
        <Button asChild variant="outline" size="sm" className="h-8">
          <Link href={`/scans/${row.original.scan_id}`}>
            Report <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        </Button>
      ) : null,
  },
];

export function ViolationsTable({ data, total, hideProject = false }: { data: Violation[]; total: number; hideProject?: boolean }) {
  return <DataTable columns={cols(hideProject)} data={data} total={total} defaultPageSize={hideProject ? 10 : 20} />;
}
