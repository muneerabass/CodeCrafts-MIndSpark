'use client';

import Link from 'next/link';
import { ArrowRight, Bug, ExternalLink, FolderGit2, Hexagon, Skull } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, DueBadge, RiskBadge } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate } from '@/lib/format';
import type { AffectedComponent, VulnerabilityRow } from '@/lib/types';

const riskIcon: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-600 ring-red-500/25 dark:text-red-400',
  HIGH: 'bg-orange-500/15 text-orange-600 ring-orange-500/25 dark:text-orange-400',
  MEDIUM: 'bg-amber-500/15 text-amber-700 ring-amber-500/25 dark:text-amber-400',
  LOW: 'bg-sky-500/15 text-sky-600 ring-sky-500/25 dark:text-sky-400',
};

const cols: ColumnDef<VulnerabilityRow, unknown>[] = [
  {
    header: 'Vulnerability',
    cell: ({ row }) => {
      const v = row.original;
      const mal = v.id.startsWith('MAL-');
      return (
        <div className="flex max-w-xl items-center gap-3">
          <span className={cn('flex size-9 shrink-0 items-center justify-center rounded-lg ring-1', riskIcon[v.risk?.toUpperCase()] ?? 'bg-muted ring-border')}>
            {mal ? <Skull className="size-4" aria-hidden /> : <Bug className="size-4" aria-hidden />}
          </span>
          <div className="min-w-0">
            <Link href={`/vulnerabilities/${encodeURIComponent(v.id)}`} className="font-mono text-sm font-semibold hover:text-primary hover:underline">
              {v.id}
            </Link>
            <p className="truncate text-xs text-muted-foreground" title={v.summary}>
              {v.summary}
            </p>
          </div>
        </div>
      );
    },
  },
  { header: 'Risk', cell: ({ row }) => <RiskBadge risk={row.original.risk} /> },
  {
    header: 'Affected',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-3 text-sm whitespace-nowrap">
        <span className="inline-flex items-center gap-1" title="Affected components">
          <Hexagon className="size-3.5 text-muted-foreground" aria-hidden />
          {row.original.affected_components} {row.original.affected_components === 1 ? 'component' : 'components'}
        </span>
        <span className="inline-flex items-center gap-1" title="Affected projects">
          <FolderGit2 className="size-3.5 text-muted-foreground" aria-hidden />
          {row.original.affected_projects} {row.original.affected_projects === 1 ? 'project' : 'projects'}
        </span>
      </span>
    ),
  },
  { header: 'Fix by', cell: ({ row }) => <DueBadge due={row.original.due_at} overdue={row.original.overdue} open={row.original.open} /> },
  {
    header: 'Published',
    cell: ({ row }) => (
      <span className="text-sm text-muted-foreground" title={`Published ${fmtDate(row.original.published)} · modified ${fmtDate(row.original.modified)}`}>
        {fmtDate(row.original.published)}
      </span>
    ),
  },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <span className="flex items-center justify-end gap-1">
        <Button asChild variant="ghost" size="icon" className="size-8">
          <a
            href={`https://osv.dev/vulnerability/${encodeURIComponent(row.original.id)}`}
            target="_blank"
            rel="noreferrer"
            aria-label={`${row.original.id} on osv.dev (opens in a new tab)`}
            title="Open on osv.dev"
          >
            <ExternalLink className="size-4" />
          </a>
        </Button>
        <Button asChild variant="outline" size="sm" className="h-8">
          <Link href={`/vulnerabilities/${encodeURIComponent(row.original.id)}`}>
            View Affected <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        </Button>
      </span>
    ),
  },
];

export function VulnerabilitiesTable({ data, total }: { data: VulnerabilityRow[]; total: number }) {
  return <DataTable columns={cols} data={data} total={total} />;
}

const affectedCols: ColumnDef<AffectedComponent, unknown>[] = [
  { header: 'Component', cell: ({ row }) => <span className="font-medium">{row.original.component.name}</span> },
  { header: 'Version', cell: ({ row }) => <Chip>{row.original.component.version}</Chip> },
  { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.component.ecosystem} /> },
  {
    header: 'Projects',
    cell: ({ row }) => (
      <span className="flex flex-wrap gap-x-3 gap-y-1">
        {row.original.projects.map((p) => (
          <Link key={p.id} href={`/projects/${p.id}`} className="text-primary hover:underline">
            {p.name}
          </Link>
        ))}
      </span>
    ),
  },
];

export function AffectedTable({ data, total }: { data: AffectedComponent[]; total: number }) {
  return <DataTable columns={affectedCols} data={data} total={total} defaultPageSize={10} />;
}
