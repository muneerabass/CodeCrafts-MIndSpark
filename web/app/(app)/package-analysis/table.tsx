'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Activity, ArrowRight, BadgeCheck, Ban, Bug, Copy, GitBranch, Hourglass, ScanSearch, Sparkles } from 'lucide-react';
import { AnalysisStatus, RiskBadge } from '@/components/badges';
import { EcosystemTile } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { ago, fmtDate, suspiciousReason } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { ComponentRef, PackageAnalysis, ProjectRef, Violation } from '@/lib/types';

function PackageCell({ c }: { c: ComponentRef }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <EcosystemTile name={c.ecosystem} />
      <span className="min-w-0">
        <span className="block font-semibold">{c.name}</span>
        <span className="block font-mono text-xs text-muted-foreground">{c.version}</span>
      </span>
    </span>
  );
}

function ProjectCell({ project, version }: { project?: ProjectRef | null; version?: string }) {
  if (!project) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="min-w-0">
      <Link href={`/projects/${project.id}`} className="block font-medium hover:text-primary hover:underline">
        {project.name}
      </Link>
      {version && (
        <span className="inline-flex items-center gap-1 font-mono text-xs text-muted-foreground">
          <GitBranch className="size-3" aria-hidden />
          {version}
        </span>
      )}
    </span>
  );
}

function When({ at }: { at: string }) {
  return (
    <span className="text-sm whitespace-nowrap text-muted-foreground" title={fmtDate(at)} suppressHydrationWarning>
      {ago(at)}
    </span>
  );
}

const cols: ColumnDef<PackageAnalysis, unknown>[] = [
  { header: 'Package', cell: ({ row }) => <PackageCell c={row.original.component} /> },
  {
    header: 'Verdict',
    cell: ({ row }) => (
      <span className="inline-flex flex-col items-start gap-1">
        <AnalysisStatus status={row.original.status} />
        <span className={cn('inline-flex items-center gap-1 text-[11px]', row.original.verified ? 'text-primary' : 'text-muted-foreground')}>
          {row.original.verified && <BadgeCheck className="size-3" aria-hidden />}
          {row.original.verified ? 'Verified' : 'Unverified'}
        </span>
      </span>
    ),
  },
  { header: 'Project', cell: ({ row }) => <ProjectCell project={row.original.project} version={row.original.version} /> },
  { header: 'Scanned', cell: ({ row }) => <When at={row.original.created_at} /> },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Button asChild variant="outline" size="sm" className="h-8">
        <Link href={`/package-analysis/${row.original.id}`}>
          Open Report <ArrowRight className="size-3.5" aria-hidden />
        </Link>
      </Button>
    ),
  },
];

export function AnalysesTable({ data, total }: { data: PackageAnalysis[]; total: number }) {
  return <DataTable columns={cols} data={data} total={total} empty="No packages analysed yet." />;
}

const ruleIcon: Record<string, typeof Bug> = {
  typosquat: Copy,
  unmaintained: Hourglass,
  deprecated: Ban,
  'new-package': Sparkles,
  'no-source-repo': GitBranch,
  'unusual-behaviour': Activity,
};
const det = (v: Violation, k: string) => (v.details?.[k] == null ? '' : String(v.details[k]));
const suspCols: ColumnDef<Violation, unknown>[] = [
  { header: 'Package', cell: ({ row }) => <PackageCell c={row.original.component} /> },
  {
    header: 'Finding',
    cell: ({ row }) => {
      const v = row.original;
      const Icon = ruleIcon[v.rule_name] ?? ScanSearch;
      const like = det(v, 'similar_to');
      return (
        <div className="max-w-lg space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-md bg-muted px-1.5 py-0.5 text-xs font-medium">
              <Icon className="size-3.5" aria-hidden />
              {v.rule_name}
            </span>
            {like && (
              <span className="inline-flex items-center gap-1 rounded-md bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-700 ring-1 ring-amber-500/25 dark:text-amber-300">
                Looks like <span className="font-semibold">{like}</span>
              </span>
            )}
          </div>
          <p className="line-clamp-2 text-sm whitespace-normal text-muted-foreground">{suspiciousReason(v.rule_name, v.details, v.summary)}</p>
        </div>
      );
    },
  },
  {
    header: 'Severity',
    cell: ({ row }) => (
      <span className="inline-flex flex-col items-start gap-1">
        <RiskBadge risk={row.original.severity ?? 'high'} />
        <span className="text-[11px] text-muted-foreground">{row.original.blocking === false ? 'Report only' : 'Blocks'}</span>
      </span>
    ),
  },
  { header: 'Project', cell: ({ row }) => <ProjectCell project={row.original.project} version={row.original.version} /> },
  { header: 'Detected', cell: ({ row }) => <When at={row.original.created_at} /> },
];

export function SuspiciousTable({ data, total }: { data: Violation[]; total: number }) {
  return <DataTable columns={suspCols} data={data} total={total} empty="No suspicious packages found." />;
}
