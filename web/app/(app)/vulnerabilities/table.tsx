'use client';

import Link from 'next/link';
import { ExternalLink, FolderGit2, Hexagon } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, RiskBadge } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate } from '@/lib/format';
import type { AffectedComponent, VulnerabilityRow } from '@/lib/types';

const cols: ColumnDef<VulnerabilityRow, unknown>[] = [
  {
    header: 'ID',
    cell: ({ row }) => (
      <a
        href={`https://osv.dev/vulnerability/${encodeURIComponent(row.original.id)}`}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-2 font-mono text-sm whitespace-nowrap hover:text-primary hover:underline"
        aria-label={`${row.original.id} on osv.dev (opens in a new tab)`}
      >
        <ExternalLink className="size-4" aria-hidden /> {row.original.id}
      </a>
    ),
  },
  {
    header: 'Summary',
    cell: ({ row }) => (
      <span className="block max-w-[18rem] truncate" title={row.original.summary}>
        {row.original.summary}
      </span>
    ),
  },
  { header: 'Risk', cell: ({ row }) => <RiskBadge risk={row.original.risk} /> },
  { header: 'Affected Components', cell: ({ row }) => <span className="inline-flex items-center gap-1.5"><Hexagon className="size-4 text-muted-foreground" aria-hidden />{row.original.affected_components}</span> },
  { header: 'Affected Projects', cell: ({ row }) => <span className="inline-flex items-center gap-1.5"><FolderGit2 className="size-4 text-muted-foreground" aria-hidden />{row.original.affected_projects}</span> },
  { header: 'Published', cell: ({ row }) => fmtDate(row.original.published) },
  { header: 'Modified', cell: ({ row }) => fmtDate(row.original.modified) },
  {
    id: 'affected',
    header: () => <span className="sr-only">Affected components</span>,
    cell: ({ row }) => (
      <Link href={`/vulnerabilities/${encodeURIComponent(row.original.id)}`} className="border-l pl-4 text-sm font-medium whitespace-nowrap text-primary hover:underline">
        View Affected Components
      </Link>
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
