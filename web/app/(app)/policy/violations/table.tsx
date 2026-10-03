'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate, titleCase } from '@/lib/format';
import type { Violation } from '@/lib/types';

const cols = (hideProject: boolean): ColumnDef<Violation, unknown>[] => [
  { header: 'Rule', cell: ({ row }) => <span className="font-medium">{row.original.rule_name}</span> },
  { header: 'Category', cell: ({ row }) => <Chip>{titleCase(row.original.category)}</Chip> },
  {
    header: 'Component',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2">
        <Ecosystem name={row.original.component.ecosystem} />
        {row.original.component.name}
        <Chip>{row.original.component.version}</Chip>
      </span>
    ),
  },
  { header: 'Summary', cell: ({ row }) => <span className="line-clamp-2 max-w-md text-sm">{row.original.summary}</span> },
  ...(hideProject
    ? []
    : ([
        {
          header: 'Project',
          cell: ({ row }) =>
            row.original.project ? (
              <Link className="hover:text-primary hover:underline" href={`/projects/${row.original.project.id}`}>
                {row.original.project.name}
              </Link>
            ) : (
              '—'
            ),
        },
        { header: 'Version', cell: ({ row }) => (row.original.version ? <Chip>{row.original.version}</Chip> : '—') },
      ] satisfies ColumnDef<Violation, unknown>[])),
  { header: 'Detected', cell: ({ row }) => fmtDate(row.original.created_at) },
  {
    id: 'scan',
    header: () => <span className="sr-only">Scan</span>,
    cell: ({ row }) =>
      row.original.scan_id ? (
        <Link href={`/scans/${row.original.scan_id}`} className="text-sm font-medium text-primary hover:underline">
          Open Report
        </Link>
      ) : null,
  },
];

export function ViolationsTable({ data, total, hideProject = false }: { data: Violation[]; total: number; hideProject?: boolean }) {
  return <DataTable columns={cols(hideProject)} data={data} total={total} defaultPageSize={hideProject ? 10 : 20} />;
}
