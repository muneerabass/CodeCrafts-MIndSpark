'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { AnalysisStatus, Chip, Verification } from '@/components/badges';
import { fmtDate } from '@/lib/format';
import type { PackageAnalysis } from '@/lib/types';

const cols: ColumnDef<PackageAnalysis, unknown>[] = [
  { header: 'Component', cell: ({ row }) => <span className="font-medium">{row.original.component.name}</span> },
  {
    header: 'Project Name',
    cell: ({ row }) => (
      <Link href={`/projects/${row.original.project.id}`} className="hover:text-primary hover:underline">
        {row.original.project.name}
      </Link>
    ),
  },
  { header: 'Project Version', cell: ({ row }) => row.original.version },
  { header: 'Status', cell: ({ row }) => <AnalysisStatus status={row.original.status} /> },
  { header: 'Component Version', cell: ({ row }) => <Chip>{row.original.component.version}</Chip> },
  { header: 'Verification', cell: ({ row }) => <Verification verified={row.original.verified} /> },
  { header: 'Scan Date', cell: ({ row }) => fmtDate(row.original.created_at) },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Link href={`/package-analysis/${row.original.id}`} className="border-l pl-4 text-sm font-medium text-primary hover:underline">
        Open Report
      </Link>
    ),
  },
];

export function AnalysesTable({ data, total }: { data: PackageAnalysis[]; total: number }) {
  return <DataTable columns={cols} data={data} total={total} />;
}
