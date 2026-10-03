'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { AnalysisStatus, Chip, RiskBadge, Verification } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate, suspiciousReason } from '@/lib/format';
import type { PackageAnalysis, Violation } from '@/lib/types';

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

const det = (v: Violation, k: string) => (v.details?.[k] == null ? '' : String(v.details[k]));
const suspCols: ColumnDef<Violation, unknown>[] = [
  {
    header: 'Package',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2 font-medium">
        <Ecosystem name={row.original.component.ecosystem} /> {row.original.component.name} <Chip>{row.original.component.version}</Chip>
      </span>
    ),
  },
  { header: 'Rule', cell: ({ row }) => <Chip>{row.original.rule_name}</Chip> },
  { header: 'Severity', cell: ({ row }) => <RiskBadge risk={row.original.severity ?? 'high'} /> },
  { header: 'Reason', cell: ({ row }) => <span className="block max-w-lg text-sm whitespace-normal">{suspiciousReason(row.original.rule_name, row.original.details, row.original.summary)}</span> },
  { header: 'Similar To', cell: ({ row }) => (det(row.original, 'similar_to') ? <span className="font-medium">{det(row.original, 'similar_to')}</span> : '—') },
  {
    header: 'Project',
    cell: ({ row }) =>
      row.original.project ? (
        <Link href={`/projects/${row.original.project.id}`} className="hover:text-primary hover:underline">
          {row.original.project.name}
        </Link>
      ) : (
        '—'
      ),
  },
  { header: 'Detected', cell: ({ row }) => fmtDate(row.original.created_at) },
];

export function SuspiciousTable({ data, total }: { data: Violation[]; total: number }) {
  return <DataTable columns={suspCols} data={data} total={total} empty="No suspicious packages found." />;
}
