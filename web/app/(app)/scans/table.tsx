'use client';

import Link from 'next/link';
import { Check, GitBranch, X } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, RiskBadge, ScanStatus, ViolationCount, VulnCount, triggerLabel } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate } from '@/lib/format';
import type { ScanPackage, ScanRow } from '@/lib/types';

const cols: ColumnDef<ScanRow, unknown>[] = [
  {
    header: 'Scanned Project',
    cell: ({ row }) => (
      <Link href={`/projects/${row.original.project.id}`} className="inline-flex items-center gap-2 font-medium hover:text-primary hover:underline">
        <GitBranch className="size-4 text-muted-foreground" aria-hidden /> {row.original.project.name}
      </Link>
    ),
  },
  { header: 'Project Version', cell: ({ row }) => <Chip>{row.original.version}</Chip> },
  { header: 'Trigger', cell: ({ row }) => <Chip>{triggerLabel(row.original.trigger)}</Chip> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Scan Date', cell: ({ row }) => fmtDate(row.original.created_at) },
  { header: 'Status', cell: ({ row }) => <ScanStatus status={row.original.status} /> },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Link href={`/scans/${row.original.id}`} className="border-l pl-4 text-sm font-medium text-primary hover:underline">
        Open Report
      </Link>
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
        {row.original.violations.map((v) => (
          <li key={v.rule_name} className="text-xs text-amber-700">
            {v.rule_name}: {v.summary}
          </li>
        ))}
        {!row.original.vulns.length && !row.original.violations.length && <li className="text-xs text-muted-foreground">—</li>}
      </ul>
    ),
  },
];

export function ScanPackagesTable({ data }: { data: ScanPackage[] }) {
  return <DataTable columns={pkgCols} data={data} empty="No package changes in this scan." />;
}
