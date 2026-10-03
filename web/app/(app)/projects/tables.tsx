'use client';

import Link from 'next/link';
import { ExternalLink, GitBranch, GitPullRequest, Hexagon, MoreHorizontal, FolderOpen } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, RiskBadge, ScanStatus, ViolationCount, VulnCount, triggerLabel } from '@/components/badges';
import { Ecosystem, GitHubIcon, SourceIcon } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { parseAsInteger, parseAsString, useQueryStates } from 'nuqs';
import { fmtDate } from '@/lib/format';
import type { Project, VersionComponent, VersionScan, VulnRow } from '@/lib/types';

type TableProps<T> = { data: T[]; total: number; empty?: React.ReactNode };

const projectCols: ColumnDef<Project, unknown>[] = [
  { id: 'source', header: () => <GitPullRequest className="size-4" aria-label="Source" />, cell: ({ row }) => <SourceIcon source={row.original.source} /> },
  {
    header: 'Repository Name',
    cell: ({ row }) => (
      <Link href={`/projects/${row.original.id}`} className="font-medium hover:text-primary hover:underline">
        {row.original.name}
      </Link>
    ),
  },
  { header: 'No. of Versions', cell: ({ row }) => <span className="inline-flex items-center gap-1.5"><GitBranch className="size-4 text-muted-foreground" />{row.original.versions}</span> },
  { header: 'No. of Components', cell: ({ row }) => <span className="inline-flex items-center gap-1.5"><Hexagon className="size-4 text-muted-foreground" />{row.original.components}</span> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Created At', cell: ({ row }) => fmtDate(row.original.created_at) },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={`Actions for ${row.original.name}`}>
            <MoreHorizontal />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem asChild>
            <Link href={`/projects/${row.original.id}`}>
              <FolderOpen /> Open project
            </Link>
          </DropdownMenuItem>
          {row.original.url && (
            <DropdownMenuItem asChild>
              <a href={row.original.url} target="_blank" rel="noreferrer">
                <GitHubIcon /> See it on {row.original.source === 'github' ? 'GitHub' : 'source host'} <ExternalLink className="ml-auto" />
              </a>
            </DropdownMenuItem>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
    ),
  },
];

export function ProjectsTable(p: TableProps<Project>) {
  return <DataTable columns={projectCols} {...p} />;
}

const componentCols: ColumnDef<VersionComponent, unknown>[] = [
  { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
  { header: 'Version', cell: ({ row }) => <Chip>{row.original.version}</Chip> },
  { header: 'Classification', cell: ({ row }) => row.original.type || 'Library' },
  { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.ecosystem} /> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Created At', cell: ({ row }) => fmtDate(row.original.created_at) },
  { header: 'Updated At', cell: ({ row }) => fmtDate(row.original.updated_at) },
];
export function VersionComponentsTable(p: TableProps<VersionComponent>) {
  return <DataTable columns={componentCols} defaultPageSize={10} {...p} />;
}

const vulnCols: ColumnDef<VulnRow, unknown>[] = [
  {
    header: 'ID',
    cell: ({ row }) => (
      <Link href={`/vulnerabilities/${encodeURIComponent(row.original.id)}`} className="font-mono text-sm hover:text-primary hover:underline">
        {row.original.id}
      </Link>
    ),
  },
  { header: 'Summary', cell: ({ row }) => <span className="line-clamp-1 max-w-2xl">{row.original.summary}</span> },
  { header: 'Risk', cell: ({ row }) => <RiskBadge risk={row.original.risk} /> },
  { header: 'Published', cell: ({ row }) => fmtDate(row.original.published) },
  { header: 'Modified', cell: ({ row }) => fmtDate(row.original.modified) },
];
export function VersionVulnsTable(p: TableProps<VulnRow>) {
  return <DataTable columns={vulnCols} defaultPageSize={10} {...p} />;
}

const scanCols: ColumnDef<VersionScan, unknown>[] = [
  { header: 'Trigger', cell: ({ row }) => <Chip>{triggerLabel(row.original.trigger)}</Chip> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Scan Date', cell: ({ row }) => fmtDate(row.original.created_at) },
  { header: 'Status', cell: ({ row }) => <ScanStatus status={row.original.status} /> },
  {
    id: 'report',
    header: () => <span className="sr-only">Report</span>,
    cell: ({ row }) => (
      <Link href={`/scans/${row.original.id}`} className="text-sm font-medium text-primary hover:underline">
        Open Report
      </Link>
    ),
  },
];
export function VersionScansTable(p: TableProps<VersionScan>) {
  return <DataTable columns={scanCols} defaultPageSize={10} {...p} />;
}

export function VersionSelect({ versions, value }: { versions: { id: string; name: string }[]; value: string }) {
  const [, set] = useQueryStates({ version: parseAsString, page: parseAsInteger }, { shallow: false });
  return (
    <Select value={value} onValueChange={(v) => set({ version: v, page: null })}>
      <SelectTrigger size="sm" className="min-w-32" aria-label="Branch / version">
        <GitBranch className="size-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent align="end">
        {versions.map((v) => (
          <SelectItem key={v.id} value={v.id}>
            {v.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
