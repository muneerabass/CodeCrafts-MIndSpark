'use client';

import { ExternalLink, FolderGit2, MoreHorizontal } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import Link from 'next/link';
import { DependencyBadge, HealthBadge, ViolationCount, VulnCount } from '@/components/badges';
import { EcosystemTile } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { fmtDate } from '@/lib/format';
import type { ComponentRow } from '@/lib/types';

const depsDevSystem: Record<string, string> = { npm: 'npm', PyPI: 'pypi', Go: 'go', Maven: 'maven', 'crates.io': 'cargo', NuGet: 'nuget' };

function Status({ c }: { c: ComponentRow }) {
  const st = c.vulns
    ? { label: 'Vulnerable', cls: 'text-red-700 dark:text-red-300 bg-red-500/10 ring-red-500/25', dot: 'bg-red-500' }
    : c.violations
      ? { label: 'Policy issue', cls: 'text-amber-700 dark:text-amber-300 bg-amber-500/10 ring-amber-500/25', dot: 'bg-amber-500' }
      : { label: 'OK', cls: 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 ring-emerald-500/25', dot: 'bg-emerald-500' };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ${st.cls}`}>
      <span className={`size-1.5 rounded-full ${st.dot}`} aria-hidden />
      {st.label}
    </span>
  );
}

const cols: ColumnDef<ComponentRow, unknown>[] = [
  {
    header: 'Component',
    cell: ({ row }) => {
      const c = row.original;
      return (
        <div className="flex items-center gap-3">
          <EcosystemTile name={c.ecosystem} />
          <div className="min-w-0">
            <Link href={`/components/${encodeURIComponent(c.id)}`} className="block truncate font-semibold hover:text-primary hover:underline">
              {c.name}
            </Link>
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span className="font-mono">{c.version}</span>
              <span aria-hidden>·</span>
              <span>{c.ecosystem}</span>
            </div>
          </div>
        </div>
      );
    },
  },
  { header: 'Status', cell: ({ row }) => <Status c={row.original} /> },
  { header: 'Health', cell: ({ row }) => <HealthBadge h={row.original.health} /> },
  { header: 'Dependency', cell: ({ row }) => <DependencyBadge {...row.original} /> },
  {
    header: 'Projects',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-1.5 tabular-nums">
        <FolderGit2 className="size-4 text-muted-foreground" aria-hidden />
        {row.original.projects}
      </span>
    ),
  },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Last Updated', cell: ({ row }) => <span className="text-muted-foreground">{fmtDate(row.original.updated_at)}</span> },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => {
      const c = row.original;
      const sys = depsDevSystem[c.ecosystem];
      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label={`Actions for ${c.name}`}>
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem asChild>
              <a href={`https://osv.dev/list?q=${encodeURIComponent(c.name)}&ecosystem=${encodeURIComponent(c.ecosystem)}`} target="_blank" rel="noreferrer">
                Search advisories on OSV <ExternalLink className="ml-auto" />
              </a>
            </DropdownMenuItem>
            {sys && (
              <DropdownMenuItem asChild>
                <a href={`https://deps.dev/${sys}/${encodeURIComponent(c.name)}/${encodeURIComponent(c.version)}`} target="_blank" rel="noreferrer">
                  View on deps.dev <ExternalLink className="ml-auto" />
                </a>
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      );
    },
  },
];

export function ComponentsTable({ data, total }: { data: ComponentRow[]; total: number }) {
  return <DataTable columns={cols} data={data} total={total} />;
}
