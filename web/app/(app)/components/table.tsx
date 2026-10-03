'use client';

import { ExternalLink, FolderGit2, MoreHorizontal } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, DependencyBadge, ViolationCount, VulnCount } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { fmtDate } from '@/lib/format';
import type { ComponentRow } from '@/lib/types';

const depsDevSystem: Record<string, string> = { npm: 'npm', PyPI: 'pypi', Go: 'go', Maven: 'maven', 'crates.io': 'cargo', NuGet: 'nuget' };

const cols: ColumnDef<ComponentRow, unknown>[] = [
  { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
  { header: 'Projects', cell: ({ row }) => <span className="inline-flex items-center gap-1.5"><FolderGit2 className="size-4 text-muted-foreground" aria-hidden />{row.original.projects}</span> },
  { header: 'Version', cell: ({ row }) => <Chip>{row.original.version}</Chip> },
  { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.ecosystem} /> },
  { header: 'Type', cell: ({ row }) => row.original.type || 'Library' },
  { header: 'Dependency', cell: ({ row }) => <DependencyBadge {...row.original} /> },
  { header: 'Policy Violations', cell: ({ row }) => <ViolationCount n={row.original.violations} /> },
  { header: 'Vulnerabilities', cell: ({ row }) => <VulnCount n={row.original.vulns} /> },
  { header: 'Last Updated', cell: ({ row }) => fmtDate(row.original.updated_at) },
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
