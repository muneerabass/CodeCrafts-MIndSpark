'use client';

import Link from 'next/link';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { fmtDate, fmtDateTime, titleCase } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { AgentEvent, Endpoint, InventoryItem, PackageEvent } from '@/lib/types';

const kindStyle: Record<string, string> = {
  coding_agent: 'bg-indigo-50 text-indigo-700',
  mcp_server: 'bg-violet-50 text-violet-700',
  agent_skill: 'bg-pink-50 text-pink-700',
  ide_extension: 'bg-sky-50 text-sky-700',
};

const endpointCols: ColumnDef<Endpoint, unknown>[] = [
  {
    header: 'Endpoint',
    cell: ({ row }) => (
      <Link href={`/endpoints/${row.original.id}`} className="font-medium hover:text-primary hover:underline">
        {row.original.identifier}
      </Link>
    ),
  },
  { header: 'Type', cell: ({ row }) => <Chip>{titleCase(row.original.endpoint_type)}</Chip> },
  { header: 'Hostname', cell: ({ row }) => <span className="font-mono text-xs">{row.original.hostname}</span> },
  { header: 'OS', cell: ({ row }) => titleCase(row.original.os) },
  { header: 'Inventory', cell: ({ row }) => row.original.inventory_count },
  { header: 'Last Sync', cell: ({ row }) => fmtDateTime(row.original.last_sync_at) },
  { header: 'Created At', cell: ({ row }) => fmtDate(row.original.created_at) },
];
export function EndpointsTable({ data, total }: { data: Endpoint[]; total: number }) {
  return <DataTable columns={endpointCols} data={data} total={total} />;
}

const inventoryCols: ColumnDef<InventoryItem, unknown>[] = [
  { header: 'Kind', cell: ({ row }) => <span className={cn('rounded-md px-1.5 py-0.5 text-xs font-medium', kindStyle[row.original.kind] ?? 'bg-muted')}>{titleCase(row.original.kind)}</span> },
  { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
  { header: 'Version', cell: ({ row }) => (row.original.version ? <Chip>{row.original.version}</Chip> : '—') },
  { header: 'Scope', cell: ({ row }) => titleCase(row.original.scope || '—') },
  { header: 'Config Path', cell: ({ row }) => <span className="font-mono text-xs">{row.original.config_path}</span> },
  { header: 'Updated At', cell: ({ row }) => fmtDateTime(row.original.last_seen) },
];
export function InventoryTable({ data, total }: { data: InventoryItem[]; total: number }) {
  return <DataTable columns={inventoryCols} data={data} total={total} empty="No AI tools, MCP servers, skills or extensions reported yet." />;
}

const pkgEventCols: ColumnDef<PackageEvent, unknown>[] = [
  { header: 'Time', cell: ({ row }) => fmtDateTime(row.original.ts) },
  { header: 'Event', cell: ({ row }) => <span className={cn('text-sm font-medium', row.original.event_type.includes('block') && 'text-red-600')}>{titleCase(row.original.event_type)}</span> },
  { header: 'Package', cell: ({ row }) => <span className="font-medium">{row.original.package_name}</span> },
  { header: 'Version', cell: ({ row }) => <Chip>{row.original.version}</Chip> },
  { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.ecosystem} /> },
];
export function PackageEventsTable({ data, total }: { data: PackageEvent[]; total: number }) {
  return <DataTable columns={pkgEventCols} data={data} total={total} empty="No package installs recorded. Install PMG on this machine to see them." />;
}

const agentEventCols: ColumnDef<AgentEvent, unknown>[] = [
  { header: 'Time', cell: ({ row }) => fmtDateTime(row.original.ts) },
  { header: 'Agent', cell: ({ row }) => <span className="font-medium">{row.original.agent_name}</span> },
  { header: 'Action', cell: ({ row }) => titleCase(row.original.action_type) },
  { header: 'Tool', cell: ({ row }) => <span className="block max-w-md truncate font-mono text-xs">{row.original.tool_name ?? '—'}</span> },
  { header: 'Result', cell: ({ row }) => titleCase(row.original.result_status) },
];
export function AgentEventsTable({ data, total }: { data: AgentEvent[]; total: number }) {
  return <DataTable columns={agentEventCols} data={data} total={total} empty="No coding-agent activity recorded for this endpoint." />;
}
