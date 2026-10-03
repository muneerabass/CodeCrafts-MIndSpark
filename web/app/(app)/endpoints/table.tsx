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

// Install guard (depguard CLI) and PMG event types, in plain words.
const EVENT_LABELS: Record<string, string> = {
  'guard.allow': 'Install allowed',
  'guard.warn': 'Install allowed with warnings',
  'guard.block': 'Install blocked',
  'guard.override': 'Install forced (override)',
  'guard.package.block': 'Package blocked',
  'guard.package.warn': 'Package warning',
  'guard.package.allow': 'Package allowed',
};
const eventTone = (t: string) =>
  t.includes('block') ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200' : t.includes('override') ? 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200' : t.includes('warn') ? 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200' : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200';

const pkgEventCols: ColumnDef<PackageEvent, unknown>[] = [
  { header: 'Time', cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
  {
    header: 'Event',
    cell: ({ row }) => <span className={cn('rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap', eventTone(row.original.event_type))}>{EVENT_LABELS[row.original.event_type] ?? titleCase(row.original.event_type)}</span>,
  },
  {
    header: 'Package',
    cell: ({ row }) => {
      const e = row.original;
      const cmd = typeof e.details?.command === 'string' ? e.details.command : null;
      return e.package_name ? (
        <span className="inline-flex items-center gap-1.5 font-medium">
          {e.package_name} {e.version && <Chip>{e.version}</Chip>}
        </span>
      ) : cmd ? (
        <span className="font-mono text-xs">{cmd}</span>
      ) : (
        '—'
      );
    },
  },
  { header: 'Ecosystem', cell: ({ row }) => (row.original.ecosystem ? <Ecosystem name={row.original.ecosystem} /> : '—') },
  {
    header: 'Details',
    cell: ({ row }) => {
      const e = row.original;
      const reason = typeof e.details?.reason === 'string' && e.details.reason ? e.details.reason : null;
      return (
        <span className="block max-w-md text-xs whitespace-normal text-muted-foreground">
          {e.message ?? '—'}
          {reason && <span className="mt-0.5 block text-orange-700 dark:text-orange-300">Reason: {reason}</span>}
        </span>
      );
    },
  },
];
export function PackageEventsTable({ data, total }: { data: PackageEvent[]; total: number }) {
  return <DataTable columns={pkgEventCols} data={data} total={total} empty="No package installs recorded yet. Set up the depguard install guard (Setup → Install Guard) on this machine." />;
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
