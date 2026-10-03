import Link from 'next/link';
import { api, apiOr404, listQuery, one, type SearchParams } from '@/lib/api';
import { fmtDateTime, titleCase } from '@/lib/format';
import type { AgentEvent, Endpoint, InventoryItem, List, PackageEvent } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { Chip } from '@/components/badges';
import { cn } from '@/lib/utils';
import { AgentEventsTable, InventoryTable, PackageEventsTable } from '../table';

const TABS = [
  { key: 'inventory', label: 'Inventory' },
  { key: 'package-events', label: 'Package Events' },
  { key: 'agent-events', label: 'Agent Activity' },
] as const;

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `Endpoint ${(await params).id}` };
}

export default async function EndpointPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: SearchParams }) {
  const { id } = await params;
  const sp = await searchParams;
  const tab = TABS.find((t) => t.key === one(sp.tab))?.key ?? 'inventory';
  const base = `/endpoints/${encodeURIComponent(id)}`;
  const e = await apiOr404<Endpoint>(base);
  const q = listQuery(sp, []);

  return (
    <>
      <PageHeader crumbs={[{ label: 'Endpoints', href: '/endpoints' }, { label: e.identifier }]} actions={null} />
      <div className="border-b bg-muted/30 px-6 py-5">
        <h1 className="text-xl font-semibold">{e.identifier}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
          <Chip>{titleCase(e.endpoint_type)}</Chip>
          <span className="font-mono text-xs">{e.hostname}</span>
          <span>· {titleCase(e.os)}</span>
          <span>· last sync {fmtDateTime(e.last_sync_at)}</span>
        </div>
      </div>
      <nav className="flex gap-1 border-b px-4 py-2" aria-label="Endpoint sections">
        <div className="flex gap-1 rounded-lg bg-muted p-1">
          {TABS.map((t) => (
            <Link
              key={t.key}
              href={`?tab=${t.key}`}
              aria-current={t.key === tab ? 'page' : undefined}
              className={cn('rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground', t.key === tab && 'bg-background font-medium text-foreground shadow-xs')}
            >
              {t.label}
            </Link>
          ))}
        </div>
      </nav>
      {tab === 'inventory' && <Inventory base={base} q={q} />}
      {tab === 'package-events' && <PackageEvents base={base} q={q} />}
      {tab === 'agent-events' && <AgentEvents base={base} q={q} />}
    </>
  );
}

async function Inventory({ base, q }: { base: string; q: Record<string, string> }) {
  const d = await api<List<InventoryItem>>(`${base}/inventory`, { query: q });
  return <InventoryTable data={d.items} total={d.total} />;
}
async function PackageEvents({ base, q }: { base: string; q: Record<string, string> }) {
  const d = await api<List<PackageEvent>>(`${base}/package-events`, { query: q });
  return <PackageEventsTable data={d.items} total={d.total} />;
}
async function AgentEvents({ base, q }: { base: string; q: Record<string, string> }) {
  const d = await api<List<AgentEvent>>(`${base}/agent-events`, { query: q });
  return <AgentEventsTable data={d.items} total={d.total} />;
}
