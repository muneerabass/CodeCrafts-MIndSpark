import Link from 'next/link';
import { Activity, ArrowRight, Bot, ChevronRight, Eye, ExternalLink, History, Monitor, ShieldCheck, SquareTerminal } from 'lucide-react';
import { api, listQuery, type SearchParams } from '@/lib/api';
import type { Endpoint, List } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { Button } from '@/components/ui/button';
import { EndpointsTable } from './table';

export const metadata = { title: 'Endpoints' };

const steps = [
  { icon: SquareTerminal, title: 'Run the depguard agent or PMG', text: 'depguard agent, or PMG guarding package installs' },
  { icon: ShieldCheck, title: 'It reports to depguard', text: 'AI tool inventory, package installs, agent activity' },
  { icon: Activity, title: 'The endpoint shows up here', text: 'With its live inventory and event history' },
];

const kinds = [
  ['Coding agent', 'bg-indigo-50 text-indigo-700'],
  ['MCP server', 'bg-violet-50 text-violet-700'],
  ['Agent skill', 'bg-pink-50 text-pink-700'],
  ['IDE extension', 'bg-sky-50 text-sky-700'],
];

export default async function EndpointsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const data = await api<List<Endpoint>>('/endpoints', { query: listQuery(sp, []) });
  const header = <PageHeader crumbs={[{ label: 'Endpoints' }]} info="Developer laptops, CI runners and agent sandboxes that report to depguard through the depguard agent or PMG." actions={null} />;

  if (!data.total) {
    return (
      <>
        {header}
        <EmptyState icon={Monitor} title="No Endpoints yet" className="max-w-3xl py-16">
          <p>An endpoint is any machine that builds or writes code — a laptop, a CI runner, an AI agent sandbox. Once it runs depguard tooling, it checks in here.</p>
          <ol className="mt-6 grid gap-2 rounded-xl border border-dashed bg-muted/30 p-4 sm:grid-cols-[1fr_auto_1fr_auto_1fr]">
            {steps.map((s, i) => (
              <li key={s.title} className="contents">
                {i > 0 && <ChevronRight className="hidden size-4 self-center text-muted-foreground sm:block" aria-hidden />}
                <div className="flex flex-col items-center gap-1 p-2">
                  <span className="flex size-10 items-center justify-center rounded-lg border bg-background">
                    <s.icon className="size-5" aria-hidden />
                  </span>
                  <span className="font-medium text-foreground">{s.title}</span>
                  <span className="text-xs">{s.text}</span>
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-6 text-xs font-semibold tracking-wide uppercase">Each endpoint reports</p>
          <ul className="mt-2 flex flex-wrap justify-center gap-2">
            {kinds.map(([label, cls]) => (
              <li key={label} className={`rounded-md px-2 py-1 text-xs font-medium ${cls}`}>
                {label}
              </li>
            ))}
          </ul>
          <p className="mt-6 text-left text-xs font-semibold tracking-wide uppercase">What you can do with it</p>
          <ul className="mt-2 space-y-2 text-left">
            <li className="flex gap-2"><Eye className="size-4 shrink-0" aria-hidden /> Know which AI coding agents, MCP servers and extensions run on each machine.</li>
            <li className="flex gap-2"><Bot className="size-4 shrink-0" aria-hidden /> Audit the commands and package installs your coding agents performed.</li>
            <li className="flex gap-2"><History className="size-4 shrink-0" aria-hidden /> Follow package installs across machines and see which ones PMG blocked.</li>
          </ul>
          <div className="mt-6 flex flex-col items-center gap-3">
            <Button asChild>
              <Link href="/setup/guides/ai-tools">
                Set up Endpoint Hub <ArrowRight />
              </Link>
            </Button>
            <Link href="/setup/guides/pmg" className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
              Read the PMG quickstart <ExternalLink className="size-3.5" aria-hidden />
            </Link>
          </div>
        </EmptyState>
      </>
    );
  }

  return (
    <>
      {header}
      <EndpointsTable data={data.items} total={data.total} />
    </>
  );
}
