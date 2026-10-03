import Link from 'next/link';
import { ArrowRight, Bug, FileChartLine, Filter, History, Scale, ShieldCheck, Skull, TrendingUp, Wrench, ExternalLink } from 'lucide-react';
import { api, listQuery, type SearchParams } from '@/lib/api';
import type { List, Project, Violation } from '@/lib/types';
import { EmptyState, PageHeader } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { ViolationsTable } from './table';
import { SEVERITY_OPTIONS } from '@/lib/format';

export const metadata = { title: 'Policy Violations' };

const KEYS = ['rule', 'category', 'severity', 'project_id', 'version'];

export default async function ViolationsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const q = listQuery(sp, KEYS);
  const [data, projects] = await Promise.all([
    api<List<Violation>>('/policy/violations', { query: q }),
    api<List<Project>>('/projects', { query: { page_size: 50 } }),
  ]);
  const filtered = KEYS.some((k) => q[k]);
  const header = <PageHeader crumbs={[{ label: 'Policy', href: '/policy' }, { label: 'Violations' }]} info="Packages that broke a rule in your policy, with the rule, project and scan that caught them." actions={null} />;

  if (!data.total && !filtered) {
    return (
      <>
        {header}
        <EmptyState icon={FileChartLine} title="No Policy Violations yet" className="py-20">
          <p>Your policy defines which dependencies are acceptable. When a scanned package fails one of its rules, it is listed here along with the rule it failed.</p>
          <p className="mt-6 text-xs font-semibold tracking-wide uppercase">Rules can look at</p>
          <ul className="mt-2 flex flex-wrap justify-center gap-2">
            {[
              [Bug, 'Vulnerability'],
              [Skull, 'Malware'],
              [Scale, 'License'],
              [TrendingUp, 'Popularity'],
              [Wrench, 'Maintenance'],
            ].map(([Icon, label]) => {
              const I = Icon as typeof Bug;
              return (
                <li key={label as string} className="inline-flex items-center gap-1 rounded-md bg-accent px-2 py-1 text-xs font-medium text-accent-foreground">
                  <I className="size-3.5" aria-hidden /> {label as string}
                </li>
              );
            })}
          </ul>
          <p className="mt-6 text-left text-xs font-semibold tracking-wide uppercase">What you can do with it</p>
          <ul className="mt-2 space-y-2 text-left">
            <li className="flex gap-2"><ShieldCheck className="size-4 shrink-0" aria-hidden /> Fail pull requests and CI jobs that introduce risky packages.</li>
            <li className="flex gap-2"><Filter className="size-4 shrink-0" aria-hidden /> Narrow violations by rule, project or branch to decide what to fix first.</li>
            <li className="flex gap-2"><History className="size-4 shrink-0" aria-hidden /> See which scan first reported each violation, and when.</li>
          </ul>
          <div className="mt-6 flex flex-col items-center gap-3">
            <Button asChild>
              <Link href="/setup/integrations">
                Connect your repos <ArrowRight />
              </Link>
            </Button>
            <Link href="/policy" className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline">
              Learn how to write a policy <ExternalLink className="size-3.5" />
            </Link>
          </div>
        </EmptyState>
      </>
    );
  }

  return (
    <>
      {header}
      <FilterBar
        filters={[
          { type: 'text', key: 'rule', label: 'Rule' },
          { type: 'select', key: 'category', label: 'Category', options: ['vulnerability', 'malware', 'license', 'suspicious', 'popularity', 'maintenance', 'custom'].map((v) => ({ value: v, label: v[0].toUpperCase() + v.slice(1) })) },
          { type: 'select', key: 'severity', label: 'Severity', options: SEVERITY_OPTIONS },
          { type: 'select', key: 'project_id', label: 'Project', options: projects.items.map((p) => ({ value: p.id, label: p.name })) },
          { type: 'text', key: 'version', label: 'Version', placeholder: 'Branch' },
        ]}
      />
      <ViolationsTable data={data.items} total={data.total} />
    </>
  );
}
