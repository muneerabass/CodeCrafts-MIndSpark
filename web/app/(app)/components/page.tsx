import { api, listQuery, type SearchParams } from '@/lib/api';
import { DIRECT_OPTIONS, ECOSYSTEMS } from '@/lib/format';
import type { ComponentRow, List } from '@/lib/types';
import { Bug, FileChartLine, GitCommitVertical, Hexagon } from 'lucide-react';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { ComponentsTable } from './table';

export const metadata = { title: 'Components' };

export default async function ComponentsPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const count = (q: Record<string, string>) => api<List<ComponentRow>>('/components', { query: { ...q, page_size: 10 } }).then((l) => l.total);
  const [data, total, withVulns, withViolations, direct] = await Promise.all([
    api<List<ComponentRow>>('/components', { query: listQuery(sp, ['name', 'version', 'ecosystem', 'from', 'to', 'has_vulns', 'has_violations', 'direct']) }),
    count({}),
    count({ has_vulns: 'true' }),
    count({ has_violations: 'true' }),
    count({ direct: 'true' }),
  ]);
  const share = (n: number) => (total ? n / total : 0);
  const none = !sp.has_vulns && !sp.has_violations && !sp.direct;
  const tiles: StatTile[] = [
    { label: 'Components', value: total, icon: Hexagon, href: '/components', active: none, tone: 'primary' },
    { label: 'With vulnerabilities', value: withVulns, icon: Bug, href: '/components?has_vulns=true', active: sp.has_vulns === 'true', tone: 'red', share: share(withVulns) },
    {
      label: 'With policy violations',
      value: withViolations,
      icon: FileChartLine,
      href: '/components?has_violations=true',
      active: sp.has_violations === 'true',
      tone: 'amber',
      share: share(withViolations),
    },
    { label: 'Direct dependencies', value: direct, icon: GitCommitVertical, href: '/components?direct=true', active: sp.direct === 'true', tone: 'sky', share: share(direct) },
  ];
  return (
    <>
      <PageHeader crumbs={[{ label: 'Components' }]} info="Every open source package found across all projects, one row per name and version." actions={null} />
      <PageIntro title="Components" description="Every open source package across your projects, one row per name and version." />
      <StatTiles label="Component summary" tiles={tiles} />
      <FilterBar
        filters={[
          { type: 'text', key: 'name', label: 'Name', placeholder: 'Package name' },
          { type: 'text', key: 'version', label: 'Version' },
          { type: 'select', key: 'ecosystem', label: 'Ecosystem', options: ECOSYSTEMS },
          { type: 'select', key: 'direct', label: 'Dependency', options: DIRECT_OPTIONS },
          { type: 'daterange' },
          { type: 'toggle', key: 'has_vulns', label: 'Has Vulnerabilities' },
          { type: 'toggle', key: 'has_violations', label: 'Has Policy Violations' },
        ]}
      />
      <ComponentsTable data={data.items} total={data.total} />
    </>
  );
}
