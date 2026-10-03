import { api, listQuery, type SearchParams } from '@/lib/api';
import type { List, VulnerabilityRow } from '@/lib/types';
import { AlarmClock, CircleAlert, Flame, Info, TriangleAlert } from 'lucide-react';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { FilterBar } from '@/components/data-table';
import { VulnerabilitiesTable } from './table';

export const metadata = { title: 'Vulnerabilities' };

export default async function VulnerabilitiesPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const count = (risk: string) => api<List<VulnerabilityRow>>('/vulnerabilities', { query: { risk, page_size: 10 } }).then((l) => l.total);
  const [data, critical, high, medium, low, overdue] = await Promise.all([
    api<List<VulnerabilityRow>>('/vulnerabilities', { query: listQuery(sp, ['risk', 'id', 'from', 'to', 'overdue']) }),
    count('CRITICAL'),
    count('HIGH'),
    count('MEDIUM'),
    count('LOW'),
    api<List<VulnerabilityRow>>('/vulnerabilities', { query: { overdue: 1, page_size: 10 } }).then((l) => l.total),
  ]);
  const tile = (risk: string, label: string, value: number, tone: StatTile['tone'], icon: StatTile['icon']): StatTile => ({
    label,
    value,
    icon,
    tone,
    href: sp.risk === risk ? '/vulnerabilities' : `/vulnerabilities?risk=${risk}`,
    active: sp.risk === risk,
  });
  const tiles: StatTile[] = [
    tile('CRITICAL', 'Critical', critical, 'red', Flame),
    tile('HIGH', 'High', high, 'orange', TriangleAlert),
    tile('MEDIUM', 'Medium', medium, 'amber', CircleAlert),
    tile('LOW', 'Low', low, 'sky', Info),
    { label: 'Past fix deadline', value: overdue, icon: AlarmClock, tone: 'red', href: sp.overdue === '1' ? '/vulnerabilities' : '/vulnerabilities?overdue=1', active: sp.overdue === '1' },
  ];
  return (
    <>
      <PageHeader crumbs={[{ label: 'Vulnerabilities' }]} info="Known advisories (OSV, GitHub, CVE) that affect at least one component in your projects." actions={null} />
      <PageIntro title="Vulnerabilities" description="Known advisories affecting at least one package in your projects, most severe first, with the deadline to fix each one." />
      <StatTiles label="Vulnerabilities by risk" tiles={tiles} />
      <FilterBar
        filters={[
          {
            type: 'select',
            key: 'risk',
            label: 'Risk',
            options: [
              { value: 'CRITICAL', label: 'Critical' },
              { value: 'HIGH', label: 'High' },
              { value: 'MEDIUM', label: 'Medium' },
              { value: 'LOW', label: 'Low' },
            ],
          },
          { type: 'text', key: 'id', label: 'Vulnerability ID', placeholder: 'GHSA-…, CVE-…, MAL-…' },
          { type: 'daterange' },
        ]}
      />
      <VulnerabilitiesTable data={data.items} total={data.total} />
    </>
  );
}
