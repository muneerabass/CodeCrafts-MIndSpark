import { ExternalLink, Siren } from 'lucide-react';
import { api, apiOr404, listQuery, type SearchParams } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AffectedComponent, List, VulnerabilityDetail } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { Chip, RiskBadge } from '@/components/badges';
import { Markdown } from '@/components/markdown';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { AffectedTable } from '../table';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: decodeURIComponent((await params).id) };
}

export default async function VulnerabilityPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: SearchParams }) {
  const id = decodeURIComponent((await params).id);
  const sp = await searchParams;
  const path = `/vulnerabilities/${encodeURIComponent(id)}`;
  const [v, affected] = await Promise.all([apiOr404<VulnerabilityDetail>(path), api<List<AffectedComponent>>(`${path}/components`, { query: listQuery(sp, [], 10) })]);

  return (
    <>
      <PageHeader crumbs={[{ label: 'Vulnerabilities', href: '/vulnerabilities' }, { label: v.id }]} actions={null} />
      <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="font-mono text-xl font-semibold">{v.id}</h1>
            <RiskBadge risk={v.risk} />
            {v.kev && (
              <span className="inline-flex items-center gap-1 rounded-md bg-red-600 px-1.5 py-0.5 text-xs font-semibold text-white" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
                <Siren className="size-3.5" aria-hidden /> Known exploited
              </span>
            )}
            <a href={`https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm text-primary hover:underline">
              osv.dev <ExternalLink className="size-3.5" aria-hidden />
            </a>
          </div>
          <p className="mt-2 text-muted-foreground">{v.summary}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <Card className="md:col-span-2">
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent>
              <Markdown>{v.details || v.summary}</Markdown>
            </CardContent>
          </Card>
          <Card>
            <CardContent>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
                <dt className="text-muted-foreground">Published</dt>
                <dd>{fmtDate(v.published)}</dd>
                <dt className="text-muted-foreground">Modified</dt>
                <dd>{fmtDate(v.modified)}</dd>
                <dt className="text-muted-foreground">EPSS</dt>
                <dd>{v.epss != null ? `${(v.epss * 100).toFixed(2)}%` : '—'}</dd>
                <dt className="text-muted-foreground">Aliases</dt>
                <dd className="flex flex-wrap gap-1">{v.aliases?.length ? v.aliases.map((a) => <Chip key={a}>{a}</Chip>) : '—'}</dd>
                {v.severity?.map((s) => (
                  <div key={s.score} className="contents">
                    <dt className="text-muted-foreground">{s.type}</dt>
                    <dd className="font-mono text-xs break-all">{s.score}</dd>
                  </div>
                ))}
              </dl>
              {!!v.references?.length && (
                <ul className="mt-4 space-y-1 border-t pt-3 text-sm">
                  {v.references.slice(0, 8).map((r) => (
                    <li key={r.url} className="truncate">
                      <a href={r.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                        {r.url}
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="gap-0 overflow-hidden py-0">
          <CardHeader className="border-b py-4">
            <CardTitle>Affected components</CardTitle>
          </CardHeader>
          <AffectedTable data={affected.items} total={affected.total} />
        </Card>
      </div>
    </>
  );
}
