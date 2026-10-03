import Link from 'next/link';
import { ShieldCheck, Skull } from 'lucide-react';
import { apiOr404 } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import { fmtDateTime } from '@/lib/format';
import { verifyAnalysis } from '@/lib/actions';
import type { PackageAnalysisDetail } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { AnalysisStatus, Chip, Verification } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { ActionButton } from '@/components/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

type Rule = { rule?: string; message?: string; location?: string };

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `Package analysis ${(await params).id}` };
}

export default async function AnalysisReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { role } = await requireOrg();
  const a = await apiOr404<PackageAnalysisDetail>(`/package-analyses/${encodeURIComponent(id)}`);
  const ev = a.evidence as { rules?: Rule[] } | null;
  const rules = Array.isArray(ev?.rules) ? ev.rules : null;

  return (
    <>
      <PageHeader crumbs={[{ label: 'Package Analysis', href: '/package-analysis' }, { label: `${a.component.name}@${a.component.version}` }]} actions={null} />
      <div className="mx-auto w-full max-w-5xl space-y-6 p-4 md:p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="flex flex-wrap items-center gap-2 text-xl font-semibold">
              <Ecosystem name={a.component.ecosystem} /> {a.component.name} <Chip>{a.component.version}</Chip>
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Found in{' '}
              <Link className="text-foreground hover:underline" href={`/projects/${a.project.id}`}>
                {a.project.name}
              </Link>{' '}
              ({a.version}) · analysed {fmtDateTime(a.created_at)}
              {a.scan_id && (
                <>
                  {' '}·{' '}
                  <Link className="text-primary hover:underline" href={`/scans/${a.scan_id}`}>
                    scan report
                  </Link>
                </>
              )}
            </p>
            <div className="mt-3 flex items-center gap-2">
              <AnalysisStatus status={a.status} />
              <Verification verified={a.verified} />
            </div>
          </div>
          {canWrite(role) && (
            <div className="flex gap-2">
              <ActionButton variant="destructive" action={verifyAnalysis.bind(null, a.id, 'malicious')} ok="Marked as malicious" confirm="Mark this package version as malicious? It will fail policy checks in every project.">
                <Skull /> Mark malicious
              </ActionButton>
              <ActionButton variant="outline" action={verifyAnalysis.bind(null, a.id, 'clean')} ok="Marked as clean">
                <ShieldCheck /> Mark clean
              </ActionButton>
            </div>
          )}
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Verdict</CardTitle>
            <CardDescription>
              Source: <span className="font-medium text-foreground">{a.source === 'osv' ? 'Known-malicious advisory (OSV)' : a.source === 'guarddog' ? 'Heuristic analysis (guarddog)' : a.source}</span>
            </CardDescription>
          </CardHeader>
          <CardContent className="text-sm">
            {a.verified ? (
              <p>
                Verified by <span className="font-medium">{a.verified_by ?? 'an administrator'}</span> on {fmtDateTime(a.verified_at)}.
              </p>
            ) : (
              <p className="text-muted-foreground">Not reviewed yet. Owners and admins can confirm or dismiss this verdict.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent>
            {rules ? (
              rules.length ? (
                <ul className="divide-y rounded-md border">
                  {rules.map((r, i) => (
                    <li key={i} className="p-3 text-sm">
                      <p className="font-mono text-xs font-semibold">{r.rule}</p>
                      <p>{r.message}</p>
                      {r.location && <p className="font-mono text-xs text-muted-foreground">{r.location}</p>}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">No heuristic rules matched this package.</p>
              )
            ) : (
              <pre className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{JSON.stringify(a.evidence, null, 2)}</pre>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
