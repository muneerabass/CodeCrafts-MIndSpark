import Link from 'next/link';
import { AlertTriangle, Bug, FileChartLine, Hexagon, ShieldAlert, Skull } from 'lucide-react';
import { api, apiOr404 } from '@/lib/api';
import { fmtDateTime, suspiciousReason } from '@/lib/format';
import type { Finding, PathItem, ScanDetail } from '@/lib/types';
import { Breadcrumbs } from '@/components/paths';
import { Ecosystem } from '@/components/icons';
import { PageHeader } from '@/components/page';
import { Chip, RiskBadge, ScanStatus, triggerLabel } from '@/components/badges';
import { Markdown } from '@/components/markdown';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { DownloadReport, ScanPackagesTable } from '../table';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `Scan ${(await params).id}` };
}

const conclusionStyle: Record<string, string> = {
  success: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  failure: 'bg-red-50 text-red-700 ring-red-200',
  neutral: 'bg-amber-50 text-amber-700 ring-amber-200',
};

export default async function ScanReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const s = await apiOr404<ScanDetail>(`/scans/${encodeURIComponent(id)}`);
  const { paths } = await api<{ paths: PathItem[] }>(`/scans/${encodeURIComponent(id)}/paths`);
  const findings = s.findings ?? [];
  const transitive = s.packages.filter((p) => p.direct === false && p.vulns.length);
  const ranked = [...paths].sort((a, b) => b.score - a.score);
  const counts = [
    { label: 'Components', value: s.counts.components, icon: Hexagon, tone: 'text-primary' },
    { label: 'Vulnerabilities', value: s.counts.vulns, icon: Bug, tone: 'text-red-600' },
    { label: 'Policy Violations', value: s.counts.violations, icon: FileChartLine, tone: 'text-amber-600' },
    { label: 'Malicious', value: s.counts.malicious, icon: Skull, tone: 'text-red-700' },
    { label: 'Suspicious', value: s.counts.suspicious, icon: ShieldAlert, tone: 'text-amber-600' },
  ];
  return (
    <>
      <PageHeader crumbs={[{ label: 'Scans', href: '/scans' }, { label: s.id }]} info="Full result of one scan: counts, the rendered report and every package that was evaluated." actions={<DownloadReport id={s.id} />} />
      <div className="mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold">
              <Link href={`/projects/${s.project.id}`} className="hover:text-primary hover:underline">
                {s.project.name}
              </Link>
            </h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
              <Chip>{s.version}</Chip>
              <Chip>{triggerLabel(s.trigger)}</Chip>
              {s.pr_number && <Chip>PR #{s.pr_number}</Chip>}
              {s.head_sha && <span className="font-mono text-xs">{s.head_sha.slice(0, 12)}</span>}
              <span>· started {fmtDateTime(s.created_at)}</span>
              {s.finished_at && <span>· finished {fmtDateTime(s.finished_at)}</span>}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <ScanStatus status={s.status} />
            {s.conclusion && (
              <span className={cn('rounded-md px-2 py-1 text-xs font-semibold uppercase ring-1', conclusionStyle[s.conclusion] ?? 'bg-muted ring-border')}>
                {s.conclusion === 'failure' ? 'Blocked' : s.conclusion === 'neutral' ? 'Warning' : s.conclusion === 'success' ? 'Passed' : s.conclusion}
              </span>
            )}
          </div>
        </div>

        {s.error && (
          <div role="alert" className="flex gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800">
            <AlertTriangle className="size-4 shrink-0" aria-hidden /> {s.error}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {counts.map((c) => (
            <Card key={c.label} className="gap-2 py-4">
              <CardHeader className="px-4">
                <CardTitle className="flex items-center gap-2 text-sm font-normal text-muted-foreground">
                  <c.icon className={cn('size-4', c.tone)} aria-hidden /> {c.label}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 text-2xl font-semibold tabular-nums">{c.value}</CardContent>
            </Card>
          ))}
        </div>

        {s.report_md && (
          <Card>
            <CardHeader>
              <CardTitle>Report</CardTitle>
            </CardHeader>
            <CardContent>
              <Markdown>{s.report_md}</Markdown>
            </CardContent>
          </Card>
        )}

        <Section title={`Transitive vulnerabilities (${transitive.length})`} empty="No vulnerable transitive dependencies.">
          {transitive.length > 0 && (
            <table className="w-full text-sm">
              <thead className="text-left text-muted-foreground">
                <tr>
                  <th className="py-2 font-normal">Package</th>
                  <th className="font-normal">Depth</th>
                  <th className="font-normal">Introduced via</th>
                  <th className="font-normal">Advisories</th>
                </tr>
              </thead>
              <tbody>
                {transitive.map((p) => (
                  <tr key={p.component.id + p.manifest_path} className="border-t align-top">
                    <td className="py-2 font-medium">
                      {p.component.name}@{p.component.version}
                    </td>
                    <td className="tabular-nums">{p.depth ?? '?'}</td>
                    <td className="font-mono text-xs">{p.via.join(' → ')}</td>
                    <td className="space-y-1">
                      {p.vulns.map((v) => (
                        <div key={v.id} className="flex items-center gap-2 text-xs">
                          <RiskBadge risk={v.risk} />
                          <Link className="font-mono hover:underline" href={`/vulnerabilities/${encodeURIComponent(v.id)}`}>
                            {v.id}
                          </Link>
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Section>

        <FindingsSection title="Suspicious packages" items={findings.filter((f) => f.category === 'suspicious')} empty="No suspicious packages." />
        <FindingsSection title="License issues" items={findings.filter((f) => f.category === 'license')} empty="No license issues." />

        <Section title={`Attack paths (${ranked.length})`} empty="No attack paths: no vulnerable package is reachable from the app.">
          {ranked.length > 0 && (
            <ol className="divide-y">
              {ranked.map((p, i) => (
                <li key={i} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                  <span className="w-10 rounded-md bg-primary/10 py-0.5 text-center font-semibold tabular-nums text-primary" title="Path score (0–100)">
                    {p.score}
                  </span>
                  <RiskBadge risk={p.risk} />
                  <Breadcrumbs p={p} />
                  {p.imported === false && <Chip>not imported</Chip>}
                  {p.approximate && <Chip>approximate</Chip>}
                  <span className="ml-auto text-xs text-muted-foreground">{p.fix}</span>
                </li>
              ))}
            </ol>
          )}
        </Section>

        <Card className="gap-0 overflow-hidden py-0">
          <CardHeader className="border-b py-4">
            <CardTitle>Packages ({s.packages.length})</CardTitle>
          </CardHeader>
          <ScanPackagesTable data={s.packages} />
        </Card>
      </div>
    </>
  );
}

function Section({ title, empty, children }: { title: string; empty: string; children: React.ReactNode }) {
  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>{children || <p className="text-sm text-muted-foreground">{empty}</p>}</CardContent>
    </Card>
  );
}

function FindingsSection({ title, items, empty }: { title: string; items: Finding[]; empty: string }) {
  return (
    <Section title={`${title} (${items.length})`} empty={empty}>
      {items.length > 0 && (
        <ul className="divide-y">
          {items.map((f, i) => (
            <li key={i} className="flex flex-wrap items-start gap-3 py-2 text-sm">
              <RiskBadge risk={f.severity} />
              <span className="inline-flex items-center gap-2 font-medium">
                <Ecosystem name={f.component.ecosystem} /> {f.component.name}@{f.component.version}
              </span>
              <Chip>{f.rule}</Chip>
              {f.blocking && <Chip className="bg-red-100 text-red-800">blocking</Chip>}
              <span className="basis-full text-muted-foreground">
                {f.category === 'suspicious' ? suspiciousReason(f.rule, f.details, f.summary) : String(f.details.explanation ?? f.summary)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
