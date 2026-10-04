import Link from 'next/link';
import { AlertTriangle, Bug, CheckCircle2, FileChartLine, GitBranch, Hexagon, Layers, LayoutDashboard, Route, Scale, ShieldAlert, ShieldX, Skull, Wrench } from 'lucide-react';
import { api, apiOr404 } from '@/lib/api';
import { fmtDateTime, suspiciousReason, titleCase } from '@/lib/format';
import type { Finding, FixPR, List, PathItem, ScanDetail, ScanPackage } from '@/lib/types';
import { canWrite, requireOrg } from '@/lib/session';
import { FixButton } from '@/components/fix-button';
import { Breadcrumbs } from '@/components/paths';
import { EcosystemTile } from '@/components/icons';
import { PageHeader } from '@/components/page';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Chip, RiskBadge, ScanStatus, triggerLabel } from '@/components/badges';
import { Markdown } from '@/components/markdown';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { DownloadReport, ScanPackagesTable } from '../table';
import { FindingsByCategory, SavePdfButton, SeverityDonut, ShowMore, VulnsByDepth } from './charts';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  return { title: `Scan ${(await params).id}` };
}

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const sevRank = (r: string) => {
  const i = SEV_ORDER.indexOf(r.toUpperCase());
  return i < 0 ? SEV_ORDER.length : i;
};
const FINDING_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// What each finding rule means and what to do about it, in plain words.
const RULE_HELP: Record<string, { title: string; what: string; action: string }> = {
  typosquat: {
    title: 'Lookalike package names',
    what: 'The name is one typo away from a popular package, a common way to slip in malware.',
    action: 'Confirm you meant this package; otherwise switch to the popular one.',
  },
  'unusual-behaviour': {
    title: 'Unusual install-time behaviour',
    what: 'Static analysis found code patterns typical of malicious packages (install scripts, obfuscation, exfiltration).',
    action: 'Review the package source before using it.',
  },
  unmaintained: {
    title: 'Unmaintained packages',
    what: 'No release for a long time and little or no activity in the source repository, so security fixes are unlikely.',
    action: 'Plan a replacement for the ones you depend on directly.',
  },
  deprecated: {
    title: 'Deprecated packages',
    what: 'The publisher has marked this version as deprecated.',
    action: 'Upgrade or move to the recommended replacement.',
  },
  'new-package': {
    title: 'Very new packages',
    what: 'First published less than 30 days ago, with no track record yet.',
    action: 'Check the publisher and source before trusting it.',
  },
  'release-age': {
    title: 'Brand-new releases',
    what: 'Published within the cooldown your policy sets. Hijacked releases are usually caught and pulled within hours.',
    action: 'Stay on the previous version for a few days, or allow it once the release has a track record.',
  },
  'install-script-added': {
    title: 'New install scripts',
    what: 'This release runs code on install that its previous release did not, the pattern of hijacked npm releases.',
    action: 'Read the script and the release notes before upgrading.',
  },
  'provenance-dropped': {
    title: 'Provenance dropped',
    what: 'Earlier releases were built and signed by the project CI; this one was published without that proof.',
    action: 'Treat it as possibly published from a stolen token; stay on the previous version.',
  },
  'publisher-changed': {
    title: 'New publisher',
    what: 'Published by an account that never published this package before.',
    action: 'Check the project announced the new maintainer.',
  },
  'new-behaviour': {
    title: 'New behaviour in an upgrade',
    what: 'Heuristic analysis found behaviour in the new version that the version you had did not show.',
    action: 'Review what changed before merging the upgrade.',
  },
  'no-source-repo': {
    title: 'No source repository',
    what: 'The package does not link to its source code, so it cannot be reviewed.',
    action: 'Prefer packages with a public source repository.',
  },
  'license-conflict': {
    title: 'License conflicts',
    what: 'These licenses cannot be combined in one distributed product.',
    action: 'Replace one side of the conflict or get legal sign-off.',
  },
  'license-unknown': {
    title: 'Unknown licenses',
    what: 'No recognisable license was found, so you have no clear right to use or ship it.',
    action: 'Find the license in the source or replace the package.',
  },
  'license-copyleft-distributed': {
    title: 'Copyleft in a distributed product',
    what: 'Strong copyleft (e.g. GPL) obliges you to release your source when you distribute the product.',
    action: 'Replace it, or confirm the obligations with legal.',
  },
  'license-network-copyleft': {
    title: 'Network copyleft',
    what: 'AGPL/SSPL-style terms apply even when the software is only offered as a service.',
    action: 'Replace it, or confirm the obligations with legal.',
  },
  'license-weak-copyleft': {
    title: 'Weak copyleft',
    what: 'LGPL/MPL-style terms: changes to the library itself must be shared; usually fine when used unmodified.',
    action: 'Keep it unmodified and include its notice.',
  },
  'license-multiple': {
    title: 'Several licenses listed',
    what: 'The package ships several license files; the permissive one was assumed.',
    action: 'Confirm which license covers the code you use.',
  },
  'license-noncommercial': {
    title: 'Non-commercial licenses',
    what: 'Commercial use is not allowed.',
    action: 'Replace the package for any commercial product.',
  },
};
const ruleHelp = (rule: string) => RULE_HELP[rule] ?? { title: titleCase(rule), what: '', action: '' };

const verdict: Record<string, { label: string; tone: string; Icon: typeof ShieldX }> = {
  failure: {
    label: 'Blocked',
    tone: 'border-red-200 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100',
    Icon: ShieldX,
  },
  neutral: {
    label: 'Passed with warnings',
    tone: 'border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100',
    Icon: ShieldAlert,
  },
  success: {
    label: 'Passed',
    tone: 'border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-100',
    Icon: CheckCircle2,
  },
};

const pkgKey = (p: { component: { name: string; version: string } }) => `${p.component.name}@${p.component.version}`;

function duration(a: string, b: string | null) {
  if (!b) return null;
  const s = Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export default async function ScanReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const s = await apiOr404<ScanDetail>(`/scans/${encodeURIComponent(id)}`);
  const { paths } = await api<{ paths: PathItem[] }>(`/scans/${encodeURIComponent(id)}/paths`);
  const { role } = await requireOrg();
  const fixes = s.trigger === 'pull_request' ? [] : (await api<List<FixPR>>('/fixes', { query: { project_id: s.project.id, page_size: 50 } })).items;
  const fixOf = (p: ScanPackage) =>
    fixes.find((f) => f.name === p.component.name && f.from_version === p.component.version && f.manifest_path === p.manifest_path && f.status !== 'closed');
  const findings = s.findings ?? [];

  // ---- derived data (one package may appear in several manifests: count it once)
  const uniq = new Map<string, ScanPackage>();
  for (const p of s.packages) if (!uniq.has(pkgKey(p))) uniq.set(pkgKey(p), p);
  const pkgs = [...uniq.values()];
  const direct = pkgs.filter((p) => p.direct === true).length;
  const transitive = pkgs.filter((p) => p.direct === false).length;

  const vulnerable = pkgs.filter((p) => p.vulns.length);
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const p of s.packages)
    for (const v of p.vulns) {
      const k = v.risk.toLowerCase() as keyof typeof sevCounts;
      if (k in sevCounts) sevCounts[k]++;
    }
  const worst = (p: ScanPackage) => Math.min(...p.vulns.map((v) => sevRank(v.risk)));
  vulnerable.sort((a, b) => worst(a) - worst(b) || b.vulns.length - a.vulns.length);

  const ranked = [...paths].sort((a, b) => b.score - a.score);
  const fixFor = new Map<string, string>();
  const fixable = new Set<string>(); // packages with a published fixed version
  for (const p of ranked) {
    const k = `${p.target.name}@${p.target.version}`;
    if (!fixFor.has(k) && p.fix) fixFor.set(k, p.fix);
    if (p.advisories.some((a) => a.fixed_in && !a.id.startsWith('MAL-'))) fixable.add(k);
  }

  const depthBuckets = new Map<string, number>();
  for (const p of vulnerable) {
    const d = p.depth == null ? '?' : p.depth >= 5 ? '5+' : String(p.depth);
    depthBuckets.set(d, (depthBuckets.get(d) ?? 0) + 1);
  }
  const depthData = ['1', '2', '3', '4', '5+', '?']
    .filter((d) => depthBuckets.has(d))
    .map((d) => ({
      depth: d === '1' ? 'Direct' : d,
      count: depthBuckets.get(d)!,
    }));

  // Vulnerability and malware rule violations live on packages; suspicious/license ones are findings.
  const ruleViolations = new Map<string, { category: string; rule: string }>();
  for (const p of pkgs)
    for (const v of p.violations)
      if (v.category !== 'suspicious' && v.category !== 'license')
        ruleViolations.set(`${pkgKey(p)}|${v.rule_name}`, {
          category: v.category,
          rule: v.rule_name,
        });
  const catRows = ['vulnerability', 'malware', 'license', 'suspicious']
    .map((c) => {
      const f = findings.filter((x) => x.category === c);
      const r = [...ruleViolations.values()].filter((x) => x.category === c).length;
      return {
        category: titleCase(c),
        blocking: r + f.filter((x) => x.blocking).length,
        warning: f.filter((x) => !x.blocking).length,
      };
    })
    .filter((d) => d.blocking + d.warning);
  const blockingCount = catRows.reduce((n, d) => n + d.blocking, 0);

  // "Fix these first": highest-scoring path per vulnerable package, then blocking non-vulnerability findings by rule.
  const topFixes: PathItem[] = [];
  const seenTarget = new Set<string>();
  for (const p of ranked) {
    const k = `${p.target.name}@${p.target.version}`;
    if (seenTarget.has(k)) continue;
    seenTarget.add(k);
    topFixes.push(p);
    if (topFixes.length === 5) break;
  }
  const malicious = pkgs.filter((p) => p.malware);
  const blockingGroups = group(findings.filter((f) => f.blocking));

  const suspiciousCount = findings.filter((f) => f.category === 'suspicious').length;
  const licenseCount = findings.filter((f) => f.category === 'license').length;
  const v = verdict[s.conclusion] ?? null;
  const took = duration(s.created_at, s.finished_at);

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Scans', href: '/scans' }, { label: s.id }]}
        info="Full result of one scan: verdict, charts, what to fix first, attack paths, suspicious packages and license issues."
        actions={
          <div className="flex gap-2">
            <SavePdfButton />
            <DownloadReport id={s.id} />
          </div>
        }
      />
      <div className="report mx-auto w-full max-w-6xl space-y-6 p-4 md:p-6 print:max-w-none print:space-y-4 print:p-0">
        {/* ---- title + verdict */}
        <section className={cn('break-inside-avoid rounded-xl border p-5', v?.tone ?? 'bg-card')}>
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-xs font-medium uppercase tracking-wide opacity-70">depguard · supply chain security report</p>
              <h1 className="mt-1 text-2xl font-semibold">
                <Link href={`/projects/${s.project.id}`} className="hover:underline">
                  {s.project.name}
                </Link>
              </h1>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-sm opacity-80">
                <span className="inline-flex items-center gap-1">
                  <GitBranch className="size-3.5" aria-hidden /> {s.version}
                </span>
                <Chip>{triggerLabel(s.trigger)}</Chip>
                {s.pr_number && <Chip>PR #{s.pr_number}</Chip>}
                {s.head_sha && <span className="font-mono text-xs">{s.head_sha.slice(0, 12)}</span>}
                <span>· {fmtDateTime(s.created_at)}</span>
                {took && <span>· took {took}</span>}
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              {v ? (
                <span className="inline-flex items-center gap-2 text-lg font-semibold">
                  <v.Icon className="size-6" aria-hidden /> {v.label}
                </span>
              ) : (
                <ScanStatus status={s.status} />
              )}
              {s.conclusion === 'failure' && (
                <span className="text-sm opacity-80">
                  {blockingCount} blocking issue{blockingCount === 1 ? '' : 's'} must be fixed
                </span>
              )}
            </div>
          </div>
          {s.error && (
            <div role="alert" className="mt-4 flex gap-2 rounded-lg border border-red-200 bg-white/60 p-3 text-sm text-red-800">
              <AlertTriangle className="size-4 shrink-0" aria-hidden /> {s.error}
            </div>
          )}
        </section>

        {/* ---- key numbers */}
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5 print:grid-cols-5">
          <Kpi icon={Hexagon} tone="text-primary" label="Components" value={s.counts.components} sub={`${direct} direct · ${transitive} transitive`} />
          <Kpi icon={Bug} tone="text-red-600" label="Vulnerabilities" value={s.counts.vulns} sub={`${sevCounts.critical} critical · ${sevCounts.high} high`} />
          <Kpi icon={FileChartLine} tone="text-amber-600" label="Policy violations" value={s.counts.violations} sub={`${blockingCount} blocking`} />
          <Kpi icon={ShieldAlert} tone="text-amber-600" label="Suspicious" value={s.counts.suspicious} sub={`${findings.filter((f) => f.category === 'suspicious' && f.blocking).length} blocking`} />
          <Kpi icon={Skull} tone="text-red-700" label="Malicious" value={s.counts.malicious} sub={s.counts.malicious ? 'remove immediately' : 'none found'} />
        </div>

        <Tabs defaultValue="overview" className="gap-5">
          <TabsList className="max-w-full justify-start overflow-x-auto print:hidden [&>button]:shrink-0">
            <TabsTrigger value="overview" className="group">
              <LayoutDashboard /> Overview
            </TabsTrigger>
            <TabsTrigger value="vulns" className="group">
              <Bug /> Vulnerabilities <TabCount n={vulnerable.length} />
            </TabsTrigger>
            <TabsTrigger value="findings" className="group">
              <ShieldAlert /> Suspicious &amp; licenses <TabCount n={suspiciousCount + licenseCount} />
            </TabsTrigger>
            <TabsTrigger value="packages" className="group">
              <Layers /> All packages <TabCount n={s.packages.length} />
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" forceMount className={tabCls}>
            {/* ---- charts */}
            <div className="grid gap-4 md:grid-cols-3 print:grid-cols-2">
              <ChartCard title="Vulnerabilities by severity" desc="Every advisory affecting an installed package">
                <SeverityDonut counts={sevCounts} />
              </ChartCard>
              <ChartCard title="Policy findings" desc="Blocking issues fail the check; warnings do not">
                <FindingsByCategory data={catRows} />
              </ChartCard>
              <ChartCard title="Where vulnerabilities sit" desc="Vulnerable packages by distance from your code">
                <VulnsByDepth data={depthData} />
              </ChartCard>
            </div>

            {/* ---- fix first */}
            {(topFixes.length > 0 || blockingGroups.length > 0 || malicious.length > 0) && (
              <Card className="break-inside-avoid">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Wrench className="size-4 text-primary" aria-hidden /> Fix these first
                  </CardTitle>
                  <CardDescription>The highest-risk items, ranked by severity, exploit likelihood and how directly they reach your app.</CardDescription>
                </CardHeader>
                <CardContent>
                  <ol className="space-y-3">
                    {malicious.map((p) => (
                      <FixItem key={pkgKey(p)} n={0} tone="red" title={`Remove ${pkgKey(p)}`} body="Known malicious package. Remove it and rotate any secrets the build environment had access to." />
                    ))}
                    {topFixes.map((p, i) => (
                      <FixItem
                        key={i}
                        n={i + 1}
                        tone={sevRank(p.risk) <= 1 ? 'red' : 'amber'}
                        title={p.fix || `Upgrade ${p.target.name}`}
                        body={
                          <span className="flex flex-wrap items-center gap-2">
                            <RiskBadge risk={p.risk} />
                            <span>
                              {p.advisories.length} advisor
                              {p.advisories.length === 1 ? 'y' : 'ies'} in {p.target.name}@{p.target.version}
                              {p.advisories.some((a) => a.kev) && <strong className="text-red-700"> · actively exploited (CISA KEV)</strong>}
                            </span>
                            <span className="text-muted-foreground">· risk score {p.score}</span>
                          </span>
                        }
                      />
                    ))}
                    {blockingGroups.map(([rule, items], i) => (
                      <FixItem
                        key={rule}
                        n={topFixes.length + i + 1}
                        tone="amber"
                        title={`${ruleHelp(rule).title}: ${items.length} package${items.length === 1 ? '' : 's'}`}
                        body={`${ruleHelp(rule).action} ${items
                          .slice(0, 4)
                          .map((f) => f.component.name)
                          .join(', ')}${items.length > 4 ? ` and ${items.length - 4} more` : ''}.`}
                      />
                    ))}
                  </ol>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="vulns" forceMount className={tabCls}>
            {/* ---- vulnerable packages, each with its attack paths */}
            <div className="flex flex-wrap items-end justify-between gap-2">
              <div>
                <h2 className="flex items-center gap-2 text-lg font-semibold" data-slot="card-title">
                  <Bug className="size-5 text-primary" aria-hidden /> Vulnerable packages <span className="text-sm font-normal text-muted-foreground">{vulnerable.length}</span>
                </h2>
                <p className="text-sm text-muted-foreground">Worst first. Each card shows the advisories, the fix and how the package reaches your app.</p>
              </div>
              <span className="text-sm text-muted-foreground">
                {ranked.length} attack path{ranked.length === 1 ? '' : 's'}
              </span>
            </div>
            {vulnerable.length === 0 ? (
              <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed py-12 text-center text-sm text-muted-foreground">
                <CheckCircle2 className="size-7 text-emerald-600 dark:text-emerald-400" aria-hidden /> No known vulnerabilities in any installed package.
              </div>
            ) : (
              <ShowMore
                className="space-y-3"
                shown={10}
                label="vulnerable packages"
                rows={vulnerable.map((p) => {
                  const k = pkgKey(p);
                  const risk = SEV_ORDER[worst(p)] ?? 'UNKNOWN';
                  const pp = ranked.filter((x) => `${x.target.name}@${x.target.version}` === k);
                  const top = pp[0];
                  const kev = pp.some((x) => x.advisories.some((a) => a.kev));
                  const vulnsSorted = [...p.vulns].sort((a, b) => sevRank(a.risk) - sevRank(b.risk));
                  return (
                    <li key={k} className={cn('break-inside-avoid overflow-hidden rounded-xl border border-l-4 bg-card', sevEdge[risk] ?? 'border-l-border')}>
                      <div className="flex flex-wrap items-center gap-3 p-4">
                        <EcosystemTile name={p.component.ecosystem} />
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-baseline gap-x-2">
                            <span className="font-semibold">{p.component.name}</span>
                            <span className="font-mono text-sm text-muted-foreground">{p.component.version}</span>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {p.direct ? 'Direct dependency' : p.direct === false ? `Transitive · depth ${p.depth ?? '?'}` : 'Dependency type unknown'}
                            {p.dev ? ' · dev only' : ''}
                            {p.direct === false && p.via.length > 1 && <span className="font-mono"> · via {p.via.slice(0, -1).join(' → ')}</span>}
                          </div>
                        </div>
                        {kev && <span className="rounded-md bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-700 dark:text-red-300">Actively exploited</span>}
                        <RiskBadge risk={risk} />
                        {top && (
                          <span className="w-16 text-right" title="Risk score: severity, exploit likelihood, depth and whether your code imports it">
                            <span className="block text-xl leading-none font-semibold tabular-nums">{top.score}</span>
                            <span className="text-[10px] tracking-wide text-muted-foreground uppercase">risk score</span>
                          </span>
                        )}
                      </div>
                      <div className="grid gap-4 border-t p-4 md:grid-cols-2">
                        <div>
                          <h4 className="mb-1.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                            {p.vulns.length} advisor{p.vulns.length === 1 ? 'y' : 'ies'}
                          </h4>
                          <div className="flex flex-wrap gap-1.5">
                            {vulnsSorted.map((x) => (
                              <Link
                                key={x.id}
                                href={`/vulnerabilities/${encodeURIComponent(x.id)}`}
                                title={x.summary}
                                className={cn('rounded-md px-1.5 py-0.5 font-mono text-[11px] whitespace-nowrap hover:underline', sevPill(x.risk))}
                              >
                                {x.id}
                              </Link>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h4 className="mb-1.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">How to fix</h4>
                          <p className="flex items-start gap-2 text-sm">
                            <Wrench className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
                            {fixFor.get(k) ?? 'No fixed version published yet. Consider replacing the package.'}
                          </p>
                          {fixable.has(k) && !p.malware && s.trigger !== 'pull_request' && (
                            <FixButton
                              className="mt-2 print:hidden"
                              projectId={s.project.id}
                              pkg={{ ecosystem: p.component.ecosystem, name: p.component.name, version: p.component.version, manifest_path: p.manifest_path }}
                              fix={fixOf(p)}
                              canEdit={canWrite(role)}
                            />
                          )}
                        </div>
                      </div>
                      {top && (
                        <div className="border-t bg-muted/30 px-4 py-3">
                          <h4 className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
                            <Route className="size-3.5" aria-hidden /> How it reaches your app
                          </h4>
                          <PathLine p={top} />
                          {pp.length > 1 && (
                            <details className="group/p mt-1.5">
                              <summary className="cursor-pointer list-none text-xs text-primary hover:underline [&::-webkit-details-marker]:hidden">
                                {pp.length - 1} more path{pp.length === 2 ? '' : 's'}
                              </summary>
                              <div className="mt-1.5 space-y-1.5">
                                {pp.slice(1).map((x, n) => (
                                  <PathLine key={n} p={x} />
                                ))}
                              </div>
                            </details>
                          )}
                        </div>
                      )}
                    </li>
                  );
                })}
              />
            )}
          </TabsContent>

          <TabsContent value="findings" forceMount className={tabCls}>
            {/* ---- suspicious + licenses */}
            <FindingGroups
              icon={ShieldAlert}
              title="Suspicious packages"
              items={findings.filter((f) => f.category === 'suspicious')}
              empty="No suspicious packages: no lookalike names, unmaintained or deprecated packages."
            />
            <FindingGroups icon={Scale} title="License issues" items={findings.filter((f) => f.category === 'license')} empty="No license issues for how this project is used." />
          </TabsContent>

          <TabsContent value="packages" forceMount className={cn(tabCls, 'print:!hidden')}>
            {/* ---- full inventory (screen only) */}
            <Card className="gap-0 overflow-hidden py-0 print:hidden">
              <CardHeader className="border-b py-4">
                <CardTitle className="flex items-center gap-2">
                  <Layers className="size-4 text-primary" aria-hidden /> All packages ({s.packages.length})
                </CardTitle>
              </CardHeader>
              <ScanPackagesTable data={s.packages} />
            </Card>

            {s.report_md && (
              <details className="rounded-xl border bg-card p-4 print:hidden">
                <summary className="cursor-pointer text-sm font-medium">Pull request comment (as posted on GitHub)</summary>
                <div className="mt-4">
                  <Markdown>{s.report_md}</Markdown>
                </div>
              </details>
            )}
          </TabsContent>
        </Tabs>

        <p className="hidden text-center text-xs text-muted-foreground print:block">
          Generated by depguard on {fmtDateTime(new Date().toISOString())} · scan {s.id}
        </p>
      </div>
    </>
  );
}

const sevEdge: Record<string, string> = { CRITICAL: 'border-l-red-500', HIGH: 'border-l-orange-500', MEDIUM: 'border-l-amber-500', LOW: 'border-l-sky-500' };

function PathLine({ p }: { p: PathItem }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm">
      <Breadcrumbs p={p} />
      {p.imported === false && <Chip>not imported</Chip>}
      {p.dev && <Chip>dev only</Chip>}
      {p.approximate && <Chip>approximate</Chip>}
    </div>
  );
}

// Inactive tabs stay in the page (hidden) so "Save as PDF" prints every section.
const tabCls = 'space-y-6 data-[state=inactive]:hidden print:!block print:space-y-4';

function TabCount({ n }: { n: number }) {
  return (
    <span className="ml-1 rounded-full bg-muted px-1.5 text-[11px] font-medium tabular-nums text-muted-foreground group-data-[state=active]:bg-primary/15 group-data-[state=active]:text-primary">
      {n}
    </span>
  );
}

function group(items: Finding[]): [string, Finding[]][] {
  const m = new Map<string, Finding[]>();
  for (const f of items) m.set(f.rule, [...(m.get(f.rule) ?? []), f]);
  const top = (fs: Finding[]) => Math.min(...fs.map((f) => FINDING_ORDER.indexOf(f.severity)));
  return [...m.entries()].sort((a, b) => top(a[1]) - top(b[1]) || b[1].length - a[1].length);
}

function sevPill(risk: string) {
  switch (risk.toUpperCase()) {
    case 'CRITICAL':
      return 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200';
    case 'HIGH':
      return 'bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200';
    case 'MEDIUM':
      return 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200';
    default:
      return 'bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200';
  }
}

function Kpi({ icon: Icon, tone, label, value, sub }: { icon: typeof Bug; tone: string; label: string; value: number; sub: string }) {
  return (
    <Card className="break-inside-avoid gap-1 py-4">
      <CardHeader className="px-4">
        <CardTitle className="flex items-center gap-2 text-sm font-normal text-muted-foreground">
          <Icon className={cn('size-4', tone)} aria-hidden /> {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4">
        <div className="text-3xl font-semibold tabular-nums">{value}</div>
        <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div>
      </CardContent>
    </Card>
  );
}

function ChartCard({ title, desc, children }: { title: string; desc: string; children: React.ReactNode }) {
  return (
    <Card className="break-inside-avoid gap-3">
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
        <CardDescription>{desc}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Section({ icon: Icon, title, count, desc, empty, children }: { icon: typeof Bug; title: string; count: number; desc?: string; empty: string; children: React.ReactNode }) {
  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Icon className="size-4 text-primary" aria-hidden /> {title}
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium tabular-nums text-muted-foreground">{count}</span>
        </CardTitle>
        {desc && <CardDescription>{desc}</CardDescription>}
      </CardHeader>
      <CardContent>
        {children || (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <CheckCircle2 className="size-4 text-emerald-600" aria-hidden /> {empty}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function FixItem({ n, tone, title, body }: { n: number; tone: 'red' | 'amber'; title: string; body: React.ReactNode }) {
  return (
    <li className="flex break-inside-avoid gap-3">
      <span className={cn('flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold text-white', tone === 'red' ? 'bg-red-600' : 'bg-amber-500')}>{n || '!'}</span>
      <div className="min-w-0 text-sm">
        <div className="font-medium">{title}</div>
        <div className="mt-0.5 text-muted-foreground">{body}</div>
      </div>
    </li>
  );
}

function FindingGroups({ icon, title, items, empty }: { icon: typeof Bug; title: string; items: Finding[]; empty: string }) {
  const groups = group(items);
  return (
    <Section icon={icon} title={title} count={items.length} empty={empty}>
      {groups.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2 print:grid-cols-2">
          {groups.map(([rule, fs]) => {
            const h = ruleHelp(rule);
            const blocking = fs.filter((f) => f.blocking).length;
            const sev = FINDING_ORDER[Math.min(...fs.map((f) => FINDING_ORDER.indexOf(f.severity)))] ?? 'info';
            return (
              <div key={rule} className={cn('break-inside-avoid rounded-lg border p-3', blocking && 'border-red-200 dark:border-red-900')}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{h.title}</span>
                  <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium tabular-nums">{fs.length}</span>
                  <RiskBadge risk={sev} />
                  {blocking > 0 && <Chip className="bg-red-100 text-red-800">{blocking} blocking</Chip>}
                </div>
                {h.what && <p className="mt-1.5 text-sm text-muted-foreground">{h.what}</p>}
                {h.action && (
                  <p className="mt-1 text-sm">
                    <span className="font-medium">What to do:</span> {h.action}
                  </p>
                )}
                <FindingList items={fs} />
              </div>
            );
          })}
        </div>
      )}
    </Section>
  );
}

function FindingList({ items }: { items: Finding[] }) {
  const row = (f: Finding, i: number) => (
    <li key={i} className="py-1">
      <span className="font-mono text-xs font-medium">
        {f.component.name}@{f.component.version}
      </span>
      <span className="text-xs text-muted-foreground"> — {f.category === 'suspicious' ? suspiciousReason(f.rule, f.details, f.summary) : String(f.details.explanation ?? f.summary)}</span>
    </li>
  );
  const first = items.slice(0, 3);
  return (
    <div className="mt-2 border-t pt-2">
      <ul>{first.map(row)}</ul>
      {items.length > 3 && (
        <details>
          <summary className="cursor-pointer text-xs font-medium text-primary">Show {items.length - 3} more</summary>
          <ul>{items.slice(3).map(row)}</ul>
        </details>
      )}
    </div>
  );
}

