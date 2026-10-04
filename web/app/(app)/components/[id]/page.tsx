import Link from 'next/link';
import { Bug, ExternalLink, FolderGit2, GitFork, HeartPulse, ShieldCheck, Skull, Star } from 'lucide-react';
import { apiOr404 } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { ComponentDetail } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { DependencyBadge, RiskBadge } from '@/components/badges';
import { EcosystemTile } from '@/components/icons';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }) {
  const c = await apiOr404<ComponentDetail>(`/components/${encodeURIComponent((await params).id)}`);
  return { title: `${c.name} ${c.version}` };
}

const depsDev: Record<string, string> = { npm: 'npm', PyPI: 'pypi', Go: 'go', Maven: 'maven', 'crates.io': 'cargo', NuGet: 'nuget' };
const ring: Record<string, string> = { good: '#10b981', fair: '#f59e0b', poor: '#ef4444', malicious: '#dc2626', unknown: '#9ca3af' };
const verdict: Record<string, string> = {
  good: 'Looks well maintained and widely used.',
  fair: 'Usable, but some signals are weak. Check the factors below.',
  poor: 'Weak signals: consider an alternative or pin and review it.',
  malicious: 'Known or detected malware. Remove it.',
  unknown: 'Not enough public data to judge this package.',
};

function HealthRing({ score, level }: { score: number | null; level: string }) {
  const pct = score == null ? 0 : score / 10;
  const c = 2 * Math.PI * 42;
  return (
    <svg viewBox="0 0 100 100" className="size-28 shrink-0" role="img" aria-label={`Health ${score ?? 'unknown'} of 10`}>
      <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="9" className="text-muted" />
      <circle cx="50" cy="50" r="42" fill="none" stroke={ring[level] ?? ring.unknown} strokeWidth="9" strokeLinecap="round" strokeDasharray={`${pct * c} ${c}`} transform="rotate(-90 50 50)" />
      <text x="50" y="50" textAnchor="middle" className="fill-foreground" fontSize="24" fontWeight="600">
        {level === 'malicious' ? '0' : score == null ? '–' : score.toFixed(1)}
      </text>
      <text x="50" y="66" textAnchor="middle" className="fill-muted-foreground" fontSize="9">
        of 10
      </text>
    </svg>
  );
}

export default async function ComponentPage({ params }: { params: Promise<{ id: string }> }) {
  const c = await apiOr404<ComponentDetail>(`/components/${encodeURIComponent((await params).id)}`);
  const h = c.health;
  const sys = depsDev[c.ecosystem];
  const repo = c.meta.repo ? `https://${c.meta.repo}` : null;
  const checks = Object.entries(c.scorecard.checks ?? {}).sort((a, b) => a[1] - b[1]);
  const outdated = c.meta.default_version && c.meta.default_version !== c.version;

  return (
    <>
      <PageHeader crumbs={[{ label: 'Components', href: '/components' }, { label: `${c.name} ${c.version}` }]} actions={null} />
      <div className="mx-auto w-full max-w-6xl space-y-4 p-4 md:p-6">
        <section className="flex flex-wrap items-center gap-4 rounded-xl border bg-card p-5">
          <EcosystemTile name={c.ecosystem} />
          <div className="min-w-0 flex-1">
            <h1 className="text-2xl font-semibold">{c.name}</h1>
            <p className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
              <span className="font-mono">{c.version}</span>
              <span>{c.ecosystem}</span>
              {c.licenses.length > 0 && <span>{c.licenses.join(', ')}</span>}
              {outdated && <span className="text-amber-700 dark:text-amber-400">Latest: {c.meta.default_version}</span>}
              {c.meta.deprecated && <span className="text-red-700 dark:text-red-400">Deprecated</span>}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {repo && (
              <a href={repo} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-sm hover:bg-muted">
                Source <ExternalLink className="size-3.5" />
              </a>
            )}
            {sys && (
              <a href={`https://deps.dev/${sys}/${encodeURIComponent(c.name)}/${encodeURIComponent(c.version)}`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-sm hover:bg-muted">
                deps.dev <ExternalLink className="size-3.5" />
              </a>
            )}
          </div>
        </section>

        <div className="grid gap-4 lg:grid-cols-5">
          <Card className="lg:col-span-3" aria-label="Package health">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <HeartPulse className="size-4 text-primary" /> Package health
              </CardTitle>
              <CardDescription>A 0–10 trust score from public signals. Unknown signals are left out, not counted against the package.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                <HealthRing score={h.score} level={h.level} />
                <div>
                  <p className="text-lg font-semibold capitalize">{h.level}</p>
                  <p className="text-sm text-muted-foreground">{verdict[h.level]}</p>
                </div>
              </div>
              <ul className="space-y-2.5">
                {h.factors.map((f) => (
                  <li key={f.key}>
                    <div className="flex items-baseline justify-between gap-3 text-sm">
                      <span className="font-medium">
                        {f.label} <span className="text-xs font-normal text-muted-foreground">· {f.weight}%</span>
                      </span>
                      <span className="text-xs text-muted-foreground">{f.detail || 'Unknown'}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                      {f.value != null && (
                        <div className={cn('h-full rounded-full', f.value >= 0.7 ? 'bg-emerald-500' : f.value >= 0.4 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${Math.max(4, f.value * 100)}%` }} />
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          <div className="space-y-4 lg:col-span-2">
            <Card className="gap-3">
              <CardHeader>
                <CardTitle className="text-base">At a glance</CardTitle>
              </CardHeader>
              <CardContent>
                <dl className="grid grid-cols-2 gap-3 text-sm">
                  {[
                    { icon: Star, label: 'Stars', value: c.meta.stars?.toLocaleString('en-GB') ?? '–' },
                    { icon: GitFork, label: 'Forks', value: c.meta.forks?.toLocaleString('en-GB') ?? '–' },
                    { icon: ShieldCheck, label: 'Scorecard', value: c.scorecard.score != null ? `${c.scorecard.score.toFixed(1)} / 10` : '–' },
                    { icon: Bug, label: 'Vulnerabilities', value: String(c.vulns.filter((v) => !v.id.startsWith('MAL-')).length) },
                  ].map((k) => (
                    <div key={k.label} className="rounded-lg border p-2.5">
                      <dt className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <k.icon className="size-3.5" aria-hidden /> {k.label}
                      </dt>
                      <dd className="mt-1 font-semibold tabular-nums">{k.value}</dd>
                    </div>
                  ))}
                </dl>
                <p className="mt-3 text-xs text-muted-foreground">
                  This version published {fmtDate(c.meta.published_at)} · latest release {fmtDate(c.meta.latest_published)} · first release {fmtDate(c.meta.first_published)}
                </p>
                {c.analysis && (
                  <Link href={`/package-analysis/${c.analysis.id}`} className={cn('mt-3 flex items-center gap-2 rounded-lg border p-2.5 text-sm', c.analysis.status === 'malicious' && 'border-red-500/40 bg-red-500/5 text-red-700 dark:text-red-300')}>
                    <Skull className="size-4" aria-hidden /> Malware analysis: <span className="font-medium capitalize">{c.analysis.status}</span>
                    {c.analysis.verified && ' · verified'}
                  </Link>
                )}
              </CardContent>
            </Card>

            {checks.length > 0 && (
              <Card className="gap-3" aria-label="Scorecard checks">
                <CardHeader>
                  <CardTitle className="text-base">OpenSSF Scorecard checks</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="grid gap-1.5 text-sm">
                    {checks.map(([k, v]) => (
                      <li key={k} className="flex items-center justify-between gap-2">
                        <span>{k.replace(/-/g, ' ')}</span>
                        <span className={cn('rounded px-1.5 text-xs font-semibold tabular-nums', v >= 7 ? 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300' : v >= 4 ? 'bg-amber-500/15 text-amber-800 dark:text-amber-300' : 'bg-red-500/15 text-red-700 dark:text-red-300')}>
                          {v < 0 ? 'n/a' : v}
                        </span>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <Card className="gap-3">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Bug className="size-4 text-primary" /> Known vulnerabilities
              </CardTitle>
            </CardHeader>
            <CardContent>
              {c.vulns.length === 0 ? (
                <p className="text-sm text-muted-foreground">None known for this version.</p>
              ) : (
                <ul className="divide-y">
                  {c.vulns.map((v) => (
                    <li key={v.id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                      <RiskBadge risk={v.risk} />
                      <Link href={`/vulnerabilities/${encodeURIComponent(v.id)}`} className="font-mono text-xs font-semibold hover:text-primary hover:underline">
                        {v.id}
                      </Link>
                      {v.fixed_in && <span className="text-xs text-emerald-700 dark:text-emerald-400">fixed in {v.fixed_in}</span>}
                      {v.summary && <span className="w-full text-xs text-muted-foreground">{v.summary}</span>}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
          <Card className="gap-3">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <FolderGit2 className="size-4 text-primary" /> Used in
              </CardTitle>
            </CardHeader>
            <CardContent>
              {c.projects.length === 0 ? (
                <p className="text-sm text-muted-foreground">No current project uses this version.</p>
              ) : (
                <ul className="divide-y">
                  {c.projects.map((p) => (
                    <li key={p.id + p.version + p.manifest_path} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                      <Link href={`/projects/${p.id}?version=${encodeURIComponent(p.version_id)}`} className="font-medium hover:text-primary hover:underline">
                        {p.name}
                      </Link>
                      <span className="text-xs text-muted-foreground">{p.version}</span>
                      <span className="font-mono text-xs text-muted-foreground">{p.manifest_path}</span>
                      <span className="ml-auto">
                        <DependencyBadge direct={p.direct} depth={null} />
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
