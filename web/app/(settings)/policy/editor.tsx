'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { Bug, FlaskConical, Info, Loader2, PackageCheck, Plus, RotateCcw, Scale, ScanSearch, Skull, Star, Trash2, Wrench, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAction } from '@/components/client';
import { savePolicy, testPolicy } from '@/lib/actions';
import type { CustomRule, PackageRule, Policy, Severity, SuspiciousPreset } from '@/lib/types';

const Monaco = dynamic(() => import('@monaco-editor/react'), {
  ssr: false,
  loading: () => <div className="h-[120px] animate-pulse rounded-md bg-muted" />,
});

const DEFAULT_DENY: string[] = [];
const DEFAULT_SUSPICIOUS: SuspiciousPreset = { typosquat: true, unmaintained: true, unmaintained_months: 24, deprecated: true, new_package: true, no_source_repo: false, unusual_behaviour: true, blocking: ['typosquat', 'unusual-behaviour'] };
// Toggle key in the preset -> rule name used in findings and in `blocking`.
const SUSPICIOUS_RULES: { key: keyof SuspiciousPreset; rule: string; label: string; hint: string }[] = [
  { key: 'typosquat', rule: 'typosquat', label: 'Typosquats', hint: 'Names one edit away from a popular package (lodahs vs lodash).' },
  { key: 'unmaintained', rule: 'unmaintained', label: 'Unmaintained', hint: 'No release for a long time and no sign of active maintenance.' },
  { key: 'deprecated', rule: 'deprecated', label: 'Deprecated', hint: 'Marked deprecated by its maintainers.' },
  { key: 'new_package', rule: 'new-package', label: 'Brand-new versions', hint: 'Version published less than 30 days ago.' },
  { key: 'no_source_repo', rule: 'no-source-repo', label: 'No source repository', hint: 'No linked source repository to review.' },
  { key: 'unusual_behaviour', rule: 'unusual-behaviour', label: 'Unusual behaviour', hint: 'Install scripts, obfuscation or exfiltration found by heuristic analysis.' },
];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Older stored policies lack the suspicious preset and the new license fields. */
function withDefaults(p: Policy): Policy {
  return {
    ...p,
    presets: {
      ...p.presets,
      license: { enabled: true, blocking_severity: 'high', ...p.presets.license },
      suspicious: { ...DEFAULT_SUSPICIOUS, ...p.presets.suspicious },
    },
  };
}
const CATEGORIES = ['vulnerability', 'malware', 'license', 'popularity', 'maintenance'];
const RISKS = [
  { v: 'CRITICAL', l: 'Critical only' },
  { v: 'HIGH', l: 'High and above' },
  { v: 'MEDIUM', l: 'Medium and above' },
  { v: 'LOW', l: 'Any severity' },
  { v: 'OFF', l: 'Off' },
] as const;

function Preset({
  icon: Icon,
  title,
  description,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Icon className="size-4 text-primary" /> {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">{children}</CardContent>
    </Card>
  );
}

export function PolicyEditor({ initial: raw, canEdit }: { initial: Policy; canEdit: boolean }) {
  const [initial] = useState(() => withDefaults(raw));
  const [p, setP] = useState<Policy>(initial);
  const [license, setLicense] = useState('');
  const { pending, run } = useAction();
  const ro = !canEdit;
  const set = <K extends keyof Policy['presets']>(k: K, v: Partial<Policy['presets'][K]>) =>
    setP({ ...p, presets: { ...p.presets, [k]: { ...p.presets[k], ...v } } });
  const setRule = (i: number, v: Partial<CustomRule>) => setP({ ...p, custom: p.custom.map((r, j) => (j === i ? { ...r, ...v } : r)) });
  const deny = p.presets.license.deny;
  const addLicense = () => {
    const l = license.trim();
    if (l && !deny.includes(l)) set('license', { deny: [...deny, l] });
    setLicense('');
  };
  const dirty = JSON.stringify(p) !== JSON.stringify(initial);

  return (
    <div className="grid gap-4">
      {ro && (
        <p className="flex items-center gap-2 rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">
          <Info className="size-4" /> You have read-only access. Ask an owner or admin to change the policy.
        </p>
      )}

      <Preset icon={Bug} title="Vulnerability" description="Flag packages with known vulnerabilities at or above this severity.">
        <Label htmlFor="p-risk">Minimum severity</Label>
        <Select value={p.presets.vulnerability.min_risk} onValueChange={(v) => set('vulnerability', { min_risk: v as Policy['presets']['vulnerability']['min_risk'] })} disabled={ro}>
          <SelectTrigger id="p-risk" className="w-60">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RISKS.map((r) => (
              <SelectItem key={r.v} value={r.v}>
                {r.l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Preset>

      <Preset icon={Skull} title="Malware" description="Flag packages listed as malicious in OSV, or verified malicious by your team.">
        <div className="flex items-center gap-2">
          <Switch id="p-mal" checked={p.presets.malware.enabled} onCheckedChange={(v) => set('malware', { enabled: v })} disabled={ro} />
          <Label htmlFor="p-mal">Block malicious packages</Label>
        </div>
      </Preset>

      <PackageRulesCard rules={p.presets.packages ?? []} ro={ro} onChange={(packages) => setP({ ...p, presets: { ...p.presets, packages } })} />

      <Preset icon={Scale} title="License" description="Check dependency licenses against your project license and usage model, plus a deny list of SPDX identifiers.">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch id="p-lic-on" checked={p.presets.license.enabled ?? true} onCheckedChange={(v) => set('license', { enabled: v })} disabled={ro} />
            <Label htmlFor="p-lic-on">License compliance checks</Label>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="p-lic-sev">Block at severity</Label>
            <Select value={p.presets.license.blocking_severity ?? 'high'} onValueChange={(v) => set('license', { blocking_severity: v as Severity })} disabled={ro || p.presets.license.enabled === false}>
              <SelectTrigger id="p-lic-sev" className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SEVERITIES.map((s) => (
                  <SelectItem key={s} value={s} className="capitalize">
                    {s} and above
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
        <p className="text-sm font-medium">Denied licenses</p>
        <ul className="flex flex-wrap gap-2" aria-label="Denied licenses">
          {deny.length === 0 && <li className="text-sm text-muted-foreground">No licenses denied.</li>}
          {deny.map((l) => (
            <li key={l} className="inline-flex items-center gap-1 rounded-md border bg-accent px-2 py-1 font-mono text-xs text-accent-foreground">
              {l}
              {!ro && (
                <button type="button" aria-label={`Remove ${l}`} onClick={() => set('license', { deny: deny.filter((x) => x !== l) })} className="rounded hover:text-destructive">
                  <X className="size-3" />
                </button>
              )}
            </li>
          ))}
        </ul>
        {!ro && (
          <div className="flex flex-wrap gap-2">
            <Label htmlFor="p-lic" className="sr-only">
              Add license
            </Label>
            <Input
              id="p-lic"
              className="w-60"
              placeholder="e.g. SSPL-1.0"
              value={license}
              onChange={(e) => setLicense(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addLicense();
                }
              }}
            />
            <Button type="button" variant="outline" onClick={addLicense}>
              <Plus /> Add
            </Button>
            <Button type="button" variant="ghost" onClick={() => set('license', { deny: DEFAULT_DENY })}>
              <RotateCcw /> Reset to defaults
            </Button>
          </div>
        )}
      </Preset>

      <SuspiciousCard s={p.presets.suspicious ?? DEFAULT_SUSPICIOUS} ro={ro} onChange={(v) => set('suspicious', v)} />

      <Preset icon={Star} title="Popularity" description="Flag packages whose source repository has very few stars — a common trait of typosquats.">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch id="p-pop" checked={p.presets.popularity.enabled} onCheckedChange={(v) => set('popularity', { enabled: v })} disabled={ro} />
            <Label htmlFor="p-pop">Enabled</Label>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="p-stars">Minimum stars</Label>
            <Input id="p-stars" type="number" min={0} className="w-28" value={p.presets.popularity.min_stars} onChange={(e) => set('popularity', { min_stars: Number(e.target.value) })} disabled={ro || !p.presets.popularity.enabled} />
          </div>
        </div>
      </Preset>

      <Preset icon={Wrench} title="Maintenance" description="Flag packages whose OpenSSF Scorecard score (0–10) is below a threshold.">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch id="p-maint" checked={p.presets.maintenance.enabled} onCheckedChange={(v) => set('maintenance', { enabled: v })} disabled={ro} />
            <Label htmlFor="p-maint">Enabled</Label>
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="p-score">Minimum score</Label>
            <Input id="p-score" type="number" min={0} max={10} step={0.1} className="w-28" value={p.presets.maintenance.min_scorecard} onChange={(e) => set('maintenance', { min_scorecard: Number(e.target.value) })} disabled={ro || !p.presets.maintenance.enabled} />
          </div>
        </div>
      </Preset>

      <Card className="gap-4">
        <CardHeader>
          <CardTitle className="text-base">Advanced: custom CEL rules</CardTitle>
          <CardDescription>Write your own rules in the Common Expression Language. A package that makes an expression true is a violation.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <details className="rounded-md border bg-muted/40 p-3 text-sm">
            <summary className="cursor-pointer font-medium">CEL quick reference</summary>
            <ul className="mt-2 grid gap-1 font-mono text-xs">
              <li>pkg.name, pkg.version, pkg.ecosystem — the package being checked</li>
              <li>vulns.critical, vulns.high, vulns.medium, vulns.low — lists of advisories by severity</li>
              <li>vulns.all.exists(v, v.id.startsWith(&quot;MAL-&quot;)) — any malware advisory</li>
              <li>licenses.exists(l, l == &quot;MIT&quot;) — SPDX licenses of the package</li>
              <li>scorecard.score &lt; 3.0 — OpenSSF Scorecard overall score</li>
              <li>projects.exists(p, p.stars &lt; 10) — source repository popularity</li>
            </ul>
          </details>
          {p.custom.length === 0 && <p className="text-sm text-muted-foreground">No custom rules yet.</p>}
          {p.custom.map((r, i) => (
            <RuleEditor key={i} i={i} rule={r} ro={ro} onChange={(v) => setRule(i, v)} onRemove={() => setP({ ...p, custom: p.custom.filter((_, j) => j !== i) })} />
          ))}
          {!ro && (
            <Button type="button" variant="outline" className="w-fit" onClick={() => setP({ ...p, custom: [...p.custom, { name: `custom-rule-${p.custom.length + 1}`, category: 'vulnerability', summary: '', expr: '' }] })}>
              <Plus /> Add rule
            </Button>
          )}
        </CardContent>
      </Card>

      {!ro && (
        <div className="sticky bottom-0 flex justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur">
          <Button variant="outline" disabled={!dirty || pending} onClick={() => setP(initial)}>
            Discard changes
          </Button>
          <Button disabled={!dirty || pending} onClick={() => run(() => savePolicy(p), 'Policy saved')}>
            {pending && <Loader2 className="animate-spin" />} Save policy
          </Button>
        </div>
      )}
    </div>
  );
}

function SuspiciousCard({ s, ro, onChange }: { s: SuspiciousPreset; ro: boolean; onChange: (v: Partial<SuspiciousPreset>) => void }) {
  return (
    <Preset icon={ScanSearch} title="Suspicious" description="Flag lookalike, abandoned, deprecated, brand-new and oddly-behaving packages. Blocking rules fail the check; the rest are reported only.">
      <div className="grid gap-2" role="group" aria-label="Suspicious package rules">
        {SUSPICIOUS_RULES.map((r) => {
          const on = s[r.key] as boolean;
          const blocking = s.blocking.includes(r.rule);
          return (
            <div key={r.rule} className="flex flex-wrap items-center gap-3 rounded-md border p-2">
              <Switch id={`p-s-${r.rule}`} checked={on} onCheckedChange={(v) => onChange({ [r.key]: v })} disabled={ro} />
              <div className="min-w-48 flex-1">
                <Label htmlFor={`p-s-${r.rule}`}>{r.label}</Label>
                <p className="text-xs text-muted-foreground">{r.hint}</p>
              </div>
              {r.key === 'unmaintained' && (
                <div className="flex items-center gap-2">
                  <Label htmlFor="p-s-months" className="text-xs">
                    Months without release
                  </Label>
                  <Input id="p-s-months" type="number" min={1} max={120} className="h-8 w-20" value={s.unmaintained_months} onChange={(e) => onChange({ unmaintained_months: Number(e.target.value) })} disabled={ro || !on} />
                </div>
              )}
              <div className="flex items-center gap-2">
                <Switch
                  id={`p-s-${r.rule}-block`}
                  checked={blocking}
                  onCheckedChange={(v) => onChange({ blocking: v ? [...s.blocking, r.rule] : s.blocking.filter((x) => x !== r.rule) })}
                  disabled={ro || !on}
                />
                <Label htmlFor={`p-s-${r.rule}-block`} className="text-xs">
                  Blocks
                </Label>
              </div>
            </div>
          );
        })}
      </div>
    </Preset>
  );
}

function RuleEditor({ i, rule, ro, onChange, onRemove }: { i: number; rule: CustomRule; ro: boolean; onChange: (v: Partial<CustomRule>) => void; onRemove: () => void }) {
  const [t, setT] = useState({ ecosystem: 'npm', name: '', version: '' });
  const [result, setResult] = useState<{ matched: boolean; error?: string } | null>(null);
  const { pending, run } = useAction();
  const id = `rule-${i}`;
  return (
    <fieldset className="grid gap-3 rounded-lg border p-4" aria-label={`Custom rule ${rule.name}`}>
      <div className="grid gap-3 sm:grid-cols-[1fr_12rem_auto]">
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-name`}>Name</Label>
          <Input id={`${id}-name`} value={rule.name} onChange={(e) => onChange({ name: e.target.value })} disabled={ro} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor={`${id}-cat`}>Category</Label>
          <Select value={rule.category} onValueChange={(v) => onChange({ category: v })} disabled={ro}>
            <SelectTrigger id={`${id}-cat`} className="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {CATEGORIES.map((c) => (
                <SelectItem key={c} value={c} className="capitalize">
                  {c}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {!ro && (
          <Button type="button" variant="ghost" size="icon" className="self-end text-destructive" aria-label={`Remove rule ${rule.name}`} onClick={onRemove}>
            <Trash2 />
          </Button>
        )}
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor={`${id}-sum`}>Summary</Label>
        <Input id={`${id}-sum`} value={rule.summary} onChange={(e) => onChange({ summary: e.target.value })} disabled={ro} placeholder="Shown on the violation" />
      </div>
      <div className="grid gap-1.5">
        <span className="text-sm font-medium" id={`${id}-expr`}>
          Expression
        </span>
        <div className="overflow-hidden rounded-md border" aria-labelledby={`${id}-expr`}>
          <Monaco
            height="120px"
            language="javascript"
            value={rule.expr}
            onChange={(v) => onChange({ expr: v ?? '' })}
            options={{ readOnly: ro, minimap: { enabled: false }, lineNumbers: 'off', scrollBeyondLastLine: false, fontSize: 13, wordWrap: 'on', ariaLabel: `CEL expression for ${rule.name}` }}
          />
        </div>
      </div>
      <div className="flex flex-wrap items-end gap-2 rounded-md bg-muted/40 p-3">
        <div className="grid gap-1">
          <Label htmlFor={`${id}-t-eco`} className="text-xs">
            Ecosystem
          </Label>
          <Input id={`${id}-t-eco`} className="h-8 w-28" value={t.ecosystem} onChange={(e) => setT({ ...t, ecosystem: e.target.value })} />
        </div>
        <div className="grid gap-1">
          <Label htmlFor={`${id}-t-name`} className="text-xs">
            Package
          </Label>
          <Input id={`${id}-t-name`} className="h-8 w-44" value={t.name} onChange={(e) => setT({ ...t, name: e.target.value })} placeholder="lodash" />
        </div>
        <div className="grid gap-1">
          <Label htmlFor={`${id}-t-ver`} className="text-xs">
            Version
          </Label>
          <Input id={`${id}-t-ver`} className="h-8 w-28" value={t.version} onChange={(e) => setT({ ...t, version: e.target.value })} placeholder="4.17.20" />
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={pending || !t.name}
          onClick={async () => {
            setResult(null);
            const r = await run(() => testPolicy({ expr: rule.expr, ...t }));
            if (r) setResult(r);
          }}
        >
          {pending ? <Loader2 className="animate-spin" /> : <FlaskConical />} Test
        </Button>
        <span role="status" className="text-sm">
          {result &&
            (result.error ? (
              <span className="text-destructive">Error: {result.error}</span>
            ) : result.matched ? (
              <span className="font-medium text-amber-700">Matched — this package would be a violation</span>
            ) : (
              <span className="text-emerald-700">Not matched — package passes this rule</span>
            ))}
        </span>
      </div>
    </fieldset>
  );
}

const ECOSYSTEM_CHOICES = [
  { v: 'any', l: 'Any ecosystem' },
  { v: 'npm', l: 'npm' },
  { v: 'pypi', l: 'PyPI' },
  { v: 'go', l: 'Go' },
  { v: 'cargo', l: 'Cargo' },
  { v: 'maven', l: 'Maven' },
  { v: 'rubygems', l: 'RubyGems' },
  { v: 'packagist', l: 'Packagist' },
  { v: 'nuget', l: 'NuGet' },
];
type RuleMode = 'versions' | 'deny' | 'allow';
const modeOf = (r: PackageRule): RuleMode => (r.deny ? 'deny' : r.allow ? 'allow' : 'versions');
// Mirrors internal/pkgrules.ParseRange: comparisons (>= > <= < = !=) joined by spaces/commas, alternatives by ||.
const RANGE_RE = /^\s*((>=|<=|!=|==|>|<|=)?\s*[^\s,<>=!|]+[\s,]*)+(\|\|\s*((>=|<=|!=|==|>|<|=)?\s*[^\s,<>=!|]+[\s,]*)+)*$/;
export const validRange = (s: string) => s.trim() === '' || RANGE_RE.test(s);

function PackageRulesCard({ rules, ro, onChange }: { rules: PackageRule[]; ro: boolean; onChange: (r: PackageRule[]) => void }) {
  const update = (i: number, v: Partial<PackageRule>) => onChange(rules.map((r, j) => (j === i ? { ...r, ...v } : r)));
  const setMode = (i: number, m: RuleMode) => update(i, { deny: m === 'deny' || undefined, allow: m === 'allow' || undefined, versions: m === 'versions' ? rules[i].versions : undefined });
  return (
    <Preset icon={PackageCheck} title="Package & version rules" description="Ban packages, set minimum/maximum allowed versions, or mark packages as trusted. Enforced on PR and repository scans and before installs with the depguard CLI.">
      {rules.length === 0 ? (
        <p className="text-sm text-muted-foreground">No package rules yet. Example: lodash, allowed versions &gt;=4.17.21.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm" aria-label="Package rules">
            <thead className="text-left text-xs text-muted-foreground">
              <tr>
                <th className="pb-2 font-medium">Ecosystem</th>
                <th className="pb-2 font-medium">Package</th>
                <th className="pb-2 font-medium">Rule</th>
                <th className="pb-2 font-medium">Allowed versions</th>
                <th className="pb-2 font-medium">Severity</th>
                <th className="pb-2 font-medium">Reason</th>
                <th className="pb-2" />
              </tr>
            </thead>
            <tbody>
              {rules.map((r, i) => {
                const mode = modeOf(r);
                const bad = mode === 'versions' && !validRange(r.versions ?? '');
                return (
                  <tr key={i} className="align-top">
                    <td className="py-1 pr-2">
                      <Select value={r.ecosystem || 'any'} onValueChange={(v) => update(i, { ecosystem: v === 'any' ? undefined : v })} disabled={ro}>
                        <SelectTrigger className="w-36" aria-label={`Rule ${i + 1} ecosystem`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {ECOSYSTEM_CHOICES.map((e) => (
                            <SelectItem key={e.v} value={e.v}>
                              {e.l}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </td>
                    <td className="py-1 pr-2">
                      <Input aria-label={`Rule ${i + 1} package`} className="w-44 font-mono" placeholder="lodash or @types/*" value={r.name} onChange={(e) => update(i, { name: e.target.value })} disabled={ro} />
                    </td>
                    <td className="py-1 pr-2">
                      <Select value={mode} onValueChange={(v) => setMode(i, v as RuleMode)} disabled={ro}>
                        <SelectTrigger className="w-40" aria-label={`Rule ${i + 1} type`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="versions">Allowed versions</SelectItem>
                          <SelectItem value="deny">Banned</SelectItem>
                          <SelectItem value="allow">Trusted</SelectItem>
                        </SelectContent>
                      </Select>
                    </td>
                    <td className="py-1 pr-2">
                      {mode === 'versions' ? (
                        <>
                          <Input aria-label={`Rule ${i + 1} versions`} aria-invalid={bad} className="w-40 font-mono" placeholder=">=4.17.21 <5" value={r.versions ?? ''} onChange={(e) => update(i, { versions: e.target.value })} disabled={ro} />
                          {bad && <p className="mt-1 text-xs text-destructive">Use e.g. &gt;=1.2.0 &lt;2 or &lt;2 || &gt;=3</p>}
                        </>
                      ) : (
                        <span className="inline-block pt-2 text-xs text-muted-foreground">{mode === 'deny' ? 'every version' : 'skips suspicious/license checks'}</span>
                      )}
                    </td>
                    <td className="py-1 pr-2">
                      <Select value={r.severity ?? 'high'} onValueChange={(v) => update(i, { severity: v as Severity })} disabled={ro || mode === 'allow'}>
                        <SelectTrigger className="w-32" aria-label={`Rule ${i + 1} severity`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {SEVERITIES.map((s) => (
                            <SelectItem key={s} value={s} className="capitalize">
                              {s}
                              {s === 'critical' || s === 'high' ? ' (blocks)' : ' (warns)'}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </td>
                    <td className="py-1 pr-2">
                      <Input aria-label={`Rule ${i + 1} reason`} className="w-48" placeholder="Why this rule exists" value={r.reason ?? ''} onChange={(e) => update(i, { reason: e.target.value })} disabled={ro} />
                    </td>
                    <td className="py-1">
                      {!ro && (
                        <Button type="button" variant="ghost" size="icon" aria-label={`Remove rule ${i + 1}`} onClick={() => onChange(rules.filter((_, j) => j !== i))}>
                          <Trash2 />
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {!ro && (
        <Button type="button" variant="outline" className="w-fit" onClick={() => onChange([...rules, { ecosystem: 'npm', name: '', versions: '' }])}>
          <Plus /> Add package rule
        </Button>
      )}
    </Preset>
  );
}
