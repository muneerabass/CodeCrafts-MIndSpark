'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { Bug, FlaskConical, Info, Loader2, Plus, RotateCcw, Scale, Skull, Star, Trash2, Wrench, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAction } from '@/components/client';
import { savePolicy, testPolicy } from '@/lib/actions';
import type { CustomRule, Policy } from '@/lib/types';

const Monaco = dynamic(() => import('@monaco-editor/react'), {
  ssr: false,
  loading: () => <div className="h-[120px] animate-pulse rounded-md bg-muted" />,
});

const DEFAULT_DENY = ['GPL-2.0', 'GPL-3.0', 'AGPL-3.0'];
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

export function PolicyEditor({ initial, canEdit }: { initial: Policy; canEdit: boolean }) {
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

      <Preset icon={Scale} title="License" description="Flag packages whose SPDX license starts with one of these identifiers.">
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
