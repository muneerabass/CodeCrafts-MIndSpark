'use client';

import { useState } from 'react';
import { GitPullRequestArrow, Loader2, Wand2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAction } from '@/components/client';
import { saveFixSettings } from '@/lib/actions';
import { ago } from '@/lib/format';
import type { FixPR, FixSettings } from '@/lib/types';
import { cn } from '@/lib/utils';

const LEVELS = ['critical', 'high', 'medium', 'low'];
const STATUS: Record<string, string> = {
  queued: 'bg-sky-500/15 text-sky-700 dark:text-sky-300',
  open: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
  merged: 'bg-violet-500/15 text-violet-700 dark:text-violet-300',
  closed: 'bg-muted text-muted-foreground',
  failed: 'bg-red-500/15 text-red-700 dark:text-red-300',
  unsupported: 'bg-amber-500/15 text-amber-700 dark:text-amber-300',
};

function Row({ id, title, hint, children }: { id: string; title: string; hint: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-6 py-3 first:pt-0 last:pb-0">
      <div>
        <Label htmlFor={id} className="font-medium">
          {title}
        </Label>
        <p className="mt-0.5 text-sm text-muted-foreground">{hint}</p>
      </div>
      {children}
    </div>
  );
}

export function AutoFixForm({ initial, recent, canEdit }: { initial: FixSettings; recent: FixPR[]; canEdit: boolean }) {
  const [s, setS] = useState(initial);
  const [saved, setSaved] = useState(JSON.stringify(initial));
  const { pending, run } = useAction();
  const ro = !canEdit;
  const dirty = JSON.stringify(s) !== saved;
  const toggleLevel = (l: string) => setS({ ...s, levels: s.levels.includes(l) ? s.levels.filter((x) => x !== l) : [...s.levels, l] });

  return (
    <div className="grid gap-4">
      {ro && <p className="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">You have read-only access. Owners and admins can change these settings.</p>}
      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Wand2 className="size-4 text-primary" /> Automatic fix PRs
          </CardTitle>
          <CardDescription>
            Anyone with admin access can always click <b>Create fix PR</b> on a vulnerable package. Turn this on to open them automatically after each scan of the default branch.
          </CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          <Row id="fx-auto" title="Open fix PRs automatically" hint="Supported today: npm and pnpm lockfiles, Go modules and requirements.txt.">
            <Switch id="fx-auto" checked={s.auto} disabled={ro} onCheckedChange={(v) => setS({ ...s, auto: v })} />
          </Row>
          <Row id="fx-levels" title="Fix these risk levels" hint="Vulnerabilities at these levels get a fix PR when a fixed version exists.">
            <div id="fx-levels" className="flex flex-wrap justify-end gap-1.5">
              {LEVELS.map((l) => (
                <button
                  key={l}
                  type="button"
                  disabled={ro}
                  aria-pressed={s.levels.includes(l)}
                  onClick={() => toggleLevel(l)}
                  className={cn('rounded-md border px-2.5 py-1 text-xs font-medium capitalize', s.levels.includes(l) ? 'border-primary bg-primary text-primary-foreground' : 'text-muted-foreground hover:bg-muted')}
                >
                  {l}
                </button>
              ))}
            </div>
          </Row>
          <Row id="fx-kev" title="Always fix actively exploited" hint="Vulnerabilities in CISA's Known Exploited list get a fix PR at any level.">
            <Switch id="fx-kev" checked={s.kev} disabled={ro} onCheckedChange={(v) => setS({ ...s, kev: v })} />
          </Row>
          <Row id="fx-max" title="Open PRs per project" hint="depguard stops opening new fix PRs while this many are open, so reviewers aren't flooded.">
            <Select value={String(s.max_open)} disabled={ro} onValueChange={(v) => setS({ ...s, max_open: Number(v) })}>
              <SelectTrigger id="fx-max" className="w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {[1, 3, 5, 10, 20].map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Row>
        </CardContent>
      </Card>
      {!ro && (
        <div className="flex justify-end">
          <Button
            disabled={!dirty || pending}
            onClick={() =>
              run(() => saveFixSettings(s), 'Auto-fix settings saved').then((r) => {
                if (r) {
                  setS(r);
                  setSaved(JSON.stringify(r));
                }
              })
            }
          >
            {pending && <Loader2 className="size-4 animate-spin" />} Save changes
          </Button>
        </div>
      )}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <GitPullRequestArrow className="size-4 text-primary" /> Recent fix PRs
          </CardTitle>
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">No fix PRs yet. Open a scan report and click Create fix PR on a vulnerable package.</p>
          ) : (
            <ul className="divide-y">
              {recent.map((f) => (
                <li key={f.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                  <span className={cn('rounded-md px-2 py-0.5 text-xs font-medium capitalize', STATUS[f.status])}>{f.status}</span>
                  <span className="min-w-0 flex-1">
                    <span className="font-medium">{f.name}</span>{' '}
                    <span className="font-mono text-xs text-muted-foreground">
                      {f.from_version} → {f.to_version}
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      {f.project} · {f.trigger === 'auto' ? 'automatic' : `by ${f.created_by}`} · {ago(f.created_at)}
                    </span>
                    {f.error && <span className="block text-xs text-red-600 dark:text-red-400">{f.error}</span>}
                  </span>
                  {f.pr_url && (
                    <a href={f.pr_url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline">
                      PR #{f.pr_number} →
                    </a>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
