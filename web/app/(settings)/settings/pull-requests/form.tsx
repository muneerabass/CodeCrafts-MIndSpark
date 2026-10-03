'use client';

import { useState } from 'react';
import { Bot, Loader2, MessageSquare, Tags } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Markdown } from '@/components/markdown';
import { useAction } from '@/components/client';
import { savePRSettings } from '@/lib/actions';
import type { PRSettings, PRSettingsResponse } from '@/lib/types';

const SECTIONS: { key: string; label: string; hint: string }[] = [
  { key: 'fix_commands', label: 'Fix before merging', hint: 'The most important issues with the exact command that fixes each one.' },
  { key: 'code_review', label: 'Code security review', hint: 'Findings of the rule-based and AI review of the changed code.' },
  { key: 'vulnerabilities', label: 'Package details', hint: 'Collapsible table of every new or changed package and policy violation.' },
  { key: 'suspicious', label: 'Suspicious packages', hint: 'Typosquats, unmaintained, deprecated and possibly malicious packages.' },
  { key: 'licenses', label: 'License issues', hint: 'License problems for how this project is distributed.' },
  { key: 'run_config', label: 'Run configuration', hint: 'Policy, checks and files reviewed, collapsed by default.' },
];

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

export function PRSettingsForm({ initial, canEdit }: { initial: PRSettingsResponse; canEdit: boolean }) {
  const [s, setS] = useState<PRSettings>(initial.settings);
  const [saved, setSaved] = useState(JSON.stringify(initial.settings));
  const { pending, run } = useAction();
  const ro = !canEdit;
  const dirty = JSON.stringify(s) !== saved;
  const set = (patch: Partial<PRSettings>) => setS({ ...s, ...patch });

  return (
    <div className="grid gap-4">
      {ro && <p className="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">You have read-only access. Owners and admins can change these settings.</p>}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <MessageSquare className="size-4 text-primary" /> PR comment
          </CardTitle>
          <CardDescription>depguard keeps one comment per pull request and edits it on every push.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          <Row id="pr-mode" title="When to comment" hint="The check run is always reported, whatever you choose here.">
            <Select value={s.comment_mode} onValueChange={(v) => set({ comment_mode: v as PRSettings['comment_mode'] })} disabled={ro}>
              <SelectTrigger id="pr-mode" className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="always">On every pull request</SelectItem>
                <SelectItem value="issues">Only when there are findings</SelectItem>
                <SelectItem value="never">Never (check run only)</SelectItem>
              </SelectContent>
            </Select>
          </Row>
          {SECTIONS.map((sec) => (
            <Row key={sec.key} id={`pr-sec-${sec.key}`} title={sec.label} hint={sec.hint}>
              <Switch id={`pr-sec-${sec.key}`} checked={s.sections[sec.key] ?? true} disabled={ro} onCheckedChange={(v) => set({ sections: { ...s.sections, [sec.key]: v } })} />
            </Row>
          ))}
          <Row id="pr-mention" title="Mention the author on blocking issues" hint="Adds @author to the warning so they get a notification.">
            <Switch id="pr-mention" checked={s.mention_author_on_block} disabled={ro} onCheckedChange={(v) => set({ mention_author_on_block: v })} />
          </Row>
          <Row id="pr-reqchanges" title="Request changes on blocking issues" hint="Submits a 'Changes requested' review, dismissed automatically once the issues are fixed. Needs the GitHub App permission Pull requests: Read and write.">
            <Switch id="pr-reqchanges" checked={s.request_changes_on_block} disabled={ro} onCheckedChange={(v) => set({ request_changes_on_block: v })} />
          </Row>
          <div className="grid gap-3 pt-3 md:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="pr-header">Header (Markdown)</Label>
              <Textarea id="pr-header" rows={3} maxLength={2000} value={s.header} onChange={(e) => set({ header: e.target.value })} placeholder="e.g. Security questions? Ask in #appsec." disabled={ro} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="pr-footer">Footer (Markdown)</Label>
              <Textarea id="pr-footer" rows={3} maxLength={2000} value={s.footer} onChange={(e) => set({ footer: e.target.value })} placeholder="e.g. Policy: https://wiki.example.com/dependencies" disabled={ro} />
            </div>
          </div>
          {(s.header.trim() || s.footer.trim()) && (
            <div className="pt-3">
              <p className="mb-1 text-xs font-medium text-muted-foreground">Preview</p>
              <div className="rounded-md border p-3 text-sm">
                {s.header.trim() && <Markdown>{s.header}</Markdown>}
                <p className="my-2 font-semibold">depguard Report Summary</p>
                <p className="text-muted-foreground">… status badges, urgency, fixes and findings …</p>
                {s.footer.trim() && <Markdown>{s.footer}</Markdown>}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Tags className="size-4 text-primary" /> Labels
          </CardTitle>
          <CardDescription>Labels such as depguard:blocked, depguard:urgent, depguard:malware, depguard:security, depguard:frontend or depguard:size/M. Labels without the prefix are never touched.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          <Row id="pr-labels" title="Add labels on GitHub" hint="Kept in sync on every push.">
            <Switch id="pr-labels" checked={s.labels.enabled} disabled={ro} onCheckedChange={(v) => set({ labels: { ...s.labels, enabled: v } })} />
          </Row>
          <Row id="pr-prefix" title="Label prefix" hint="Lets depguard manage only its own labels.">
            <Input id="pr-prefix" className="w-40 font-mono" maxLength={20} value={s.labels.prefix} onChange={(e) => set({ labels: { ...s.labels, prefix: e.target.value } })} disabled={ro || !s.labels.enabled} />
          </Row>
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Bot className="size-4 text-primary" /> AI security review
          </CardTitle>
          <CardDescription>
            Reviews the changed code for vulnerabilities (injection, access control, SSRF, secrets, unsafe deserialization, insecure configuration…). The changed code is sent to the
            configured model on Amazon Bedrock. A rule-based review always runs as well.
          </CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          <p className={initial.ai_configured ? 'pb-3 text-sm text-emerald-700 dark:text-emerald-300' : 'pb-3 text-sm text-amber-700 dark:text-amber-300'}>
            {initial.ai_configured ? `AI model configured${initial.ai_models ? `: ${initial.ai_models.split(',')[0]}` : ''}.` : 'No AI model is configured on the server; only the rule-based review runs.'}
          </p>
          <Row id="pr-ai" title="Run the AI security review" hint="On every new commit of an open pull request.">
            <Switch id="pr-ai" checked={s.ai_review.enabled} disabled={ro} onCheckedChange={(v) => set({ ai_review: { ...s.ai_review, enabled: v } })} />
          </Row>
          <Row id="pr-ai-size" title="Largest diff to review (KB)" hint="Bigger diffs are cut to this size; the rest is covered by the rule-based review.">
            <Input
              id="pr-ai-size"
              type="number"
              min={10}
              max={1000}
              className="w-28"
              value={s.ai_review.max_diff_kb}
              onChange={(e) => set({ ai_review: { ...s.ai_review, max_diff_kb: Number(e.target.value) } })}
              disabled={ro || !s.ai_review.enabled}
            />
          </Row>
        </CardContent>
      </Card>

      {!ro && (
        <div className="sticky bottom-0 flex justify-end gap-2 border-t bg-background/95 py-3 backdrop-blur">
          <Button variant="outline" disabled={!dirty || pending} onClick={() => setS(JSON.parse(saved))}>
            Discard changes
          </Button>
          <Button
            disabled={!dirty || pending}
            onClick={async () => {
              const r = await run(() => savePRSettings(s), 'Pull request settings saved');
              if (r) {
                setS(r.settings);
                setSaved(JSON.stringify(r.settings));
              }
            }}
          >
            {pending && <Loader2 className="animate-spin" />} Save settings
          </Button>
        </div>
      )}
    </div>
  );
}
