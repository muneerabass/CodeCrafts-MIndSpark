'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ShieldCheck, Sparkles } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { useAction } from '@/components/client';
import { saveAssistantSettings } from '@/lib/actions';
import type { AssistantSettings } from '@/lib/types';

const PROVIDER: Record<string, string> = {
  gemini: 'Google Gemini',
  bedrock: 'Amazon Bedrock',
};

export function AIForm({ initial, canEdit }: { initial: AssistantSettings; canEdit: boolean }) {
  const [s, setS] = useState(initial);
  const { pending, run } = useAction();
  const toggle = async (enabled: boolean) => {
    const r = await run(() => saveAssistantSettings(enabled), enabled ? 'Assistant turned on' : 'Assistant turned off');
    if (r) setS(r);
  };
  const u = s.usage_30d;

  return (
    <div className="grid gap-4">
      {!canEdit && <p className="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">You have read-only access. Owners and admins can change these settings.</p>}
      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Sparkles className="size-4 text-primary" /> Assistant
          </CardTitle>
          <CardDescription>On by default. When it’s off, the button disappears for members; admins see a note pointing here.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-start justify-between gap-6">
            <div>
              <Label htmlFor="ai-enabled" className="font-medium">
                Turn on Ask depguard
              </Label>
              <p className="mt-0.5 text-sm text-muted-foreground">
                {s.configured ? (
                  <>
                    Answers come from {PROVIDER[s.provider] ?? s.provider} (<code className="font-mono text-xs">{s.model}</code>).
                  </>
                ) : (
                  'No AI provider is configured on this server yet, so the assistant can’t answer even when it’s on.'
                )}
              </p>
            </div>
            <Switch id="ai-enabled" checked={s.enabled} disabled={!canEdit || pending} onCheckedChange={toggle} />
          </div>
          <dl className="grid grid-cols-3 gap-3 rounded-md border p-3 text-sm">
            {[
              ['Questions', u.questions],
              ['Input tokens', u.input_tokens],
              ['Output tokens', u.output_tokens],
            ].map(([k, v]) => (
              <div key={k}>
                <dt className="text-xs text-muted-foreground">{k}</dt>
                <dd className="font-semibold tabular-nums">{Number(v).toLocaleString('en')}</dd>
              </div>
            ))}
          </dl>
          <p className="-mt-2 text-xs text-muted-foreground">Usage over the last 30 days.</p>
        </CardContent>
      </Card>
      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheck className="size-4 text-primary" /> What the assistant can see
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm text-muted-foreground">
          <p>Questions and the relevant workspace data are sent to {PROVIDER[s.provider] ?? 'the AI provider'}; nothing is used for training.</p>
          <p>It sees exactly what the person asking can see, and it’s read-only: it never changes settings, opens pull requests or dismisses findings.</p>
          <p>From the secure vault it sees names and metadata only. Secret values are end-to-end encrypted and never reach the assistant or the AI provider.</p>
          <p>Conversations are private to each person and deleted after 30 days. Answers about general security that don’t come from your data are labelled as such.</p>
          <p>
            The AI review of pull requests is set separately in{' '}
            <Link href="/settings/pull-requests" className="text-foreground underline">
              Pull request settings
            </Link>
            .
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
