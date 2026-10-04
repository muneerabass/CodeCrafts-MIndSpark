'use client';

import { useState } from 'react';
import { toast } from 'sonner';
import { Bell, CalendarDays, Loader2, Mail, MessageSquare, Send, Ticket } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAction } from '@/components/client';
import { saveNotifications, testNotification } from '@/lib/actions';
import type { NotificationSettings, NotificationsResponse } from '@/lib/types';

const EVENTS: { key: keyof NotificationSettings['events']; label: string; hint: string }[] = [
  { key: 'malware', label: 'Malicious package found', hint: 'A scan finds a known or detected malicious package.' },
  { key: 'critical', label: 'New critical vulnerability', hint: 'A critical advisory starts affecting one of your projects.' },
  { key: 'kev', label: 'Actively exploited vulnerability', hint: 'Any vulnerability on CISA’s Known Exploited list, at any level.' },
  { key: 'pr_blocked', label: 'Pull request blocked', hint: 'A pull request fails the depguard check (once per push).' },
  { key: 'overdue', label: 'Fix deadline missed', hint: 'A vulnerability is still there after its deadline (daily check).' },
];
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

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

export function NotificationsForm({ initial, suggested, canEdit }: { initial: NotificationsResponse; suggested: string[]; canEdit: boolean }) {
  const [state, setState] = useState(initial);
  const [s, setS] = useState(initial.settings);
  const [emails, setEmails] = useState(initial.settings.email_to.join(', '));
  const [slack, setSlack] = useState('');
  const [jiraToken, setJiraToken] = useState('');
  const { pending, run } = useAction();
  const test = useAction();
  const ro = !canEdit;
  const ev = (k: keyof NotificationSettings['events'], v: boolean) => setS({ ...s, events: { ...s.events, [k]: v } });
  const jira = (patch: Partial<NotificationSettings['jira']>) => setS({ ...s, jira: { ...s.jira, ...patch } });

  const save = (extra: { slack_webhook_url?: string; jira_token?: string } = {}) => {
    const settings = { ...s, email_to: emails.split(/[\s,;]+/).filter(Boolean) };
    const body = { settings, ...extra };
    if (slack) body.slack_webhook_url = slack;
    if (jiraToken) body.jira_token = jiraToken;
    return run(() => saveNotifications(body), 'Notification settings saved').then((r) => {
      if (!r) return;
      setState(r);
      setS(r.settings);
      setEmails(r.settings.email_to.join(', '));
      setSlack('');
      setJiraToken('');
    });
  };
  const sendTest = (c: 'slack' | 'email' | 'jira') =>
    test.run(() => testNotification(c)).then((r) => r && toast.success(c === 'jira' ? 'Connected to Jira' : `Test ${c === 'slack' ? 'message' : 'email'} sent`));

  return (
    <div className="grid gap-4">
      {ro && <p className="rounded-md border bg-muted/50 p-3 text-sm text-muted-foreground">You have read-only access. Owners and admins can change these settings.</p>}
      {!state.secrets_enabled && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">This server has no encryption key (DEPGUARD_SECRET_KEY), so Slack and Jira cannot be connected yet.</p>
      )}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <MessageSquare className="size-4 text-primary" /> Slack
          </CardTitle>
          <CardDescription>
            Create an{' '}
            <a className="text-primary hover:underline" href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noreferrer">
              incoming webhook
            </a>{' '}
            for the channel that should get alerts, then paste its URL.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              aria-label="Slack webhook URL"
              type="password"
              autoComplete="off"
              disabled={ro || !state.secrets_enabled}
              placeholder={state.slack_configured ? `Connected (${state.slack_hint}). Paste a new URL to replace it.` : 'https://hooks.slack.com/services/…'}
              value={slack}
              onChange={(e) => setSlack(e.target.value)}
              className="min-w-0 flex-1"
            />
            {state.slack_configured && !ro && (
              <>
                <Button variant="outline" size="sm" disabled={test.pending} onClick={() => sendTest('slack')}>
                  <Send className="size-3.5" /> Send test
                </Button>
                <Button variant="ghost" size="sm" disabled={pending} onClick={() => save({ slack_webhook_url: '' })}>
                  Disconnect
                </Button>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Mail className="size-4 text-primary" /> Email
          </CardTitle>
          <CardDescription>{state.email_configured ? 'Alerts and the weekly digest go to these addresses.' : 'Email is not configured on this server (SMTP), so only Slack will be used.'}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <Input aria-label="Email recipients" disabled={ro} placeholder="security@your-company.com, lead@your-company.com" value={emails} onChange={(e) => setEmails(e.target.value)} className="min-w-0 flex-1" />
            {state.email_configured && state.settings.email_to.length > 0 && !ro && (
              <Button variant="outline" size="sm" disabled={test.pending} onClick={() => sendTest('email')}>
                <Send className="size-3.5" /> Send test
              </Button>
            )}
          </div>
          {suggested.length > 0 && !ro && (
            <p className="text-xs text-muted-foreground">
              Owners and admins:{' '}
              {suggested.map((e) => (
                <button key={e} type="button" className="mr-2 text-primary hover:underline" onClick={() => !emails.includes(e) && setEmails(emails ? `${emails}, ${e}` : e)}>
                  + {e}
                </button>
              ))}
            </p>
          )}
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Bell className="size-4 text-primary" /> What to alert on
          </CardTitle>
          <CardDescription>Each finding is sent once. A scan with many findings sends one message with the top 10.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          {EVENTS.map((e) => (
            <Row key={e.key} id={`ev-${e.key}`} title={e.label} hint={e.hint}>
              <Switch id={`ev-${e.key}`} checked={s.events[e.key]} disabled={ro} onCheckedChange={(v) => ev(e.key, v)} />
            </Row>
          ))}
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <CalendarDays className="size-4 text-primary" /> Weekly digest
          </CardTitle>
          <CardDescription>New and fixed vulnerabilities, missed deadlines, malware, risky pull requests and the top 5 things to fix.</CardDescription>
        </CardHeader>
        <CardContent className="divide-y">
          <Row id="dg-on" title="Send a weekly digest" hint="Sent at 08:00 UTC on the day you choose.">
            <Switch id="dg-on" checked={s.digest.enabled} disabled={ro} onCheckedChange={(v) => setS({ ...s, digest: { ...s.digest, enabled: v } })} />
          </Row>
          <Row id="dg-day" title="Day" hint="The digest covers the 7 days before it.">
            <Select value={String(s.digest.weekday)} disabled={ro || !s.digest.enabled} onValueChange={(v) => setS({ ...s, digest: { ...s.digest, weekday: Number(v) } })}>
              <SelectTrigger id="dg-day" className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DAYS.map((d, i) => (
                  <SelectItem key={d} value={String(i)}>
                    {d}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Row>
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Ticket className="size-4 text-primary" /> Jira
          </CardTitle>
          <CardDescription>
            Lets admins click <b>Create Jira ticket</b> on a vulnerability or a package in the fix queue. Jira Cloud only. Create an{' '}
            <a className="text-primary hover:underline" href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noreferrer">
              API token
            </a>{' '}
            for the account below.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <div>
            <Label htmlFor="jira-url">Jira site</Label>
            <Input id="jira-url" className="mt-1.5" disabled={ro} placeholder="https://your-site.atlassian.net" value={s.jira.base_url} onChange={(e) => jira({ base_url: e.target.value })} />
          </div>
          <div>
            <Label htmlFor="jira-email">Account email</Label>
            <Input id="jira-email" className="mt-1.5" disabled={ro} placeholder="bot@your-company.com" value={s.jira.email} onChange={(e) => jira({ email: e.target.value })} />
          </div>
          <div>
            <Label htmlFor="jira-project">Project key</Label>
            <Input id="jira-project" className="mt-1.5" disabled={ro} placeholder="SEC" value={s.jira.project_key} onChange={(e) => jira({ project_key: e.target.value.toUpperCase() })} />
          </div>
          <div>
            <Label htmlFor="jira-type">Issue type</Label>
            <Input id="jira-type" className="mt-1.5" disabled={ro} placeholder="Task" value={s.jira.issue_type} onChange={(e) => jira({ issue_type: e.target.value })} />
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="jira-token">API token</Label>
            <div className="mt-1.5 flex flex-wrap gap-2">
              <Input
                id="jira-token"
                type="password"
                autoComplete="off"
                disabled={ro || !state.secrets_enabled}
                placeholder={state.jira_token_set ? 'Saved. Paste a new token to replace it.' : 'Paste the API token'}
                value={jiraToken}
                onChange={(e) => setJiraToken(e.target.value)}
                className="min-w-0 flex-1"
              />
              {state.jira_token_set && !ro && (
                <Button variant="outline" size="sm" disabled={test.pending} onClick={() => sendTest('jira')}>
                  <Send className="size-3.5" /> Test connection
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {!ro && (
        <div className="flex justify-end">
          <Button disabled={pending} onClick={() => save()}>
            {pending && <Loader2 className="size-4 animate-spin" />} Save settings
          </Button>
        </div>
      )}
    </div>
  );
}
