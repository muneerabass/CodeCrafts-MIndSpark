'use client';

import { useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import { ArrowUp, Check, Copy, History, Loader2, MessageCircleQuestion, Plus, Sparkles, Trash2, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Markdown, safeHref } from '@/components/markdown';
import { assistantBriefing, assistantConversation, assistantConversations, assistantDeleteConversation } from '@/lib/actions';
import { ago } from '@/lib/format';
import type { AssistantBriefing, AssistantContext, AssistantConversation, AssistantSource, AssistantStep } from '@/lib/types';
import { cn } from '@/lib/utils';

type Msg = {
  role: 'user' | 'assistant';
  text: string;
  steps?: AssistantStep[];
  sources?: AssistantSource[];
  error?: string;
  streaming?: boolean;
};

/** What the user is looking at, so "this project" / "this PR" mean something to the assistant. */
export function pageContext(path: string): AssistantContext {
  const s = path.split('/').filter(Boolean);
  if (s[0] === 'pull-requests' && s[1] && s[2])
    return {
      path,
      pr: { project_id: s[1], number: Number(s[2]) },
      project_id: s[1],
    };
  if (s[0] === 'projects' && s[1]) return { path, project_id: s[1] };
  if (s[0] === 'vulnerabilities' && s[1]) return { path, vuln: decodeURIComponent(s[1]) };
  return { path };
}

function suggestions(c: AssistantContext): string[] {
  if (c.pr) return ['Why is this PR blocked?', 'What should I change to make it pass?', 'Is any new package in it risky?'];
  if (c.vuln) return [`Are we affected by ${c.vuln}?`, 'Where does this reach our code?', 'How do I fix it?'];
  if (c.project_id) return ['What should I fix first in this project?', 'Which packages here are risky?', 'Summarise this project’s security'];
  return ['What should I fix first?', 'Which pull requests are blocked?', 'Summarise our security this week'];
}

const TONE = {
  red: 'bg-red-500',
  amber: 'bg-amber-500',
  green: 'bg-emerald-500',
} as const;

// Reads a server-sent event stream: calls on(event, data) per event.
async function readSSE(res: Response, on: (event: string, data: Record<string, unknown>) => void) {
  const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let i;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let event = 'message';
      let data = '';
      for (const line of chunk.split('\n')) {
        if (line.startsWith('event:')) event = line.slice(6).trim();
        else if (line.startsWith('data:')) data += line.slice(5).trim();
      }
      if (data) on(event, JSON.parse(data));
    }
  }
}

export function AssistantWidget({ isAdmin }: { isAdmin: boolean }) {
  const path = usePathname();
  const [open, setOpen] = useState(false);
  const [briefing, setBriefing] = useState<AssistantBriefing | null | 'error'>(null);
  const [view, setView] = useState<'chat' | 'history'>('chat');
  const [convs, setConvs] = useState<AssistantConversation[]>([]);
  const [convId, setConvId] = useState<string>();
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    assistantBriefing().then((r) => setBriefing(r.ok ? r.data : 'error'));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' }); // newer browsers return a Promise, which must not reach React
  }, [msgs]);

  // Members don't see a turned-off assistant at all (so nothing shows until we know); admins get a note on how to turn it back on.
  if (briefing === null || (briefing !== 'error' && !briefing.enabled && !isAdmin)) return null;
  const ready = briefing && briefing !== 'error' && briefing.enabled && briefing.configured;

  async function ask(text: string) {
    text = text.trim();
    if (!text || busy) return;
    setInput('');
    setBusy(true);
    setView('chat');
    setMsgs((m) => [...m, { role: 'user', text }, { role: 'assistant', text: '', steps: [], streaming: true }]);
    const patch = (f: (m: Msg) => Msg) => setMsgs((all) => [...all.slice(0, -1), f(all[all.length - 1])]);
    try {
      const res = await fetch('/api/assistant/chat', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          conversation_id: convId,
          message: text,
          context: pageContext(path),
        }),
      });
      if (!res.ok || !res.body) throw new Error(`The assistant is unavailable (HTTP ${res.status}).`);
      await readSSE(res, (event, d) => {
        if (event === 'step')
          patch((m) => ({
            ...m,
            steps: [...(m.steps ?? []), d as AssistantStep],
          }));
        else if (event === 'text') patch((m) => ({ ...m, text: m.text + String(d.delta ?? '') }));
        else if (event === 'error')
          patch((m) => ({
            ...m,
            error: String(d.message ?? 'Something went wrong.'),
          }));
        else if (event === 'done') {
          setConvId(String(d.conversation_id));
          patch((m) => ({
            ...m,
            steps: (d.steps as AssistantStep[]) ?? m.steps,
            sources: d.sources as AssistantSource[],
          }));
        }
      });
    } catch (e) {
      patch((m) => ({
        ...m,
        error: e instanceof Error ? e.message : 'Something went wrong.',
      }));
    } finally {
      patch((m) => ({ ...m, streaming: false }));
      setBusy(false);
    }
  }

  async function showHistory() {
    setView('history');
    const r = await assistantConversations();
    if (r.ok) setConvs(r.data);
  }

  async function openConv(id: string) {
    const r = await assistantConversation(id);
    if (!r.ok) return;
    setConvId(id);
    setMsgs(
      r.data.messages.map((m) => ({
        role: m.role,
        text: m.text,
        steps: m.steps,
        sources: m.sources,
      })),
    );
    setView('chat');
  }

  async function deleteConv(id: string) {
    const r = await assistantDeleteConversation(id);
    if (!r.ok) return;
    setConvs((c) => c.filter((x) => x.id !== id));
    if (id === convId) {
      setConvId(undefined);
      setMsgs([]);
    }
  }

  function newChat() {
    setConvId(undefined);
    setMsgs([]);
    setView('chat');
  }

  return (
    <>
      {!open && (
        <Button aria-label="Ask depguard" title="Ask depguard (Ctrl+/)" onClick={() => setOpen(true)} className="fixed right-4 bottom-4 z-40 h-11 gap-2 rounded-full pr-4 pl-3 shadow-lg">
          <Sparkles className="size-4" /> Ask depguard
        </Button>
      )}
      {open && (
        <section
          role="dialog"
          aria-label="Ask depguard"
          className="fixed inset-0 z-50 flex flex-col overflow-hidden border bg-background shadow-2xl sm:inset-auto sm:right-4 sm:bottom-4 sm:h-[min(600px,calc(100vh-2rem))] sm:w-[400px] sm:rounded-xl"
        >
          <header className="flex items-center gap-1 border-b px-3 py-2">
            <Sparkles className="size-4 text-primary" />
            <h2 className="mr-auto text-sm font-semibold">Ask depguard</h2>
            <Button variant="ghost" size="icon" className="size-8" aria-label="New chat" title="New chat" onClick={newChat} disabled={busy}>
              <Plus className="size-4" />
            </Button>
            <Button variant="ghost" size="icon" className="size-8" aria-label="History" title="History" onClick={showHistory} disabled={busy}>
              <History className="size-4" />
            </Button>
            <Button variant="ghost" size="icon" className="size-8" aria-label="Close" title="Close (Ctrl+/)" onClick={() => setOpen(false)}>
              <X className="size-4" />
            </Button>
          </header>

          <div className="min-h-0 flex-1 overflow-y-auto p-3 text-sm">
            {briefing === 'error' ? (
              <Note>Assistant unavailable right now. Try again in a minute.</Note>
            ) : !briefing.enabled ? (
              <Note>
                The assistant is turned off for this organization. Turn it on in{' '}
                <a className="underline" href="/settings/ai">
                  Settings → AI
                </a>
                .
              </Note>
            ) : view === 'history' ? (
              <ul className="grid gap-1">
                {convs.length === 0 && <li className="text-muted-foreground">No conversations in the last 30 days.</li>}
                {convs.map((c) => (
                  <li key={c.id} className="flex items-center gap-2 rounded-md hover:bg-muted">
                    <button className="min-w-0 flex-1 px-2 py-1.5 text-left" onClick={() => openConv(c.id)}>
                      <span className="block truncate">{c.title}</span>
                      <span className="text-xs text-muted-foreground">{ago(c.updated_at)}</span>
                    </button>
                    <Button variant="ghost" size="icon" className="size-8 shrink-0" aria-label={`Delete ${c.title}`} onClick={() => deleteConv(c.id)}>
                      <Trash2 className="size-4" />
                    </Button>
                  </li>
                ))}
              </ul>
            ) : msgs.length === 0 ? (
              <div className="grid gap-4">
                {!briefing.configured && <Note>AI is not configured on this server yet.</Note>}
                {briefing.items.length > 0 && (
                  <ul className="grid gap-1.5">
                    {briefing.items.map((b) => (
                      <li key={b.text} className="flex items-start gap-2">
                        <span className={cn('mt-1.5 size-2 shrink-0 rounded-full', TONE[b.tone])} />
                        {safeHref(b.url) ? (
                          <a href={safeHref(b.url)!} className="hover:underline">
                            {b.text}
                          </a>
                        ) : (
                          b.text
                        )}
                      </li>
                    ))}
                  </ul>
                )}
                {ready && (
                  <div className="grid gap-1.5">
                    <p className="text-xs font-medium text-muted-foreground">Try asking</p>
                    {suggestions(pageContext(path)).map((s) => (
                      <button key={s} onClick={() => ask(s)} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-left hover:bg-muted">
                        <MessageCircleQuestion className="size-4 shrink-0 text-primary" /> {s}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="grid gap-3">
                {msgs.map((m, i) =>
                  m.role === 'user' ? (
                    <p key={i} className="ml-8 justify-self-end rounded-lg bg-primary px-3 py-2 text-primary-foreground">
                      {m.text}
                    </p>
                  ) : (
                    <Answer key={i} m={m} />
                  ),
                )}
                <div ref={bottom} />
              </div>
            )}
          </div>

          {ready && (
            <form
              className="flex items-end gap-2 border-t p-2"
              onSubmit={(e) => {
                e.preventDefault();
                ask(input);
              }}
            >
              <Textarea
                aria-label="Message"
                placeholder="Ask about your projects, PRs, vulnerabilities…"
                value={input}
                maxLength={4000}
                rows={1}
                className="max-h-32 min-h-9 resize-none"
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    ask(input);
                  }
                }}
              />
              <Button type="submit" size="icon" aria-label="Send" disabled={busy || !input.trim()}>
                {busy ? <Loader2 className="size-4 animate-spin" /> : <ArrowUp className="size-4" />}
              </Button>
            </form>
          )}
        </section>
      )}
    </>
  );
}

function Note({ children }: { children: React.ReactNode }) {
  return <p className="rounded-md border bg-muted/50 p-3 text-muted-foreground">{children}</p>;
}

function Answer({ m }: { m: Msg }) {
  const [copied, setCopied] = useState(false);
  const sources = (m.sources ?? []).filter((s) => safeHref(s.url));
  return (
    <div className="grid gap-2">
      {m.streaming && !m.text && !m.error && (
        <p className="flex items-center gap-2 text-muted-foreground">
          <Loader2 className="size-3.5 animate-spin" /> {m.steps?.at(-1)?.label ?? 'Thinking'}…
        </p>
      )}
      {m.text && <Markdown strict>{m.text}</Markdown>}
      {m.error && <p className="rounded-md border border-red-500/30 bg-red-500/10 p-2 text-red-700 dark:text-red-300">{m.error}</p>}
      {sources.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {sources.map((s) => (
            <a key={s.url} href={safeHref(s.url)!} className="rounded-full border px-2 py-0.5 text-xs hover:bg-muted">
              {s.title}
            </a>
          ))}
        </div>
      )}
      {!m.streaming && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {!!m.steps?.length && (
            <details className="min-w-0 flex-1">
              <summary className="cursor-pointer select-none">How I found this</summary>
              <ul className="mt-1 grid gap-1">
                {m.steps.map((s, i) => (
                  <li key={i}>
                    {s.label}
                    {s.sql && <pre className="mt-1 overflow-x-auto rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap break-all">{s.sql}</pre>}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {m.text && (
            <button
              className="ml-auto flex items-center gap-1 self-start hover:text-foreground"
              aria-label="Copy answer"
              onClick={() => navigator.clipboard.writeText(m.text).then(() => setCopied(true))}
            >
              {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied ? 'Copied' : 'Copy'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
