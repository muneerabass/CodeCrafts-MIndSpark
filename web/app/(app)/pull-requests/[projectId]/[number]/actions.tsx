'use client';

import { useState } from 'react';
import { Bot, Loader2, MessageSquare, RefreshCw, ShieldX } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Markdown } from '@/components/markdown';
import { useAction } from '@/components/client';
import { prAction, type PRActionKind } from '@/lib/actions';
import { cn } from '@/lib/utils';

const TEMPLATES: { label: string; text: string }[] = [
  { label: 'Ask to upgrade', text: 'Please upgrade the vulnerable dependencies listed in the depguard report before merging. The exact commands are in the "Fix before merging" section.' },
  { label: 'Security fix needed', text: 'depguard found a security issue in this change. Please address it (see the code review findings) and push a new commit; the review re-runs automatically.' },
  { label: 'Accepted risk', text: 'Reviewed by the security team: the reported finding is an accepted risk for this change and is tracked separately.' },
];

/** Comment editor and PR actions (admins and owners). */
export function PRActions({ projectId, number, canEdit, open }: { projectId: string; number: number; canEdit: boolean; open: boolean }) {
  const [body, setBody] = useState('');
  const [tab, setTab] = useState<'write' | 'preview'>('write');
  const { pending, run } = useAction();
  const disabled = !canEdit || !open || pending;
  const go = async (action: PRActionKind, ok: string) => {
    const r = await run(() => prAction(projectId, number, action, action === 'comment' || action === 'review' ? body : undefined), ok);
    if (r && (action === 'comment' || action === 'review')) setBody('');
  };
  return (
    <div className="space-y-3">
      {!canEdit && <p className="rounded-md bg-muted p-2 text-xs text-muted-foreground">You have read-only access. Admins and owners can comment and act on pull requests.</p>}
      {canEdit && !open && <p className="rounded-md bg-muted p-2 text-xs text-muted-foreground">This pull request is no longer open.</p>}
      <div className="flex gap-1 border-b text-sm" role="tablist" aria-label="Comment editor">
        {(['write', 'preview'] as const).map((t) => (
          <button
            key={t}
            role="tab"
            type="button"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={cn('-mb-px border-b-2 px-3 py-1.5 capitalize', tab === t ? 'border-primary font-medium' : 'border-transparent text-muted-foreground')}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === 'write' ? (
        <>
          <Label htmlFor="pr-comment" className="sr-only">
            Comment
          </Label>
          <Textarea id="pr-comment" rows={6} value={body} onChange={(e) => setBody(e.target.value)} placeholder="Write a comment (Markdown supported). It is posted on the pull request in GitHub." disabled={disabled} />
          <div className="flex flex-wrap gap-1">
            {TEMPLATES.map((t) => (
              <button key={t.label} type="button" disabled={disabled} onClick={() => setBody(t.text)} className="rounded-full border px-2 py-0.5 text-xs text-muted-foreground hover:bg-muted disabled:opacity-50">
                {t.label}
              </button>
            ))}
          </div>
        </>
      ) : (
        <div className="min-h-[9rem] rounded-md border p-3 text-sm">{body.trim() ? <Markdown>{body}</Markdown> : <p className="text-muted-foreground">Nothing to preview.</p>}</div>
      )}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" disabled={disabled || !body.trim()} onClick={() => go('comment', 'Comment queued for GitHub')}>
          {pending ? <Loader2 className="animate-spin" /> : <MessageSquare />} Post comment
        </Button>
        <Button size="sm" variant="outline" disabled={disabled || !body.trim()} onClick={() => go('review', 'Change request queued for GitHub')}>
          <ShieldX /> Request changes
        </Button>
      </div>
      <div className="flex flex-wrap gap-2 border-t pt-3">
        <Button size="sm" variant="ghost" disabled={disabled} onClick={() => go('rescan', 'Rescan queued')}>
          <RefreshCw /> Rescan
        </Button>
        <Button size="sm" variant="ghost" disabled={disabled} onClick={() => go('ai-review', 'AI security review queued')}>
          <Bot /> Re-run AI review
        </Button>
      </div>
    </div>
  );
}
