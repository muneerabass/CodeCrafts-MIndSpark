'use client';

import { useState } from 'react';
import { Loader2, Ticket } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAction } from '@/components/client';
import { createJiraIssue } from '@/lib/actions';
import type { JiraLink } from '@/lib/types';

/** Link to the Jira issue of a vulnerability/package, or a button that creates it. */
export function JiraButton({ refKind, refId, link, enabled }: { refKind: 'vuln' | 'package'; refId: string; link?: JiraLink; enabled: boolean }) {
  const [made, setMade] = useState<{ issue_key: string; url: string } | null>(null);
  const { pending, run } = useAction();
  const l = link ?? made;
  if (l)
    return (
      <a href={l.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-md bg-sky-500/15 px-2 py-1 text-xs font-medium text-sky-700 dark:text-sky-300">
        <Ticket className="size-3.5" aria-hidden /> {l.issue_key}
      </a>
    );
  if (!enabled) return null;
  return (
    <Button size="sm" variant="outline" disabled={pending} onClick={() => run(() => createJiraIssue(refKind, refId), 'Jira ticket created').then((r) => r && setMade(r))}>
      {pending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Ticket className="size-3.5" aria-hidden />} Create Jira ticket
    </Button>
  );
}
