'use client';

import { useState } from 'react';
import { toast } from 'sonner';
import { GitMerge, GitPullRequestArrow, Loader2, Wand2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { CopyButton, useAction } from '@/components/client';
import { createFix } from '@/lib/actions';
import type { FixPR } from '@/lib/types';
import { cn } from '@/lib/utils';

type Pkg = { ecosystem: string; name: string; version: string; manifest_path: string };

/** Status of an existing fix PR, or a button that opens one. */
export function FixButton({ projectId, pkg, fix, canEdit, className }: { projectId: string; pkg: Pkg; fix?: FixPR; canEdit: boolean; className?: string }) {
  const { pending, run } = useAction();
  const [command, setCommand] = useState<{ cmd: string; why: string } | null>(null);

  if (fix && (fix.status === 'open' || fix.status === 'merged') && fix.pr_url) {
    const merged = fix.status === 'merged';
    return (
      <a
        href={fix.pr_url}
        target="_blank"
        rel="noreferrer"
        className={cn(
          'inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium',
          merged ? 'bg-violet-500/15 text-violet-700 dark:text-violet-300' : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
          className,
        )}
      >
        {merged ? <GitMerge className="size-3.5" aria-hidden /> : <GitPullRequestArrow className="size-3.5" aria-hidden />}
        {merged ? 'Fixed' : 'Fix PR'} #{fix.pr_number} {merged ? 'merged' : 'open'}
      </a>
    );
  }
  if (fix?.status === 'queued')
    return (
      <span className={cn('inline-flex items-center gap-1.5 rounded-md bg-sky-500/15 px-2 py-1 text-xs font-medium text-sky-700 dark:text-sky-300', className)}>
        <Loader2 className="size-3.5 animate-spin" aria-hidden /> Opening fix PR…
      </span>
    );
  if (command)
    return (
      <div className={cn('flex flex-wrap items-center gap-2 text-xs', className)}>
        <span className="text-muted-foreground">{command.why}</span>
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{command.cmd}</code>
        <CopyButton value={command.cmd} />
      </div>
    );
  if (!canEdit) return null;

  const failed = fix?.status === 'failed' || fix?.status === 'unsupported';
  return (
    <div className={cn('flex flex-wrap items-center gap-2', className)}>
      <Button
        size="sm"
        variant={failed ? 'outline' : 'default'}
        disabled={pending}
        onClick={() =>
          run(() => createFix(projectId, pkg)).then((r) => {
            if (!r) return;
            if (r.status === 'unsupported') setCommand({ cmd: r.command, why: 'No automatic fix for this lockfile. Run:' });
            else toast.success(r.status === 'exists' ? 'A fix PR is already open' : `Opening a PR to upgrade ${pkg.name} to ${r.to_version}`);
          })
        }
      >
        {pending ? <Loader2 className="size-3.5 animate-spin" aria-hidden /> : <Wand2 className="size-3.5" aria-hidden />}
        {failed ? 'Retry fix PR' : 'Create fix PR'}
      </Button>
      {failed && fix?.error && (
        <span className="max-w-md text-xs text-red-600 dark:text-red-400" title={fix.error}>
          {fix.error.length > 120 ? fix.error.slice(0, 120) + '…' : fix.error}
        </span>
      )}
    </div>
  );
}
