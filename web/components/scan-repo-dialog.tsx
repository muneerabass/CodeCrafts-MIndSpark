'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Loader2, Lock, ScanLine } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { listRepositories, startScan } from '@/lib/actions';
import type { Repository } from '@/lib/types';
import { cn } from '@/lib/utils';
import { useAction } from './client';

/** "Scan a repository": pick a repo from linked GitHub installations and queue a full scan. */
export function ScanRepoDialog({ label = 'Scan a repository', disabled }: { label?: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [repos, setRepos] = useState<Repository[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [picked, setPicked] = useState<Repository | null>(null);
  const [branch, setBranch] = useState('');
  const { pending, run } = useAction();
  const router = useRouter();

  async function load() {
    setRepos(null);
    setError(null);
    const r = await listRepositories();
    if (r.ok) setRepos(r.data);
    else setError(r.error);
  }

  const shown = repos?.filter((r) => r.full_name.toLowerCase().includes(filter.toLowerCase())) ?? [];

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) load();
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" disabled={disabled} title={disabled ? 'Only owners and admins can start scans' : undefined}>
          <ScanLine /> {label}
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Scan a repository</DialogTitle>
          <DialogDescription>Run a full scan of a repository&apos;s default branch (or another branch) from a connected GitHub installation.</DialogDescription>
        </DialogHeader>
        <Label htmlFor="repo-filter" className="sr-only">
          Search repositories
        </Label>
        <Input id="repo-filter" placeholder="Search repositories" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <div className="max-h-64 overflow-y-auto rounded-md border" role="listbox" aria-label="Repositories">
          {error && <p className="p-4 text-sm text-destructive">{error}</p>}
          {!repos && !error && (
            <p className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> Loading repositories…
            </p>
          )}
          {repos && shown.length === 0 && (
            <p className="p-4 text-sm text-muted-foreground">
              No repositories found. <Link className="text-primary underline" href="/setup/integrations">Install the GitHub App</Link> on an organization first.
            </p>
          )}
          {shown.map((r) => (
            <button
              key={r.id}
              type="button"
              role="option"
              aria-selected={picked?.id === r.id}
              onClick={() => {
                setPicked(r);
                setBranch(r.default_branch);
              }}
              className={cn('flex w-full items-center justify-between gap-2 border-b px-3 py-2 text-left text-sm last:border-0 hover:bg-muted', picked?.id === r.id && 'bg-accent text-accent-foreground')}
            >
              <span className="flex items-center gap-2 truncate">
                {r.full_name} {r.private && <Lock className="size-3 text-muted-foreground" aria-label="Private" />}
              </span>
              <span className="text-xs text-muted-foreground">{r.default_branch}</span>
            </button>
          ))}
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="scan-branch">Branch</Label>
          <Input id="scan-branch" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="default branch" disabled={!picked} />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            disabled={!picked || pending}
            onClick={async () => {
              const res = await run(() => startScan(picked!.id, branch.trim() || undefined));
              if (res) {
                toast.success('Scan queued', { action: { label: 'View scans', onClick: () => router.push('/scans') } });
                setOpen(false);
              }
            }}
          >
            {pending && <Loader2 className="animate-spin" />} Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
