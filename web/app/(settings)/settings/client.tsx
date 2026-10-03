'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { KeyRound, Loader2, LogOut, MoreHorizontal, Pencil, Plus, Trash2, TriangleAlert, UserPlus } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { ActionButton, CopyButton, useAction } from '@/components/client';
import { EmptyState } from '@/components/page';
import { Ecosystem } from '@/components/icons';
import { authClient } from '@/lib/auth-client';
import {
  cancelInvitation,
  createApiKey,
  deleteExclusion,
  inviteMember,
  removeMember,
  resendInvitation,
  revokeApiKey,
  revokeOtherSessions,
  saveExclusion,
  saveSettings,
  updateMemberRole,
  updateOrgName,
  updateProfile,
} from '@/lib/actions';
import { fmtDate, titleCase } from '@/lib/format';
import type { ApiKey, Exclusion, Settings } from '@/lib/types';
import type { InvitationRow, MemberRow } from '@/lib/org-data';

const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'Packagist', 'NuGet', 'GitHubActions'];
const ROLES = ['member', 'admin', 'owner'] as const;

// ---------------- General ----------------
export function TenantNameForm({ name, canEdit }: { name: string; canEdit: boolean }) {
  const [value, setValue] = useState(name);
  const { pending, run } = useAction();
  return (
    <form
      className="grid gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => updateOrgName(value), 'Tenant name updated');
      }}
    >
      <Label htmlFor="tenant-name">Tenant Name</Label>
      <div className="flex gap-2">
        <Input id="tenant-name" value={value} onChange={(e) => setValue(e.target.value)} readOnly={!canEdit} aria-readonly={!canEdit} />
        {canEdit && (
          <Button type="submit" disabled={pending || value.trim() === name}>
            {pending && <Loader2 className="animate-spin" />} Save
          </Button>
        )}
      </div>
    </form>
  );
}

// ---------------- API keys ----------------
export function CreateApiKeyButton({ disabled, variant = 'default' }: { disabled?: boolean; variant?: 'default' | 'outline' }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [expires, setExpires] = useState('');
  const [key, setKey] = useState<string | null>(null);
  const { pending, run } = useAction();

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) {
          setKey(null);
          setName('');
          setExpires('');
        }
      }}
    >
      <DialogTrigger asChild>
        <Button variant={variant} disabled={disabled} title={disabled ? 'Only owners and admins can create API keys' : undefined}>
          Create API Key <Plus />
        </Button>
      </DialogTrigger>
      <DialogContent>
        {key ? (
          <>
            <DialogHeader>
              <DialogTitle>Your new API key</DialogTitle>
              <DialogDescription>Store it in your secret manager now. For security, depguard keeps only a hash and cannot show it again.</DialogDescription>
            </DialogHeader>
            <div className="flex items-center gap-2 rounded-md border bg-muted p-2">
              <code className="min-w-0 flex-1 break-all font-mono text-sm">{key}</code>
              <CopyButton value={key} />
            </div>
            <p className="flex items-center gap-2 text-sm text-amber-700">
              <TriangleAlert className="size-4" /> This is the only time the full key is displayed.
            </p>
            <DialogFooter>
              <Button onClick={() => setOpen(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form
            className="grid gap-4"
            onSubmit={async (e) => {
              e.preventDefault();
              const k = await run(() => createApiKey(name, expires || undefined));
              if (k?.key) setKey(k.key);
            }}
          >
            <DialogHeader>
              <DialogTitle>Create API key</DialogTitle>
              <DialogDescription>Keys authenticate the depguard CLI, CI integrations, endpoint agents and the MCP server for this tenant.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-1.5">
              <Label htmlFor="key-name">Name</Label>
              <Input id="key-name" required placeholder="e.g. GitHub Actions" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="key-expires">Expires on (optional)</Label>
              <Input id="key-expires" type="date" value={expires} min={new Date().toISOString().slice(0, 10)} onChange={(e) => setExpires(e.target.value)} />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending && <Loader2 className="animate-spin" />} Create key
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function ApiKeysTable({ keys, canEdit }: { keys: ApiKey[]; canEdit: boolean }) {
  const cols: ColumnDef<ApiKey, unknown>[] = [
    { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { header: 'Key', cell: ({ row }) => <code className="font-mono text-xs">{row.original.prefix}…</code> },
    { header: 'Created', cell: ({ row }) => fmtDate(row.original.created_at) },
    { header: 'Last used', cell: ({ row }) => (row.original.last_used_at ? fmtDate(row.original.last_used_at) : 'Never') },
    { header: 'Expires', cell: ({ row }) => (row.original.expires_at ? fmtDate(row.original.expires_at) : 'Never') },
    {
      id: 'actions',
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) =>
        canEdit && (
          <ActionButton
            variant="ghost"
            size="sm"
            className="text-destructive"
            confirm={`Revoke "${row.original.name}"? Anything using this key will stop working immediately.`}
            action={() => revokeApiKey(row.original.id)}
            ok="API key revoked"
          >
            <Trash2 /> Revoke
          </ActionButton>
        ),
    },
  ];
  return (
    <DataTable
      columns={cols}
      data={keys}
      empty={
        <EmptyState icon={KeyRound} title="No API keys found">
          <p>Create an API key to start using the depguard API.</p>
          <div className="mt-4">
            <CreateApiKeyButton disabled={!canEdit} />
          </div>
        </EmptyState>
      }
    />
  );
}

// ---------------- Exclusions ----------------
type ExForm = { ecosystem: string; name: string; version: string; reason: string; expires_at: string };

export function ExclusionDialog({ exclusion, trigger }: { exclusion?: Exclusion; trigger: React.ReactNode }) {
  const init = (): ExForm => ({
    ecosystem: exclusion?.ecosystem ?? 'npm',
    name: exclusion?.name ?? '',
    version: exclusion?.version ?? '',
    reason: exclusion?.reason ?? '',
    expires_at: exclusion?.expires_at?.slice(0, 10) ?? '',
  });
  const [open, setOpen] = useState(false);
  const [f, setF] = useState<ExForm>(init);
  const { pending, run } = useAction();
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setF(init());
      }}
    >
      <DialogTrigger asChild>{trigger}</DialogTrigger>
      <DialogContent>
        <form
          className="grid gap-4"
          onSubmit={async (e) => {
            e.preventDefault();
            const r = await run(() => saveExclusion(exclusion?.id ?? null, { ...f, expires_at: f.expires_at || null }), exclusion ? 'Exclusion updated' : 'Exclusion created');
            if (r) setOpen(false);
          }}
        >
          <DialogHeader>
            <DialogTitle>{exclusion ? 'Edit exclusion' : 'Create exclusion'}</DialogTitle>
            <DialogDescription>Excluded packages are skipped by Package Analysis. An exclusion never overrides a package verified as malicious.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="ex-eco">Ecosystem</Label>
            <Select value={f.ecosystem} onValueChange={(v) => setF({ ...f, ecosystem: v })}>
              <SelectTrigger id="ex-eco" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ECOSYSTEMS.map((e) => (
                  <SelectItem key={e} value={e}>
                    {e}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="ex-name">Package name</Label>
              <Input id="ex-name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ex-version">Version</Label>
              <Input id="ex-version" placeholder="All versions" value={f.version} onChange={(e) => setF({ ...f, version: e.target.value })} />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ex-reason">Reason</Label>
            <Textarea id="ex-reason" required value={f.reason} onChange={(e) => setF({ ...f, reason: e.target.value })} placeholder="Why is this package safe to skip?" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="ex-expires">Expires on (optional)</Label>
            <Input id="ex-expires" type="date" value={f.expires_at} onChange={(e) => setF({ ...f, expires_at: e.target.value })} />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />} {exclusion ? 'Save changes' : 'Create exclusion'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteExclusion({ ex }: { ex: Exclusion }) {
  const { pending, run } = useAction();
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={`Delete exclusion for ${ex.name}`} className="text-destructive">
          <Trash2 />
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this exclusion?</AlertDialogTitle>
          <AlertDialogDescription>
            {ex.ecosystem}/{ex.name}
            {ex.version && `@${ex.version}`} will be analysed again on the next scan.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction disabled={pending} onClick={() => run(() => deleteExclusion(ex.id), 'Exclusion deleted')}>
            Delete
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export function ExclusionsTable({ data, total, canEdit }: { data: Exclusion[]; total: number; canEdit: boolean }) {
  const cols: ColumnDef<Exclusion, unknown>[] = [
    { header: 'Ecosystem', cell: ({ row }) => <Ecosystem name={row.original.ecosystem} /> },
    { header: 'Package Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { header: 'Version', cell: ({ row }) => row.original.version || 'All' },
    { header: 'Reason', cell: ({ row }) => <span className="line-clamp-1 max-w-xs">{row.original.reason}</span> },
    {
      header: 'Status',
      cell: ({ row }) => (
        <span className={row.original.status === 'active' ? 'text-emerald-600' : 'text-muted-foreground'}>{titleCase(row.original.status)}</span>
      ),
    },
    { header: 'Expires At', cell: ({ row }) => (row.original.expires_at ? fmtDate(row.original.expires_at) : 'Never') },
    {
      header: 'Actions',
      cell: ({ row }) =>
        canEdit ? (
          <div className="flex gap-1">
            <ExclusionDialog
              exclusion={row.original}
              trigger={
                <Button variant="ghost" size="icon" aria-label={`Edit exclusion for ${row.original.name}`}>
                  <Pencil />
                </Button>
              }
            />
            <DeleteExclusion ex={row.original} />
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Read-only</span>
        ),
    },
  ];
  return <DataTable columns={cols} data={data} total={total} defaultPageSize={10} />;
}

// ---------------- Team ----------------
export function InviteDialog() {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<string>('member');
  const { pending, run } = useAction();
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) {
          setEmail('');
          setRole('member');
        }
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <UserPlus /> Invite Team
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form
          className="grid gap-4"
          onSubmit={async (e) => {
            e.preventDefault();
            const sent = await run(async () => {
              const r = await inviteMember(email, role);
              return r.ok ? { ok: true as const, data: true } : r;
            }, `Invitation sent to ${email}`);
            if (sent) setOpen(false);
          }}
        >
          <DialogHeader>
            <DialogTitle>Invite a teammate</DialogTitle>
            <DialogDescription>They will get an email with a link to join this tenant. Invitations expire after 7 days.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="inv-email">Email</Label>
            <Input id="inv-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.com" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="inv-role">Role</Label>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger id="inv-role" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="member">Member — read-only access</SelectItem>
                <SelectItem value="admin">Admin — manage keys, policy and scans</SelectItem>
                <SelectItem value="owner">Owner — full control, including members</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />} Send invitation
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function MemberMenu({ m }: { m: MemberRow }) {
  const { pending, run } = useAction();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" disabled={pending} aria-label={`Actions for ${m.name}`}>
          {pending ? <Loader2 className="animate-spin" /> : <MoreHorizontal />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="text-xs text-muted-foreground">Change role</DropdownMenuLabel>
        {ROLES.filter((r) => r !== m.role).map((r) => (
          <DropdownMenuItem key={r} onSelect={() => run(() => updateMemberRole(m.id, r), `${m.name} is now ${titleCase(r)}`)}>
            Make {titleCase(r)}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          onSelect={() => {
            if (window.confirm(`Remove ${m.name} from this tenant?`)) run(() => removeMember(m.id), `${m.name} removed`);
          }}
        >
          <Trash2 /> Remove member
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function InvitationActions({ inv }: { inv: InvitationRow }) {
  return (
    <div className="flex gap-1">
      <ActionButton variant="ghost" size="sm" action={() => resendInvitation(inv.email, inv.role)} ok={`Invitation re-sent to ${inv.email}`}>
        Resend
      </ActionButton>
      <ActionButton variant="ghost" size="sm" className="text-destructive" confirm={`Cancel the invitation for ${inv.email}?`} action={() => cancelInvitation(inv.id)} ok="Invitation cancelled">
        Cancel
      </ActionButton>
    </div>
  );
}

// ---------------- Preferences ----------------
type Pref = 'scan_draft_prs' | 'suppress_clean_comments' | 'block_mode';
const PREFS: { key: Pref; title: string; body: string }[] = [
  { key: 'scan_draft_prs', title: 'Scan Draft Pull Requests', body: 'Also scan pull requests that are still marked as draft. Useful when your team stacks PRs or opens drafts early for review.' },
  { key: 'suppress_clean_comments', title: 'Suppress Comments on Clean Scans', body: 'Skip the pull request comment when a scan finds nothing to report. The check run is still posted.' },
  {
    key: 'block_mode',
    title: 'Block merges on violations',
    body: 'When on, a policy violation marks the check run as failed so branch protection can block the merge. When off (warn mode), the check is reported as neutral.',
  },
];

export function PreferencesForm({ settings, canEdit }: { settings: Settings; canEdit: boolean }) {
  const [s, setS] = useState(settings);
  const { run } = useAction();
  return (
    <div className="divide-y">
      {PREFS.map((p) => (
        <div key={p.key} className="flex items-start justify-between gap-6 py-4 first:pt-0 last:pb-0">
          <div>
            <Label htmlFor={`pref-${p.key}`} className="font-medium">
              {p.title}
            </Label>
            <p id={`pref-${p.key}-desc`} className="mt-1 text-sm text-muted-foreground">
              {p.body}
            </p>
          </div>
          <Switch
            id={`pref-${p.key}`}
            aria-describedby={`pref-${p.key}-desc`}
            checked={s[p.key]}
            disabled={!canEdit}
            onCheckedChange={async (v) => {
              const prev = s;
              setS({ ...s, [p.key]: v });
              const r = await run(() => saveSettings({ [p.key]: v }), 'Preference saved');
              if (!r) setS(prev);
            }}
          />
        </div>
      ))}
    </div>
  );
}

// ---------------- Profile ----------------
export function ProfileForm({ name }: { name: string }) {
  const [value, setValue] = useState(name);
  const { pending, run } = useAction();
  return (
    <form
      className="grid gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => updateProfile(value), 'Profile updated');
      }}
    >
      <Label htmlFor="profile-name">Name</Label>
      <div className="flex gap-2">
        <Input id="profile-name" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="name" />
        <Button type="submit" disabled={pending || value.trim() === name}>
          {pending && <Loader2 className="animate-spin" />} Save
        </Button>
      </div>
    </form>
  );
}

export function SessionButtons() {
  const router = useRouter();
  return (
    <div className="flex flex-wrap gap-2">
      <ActionButton variant="outline" action={revokeOtherSessions} ok="Signed out of all other sessions">
        Sign out of other sessions
      </ActionButton>
      <Button
        variant="destructive"
        onClick={async () => {
          const r = await authClient.signOut();
          if (r.error) toast.error(r.error.message ?? 'Sign out failed');
          else router.push('/sign-in');
        }}
      >
        <LogOut /> Sign out
      </Button>
    </div>
  );
}
