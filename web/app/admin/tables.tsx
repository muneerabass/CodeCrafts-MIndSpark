'use client';

import { useState } from 'react';
import { Link2, Loader2, Plus, RotateCw, Unlink } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { ActionButton, useAction } from '@/components/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { createTenant, linkInstallation, redeliverWebhook, setTenantDisabled, unlinkInstallation } from '@/lib/admin-actions';
import { fmtDate, fmtDateTime, titleCase } from '@/lib/format';
import type { AdminInstallation, AdminTenant, FailedJob, FeedStatus, WebhookDelivery } from '@/lib/types';
import { cn } from '@/lib/utils';

const pill = 'inline-flex rounded-md px-1.5 py-0.5 text-xs font-medium';
function StatusPill({ status }: { status: string }) {
  const good = ['active', 'processed', 'ok', 'success'].includes(status);
  const bad = ['disabled', 'failed', 'discarded', 'error'].includes(status);
  return <span className={cn(pill, good ? 'bg-emerald-50 text-emerald-700' : bad ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-700')}>{titleCase(status)}</span>;
}

// ---------- tenants ----------
export type TenantRow = AdminTenant & { name: string; created_at: string | null; owner_invite: string | null };

const tenantCols: ColumnDef<TenantRow, unknown>[] = [
  { header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
  { header: 'Domain', cell: ({ row }) => <span className="font-mono text-xs">{row.original.domain}</span> },
  { header: 'Owner invite', cell: ({ row }) => (row.original.owner_invite ? <span className="text-sm">{row.original.owner_invite} <span className="text-muted-foreground">(pending)</span></span> : <span className="text-muted-foreground">—</span>) },
  { header: 'Projects', cell: ({ row }) => row.original.projects },
  { header: 'Installations', cell: ({ row }) => row.original.installations },
  { header: 'Status', cell: ({ row }) => <StatusPill status={row.original.disabled_at ? 'disabled' : 'active'} /> },
  { header: 'Created', cell: ({ row }) => fmtDate(row.original.created_at) },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => {
      const t = row.original;
      const disabled = !!t.disabled_at;
      return (
        <ActionButton
          variant="ghost"
          size="sm"
          className={disabled ? undefined : 'text-destructive hover:text-destructive'}
          action={() => setTenantDisabled(t.tenant_id, !disabled)}
          confirm={disabled ? undefined : `Disable ${t.name}? Its members lose access and scans stop.`}
          ok={disabled ? 'Tenant enabled' : 'Tenant disabled'}
        >
          {disabled ? 'Enable' : 'Disable'}
        </ActionButton>
      );
    },
  },
];

export function TenantsTable({ data, empty }: { data: TenantRow[]; empty?: React.ReactNode }) {
  return <DataTable columns={tenantCols} data={data} empty={empty} />;
}

const slugify = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40);

export function CreateTenantDialog({ suffix }: { suffix: string }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [slugTouched, setSlugTouched] = useState(false);
  const [email, setEmail] = useState('');
  const { pending, run } = useAction();
  const effSlug = slugTouched ? slug : slugify(name);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus /> Create tenant
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form
          className="flex flex-col gap-4"
          onSubmit={async (e) => {
            e.preventDefault();
            const r = await run(() => createTenant({ name, slug: effSlug, ownerEmail: email.trim() }), 'Tenant created and owner invited'); // returns { id } on success
            if (r) {
              setOpen(false);
              setName('');
              setSlug('');
              setSlugTouched(false);
              setEmail('');
            }
          }}
        >
          <DialogHeader>
            <DialogTitle>Create tenant</DialogTitle>
            <DialogDescription>Creates the organization, provisions it in the API and emails an owner invitation.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="t-name">Name</Label>
            <Input id="t-name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="t-slug">Slug</Label>
            <Input
              id="t-slug"
              required
              value={effSlug}
              onChange={(e) => {
                setSlugTouched(true);
                setSlug(e.target.value);
              }}
              aria-describedby="t-domain"
            />
            <p id="t-domain" className="text-xs text-muted-foreground">
              Tenant domain: <span className="font-mono">{effSlug || 'slug'}.{suffix}</span>
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="t-email">Owner email</Label>
            <Input id="t-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="owner@acme.com" />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />} Create &amp; invite
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

// ---------- installations ----------
type InstallRow = AdminInstallation & { tenant_domain: string | null };

function LinkDialog({ inst, tenants }: { inst: InstallRow; tenants: { id: string; domain: string }[] }) {
  const [open, setOpen] = useState(false);
  const [tenant, setTenant] = useState('');
  const { pending, run } = useAction();
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <Link2 /> Link to tenant
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Link {inst.account_login}</DialogTitle>
          <DialogDescription>Once linked, pull requests and pushes from this installation are scanned for the chosen tenant.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="link-tenant">Tenant</Label>
          <Select value={tenant} onValueChange={setTenant}>
            <SelectTrigger id="link-tenant" className="w-full">
              <SelectValue placeholder="Choose a tenant" />
            </SelectTrigger>
            <SelectContent>
              {tenants.map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.domain}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button
            disabled={!tenant || pending}
            onClick={async () => {
              const done = await run(async () => {
                const r = await linkInstallation(inst.id, tenant);
                return r.ok ? { ok: true as const, data: true } : r;
              }, 'Installation linked');
              if (done) setOpen(false);
            }}
          >
            {pending && <Loader2 className="animate-spin" />} Link
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function InstallationsTable({ data, tenants }: { data: InstallRow[]; tenants: { id: string; domain: string }[] }) {
  const cols: ColumnDef<InstallRow, unknown>[] = [
    { header: 'Account', cell: ({ row }) => <span className="font-medium">{row.original.account_login}</span> },
    { header: 'Type', cell: ({ row }) => row.original.account_type },
    { header: 'Repos', cell: ({ row }) => row.original.repos },
    { header: 'Status', cell: ({ row }) => <StatusPill status={row.original.status} /> },
    { header: 'Linked tenant', cell: ({ row }) => (row.original.tenant_domain ?? row.original.tenant_id ?? <span className="text-muted-foreground">—</span>) },
    { header: 'Installed', cell: ({ row }) => fmtDate(row.original.created_at) },
    {
      id: 'actions',
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) =>
        row.original.tenant_id ? (
          <ActionButton variant="ghost" size="sm" action={() => unlinkInstallation(row.original.id)} confirm={`Unlink ${row.original.account_login}? Scanning stops until it is linked again.`} ok="Installation unlinked">
            <Unlink /> Unlink
          </ActionButton>
        ) : (
          <LinkDialog inst={row.original} tenants={tenants} />
        ),
    },
  ];
  return <DataTable columns={cols} data={data} empty="No installations." />;
}

// ---------- ops health ----------
const feedCols: ColumnDef<FeedStatus & { stale: boolean }, unknown>[] = [
  { header: 'Source', cell: ({ row }) => <span className="font-medium uppercase">{row.original.source}</span> },
  {
    header: 'Last OK',
    cell: ({ row }) => (
      <span className={cn(row.original.stale && 'font-medium text-red-600')}>
        {fmtDateTime(row.original.last_ok)}
        {row.original.stale && ' (stale)'}
      </span>
    ),
  },
  { header: 'Last error', cell: ({ row }) => (row.original.last_error ? <span className="line-clamp-2 max-w-md text-sm text-red-600">{row.original.last_error}</span> : <span className="text-muted-foreground">—</span>) },
  { header: 'Cursor', cell: ({ row }) => <span className="font-mono text-xs">{row.original.cursor ?? '—'}</span> },
  { header: 'Updated', cell: ({ row }) => fmtDateTime(row.original.updated_at) },
];
export function FeedsTable({ data }: { data: (FeedStatus & { stale: boolean })[] }) {
  return <DataTable columns={feedCols} data={data} empty="No feed status reported." />;
}

const jobCols: ColumnDef<FailedJob, unknown>[] = [
  { header: 'ID', cell: ({ row }) => <span className="font-mono text-xs">{row.original.id}</span> },
  { header: 'Kind', cell: ({ row }) => row.original.kind },
  { header: 'State', cell: ({ row }) => <StatusPill status={row.original.state} /> },
  { header: 'Attempts', cell: ({ row }) => row.original.attempt },
  { header: 'Last error', cell: ({ row }) => <span className="line-clamp-2 max-w-md text-sm">{row.original.errors?.at(-1) ?? '—'}</span> },
  { header: 'Finalized', cell: ({ row }) => fmtDateTime(row.original.finalized_at) },
];
export function JobsTable({ data }: { data: FailedJob[] }) {
  return <DataTable columns={jobCols} data={data} empty="No failed jobs. 🎉" />;
}

const hookCols: ColumnDef<WebhookDelivery, unknown>[] = [
  { header: 'Delivery', cell: ({ row }) => <span className="font-mono text-xs">{row.original.delivery_id}</span> },
  { header: 'Event', cell: ({ row }) => row.original.event },
  { header: 'Status', cell: ({ row }) => <StatusPill status={row.original.status} /> },
  { header: 'Error', cell: ({ row }) => <span className="line-clamp-2 max-w-sm text-sm text-muted-foreground">{row.original.error ?? '—'}</span> },
  { header: 'Received', cell: ({ row }) => fmtDateTime(row.original.received_at) },
  {
    id: 'actions',
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => (
      <ActionButton variant="ghost" size="sm" action={() => redeliverWebhook(row.original.delivery_id)} ok="Redelivery requested">
        <RotateCw /> Redeliver
      </ActionButton>
    ),
  },
];
export function WebhooksTable({ data }: { data: WebhookDelivery[] }) {
  return <DataTable columns={hookCols} data={data} empty="No webhook deliveries yet." />;
}
