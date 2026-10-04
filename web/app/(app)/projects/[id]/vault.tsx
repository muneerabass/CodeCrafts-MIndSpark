'use client';

import { useState } from 'react';
import Link from 'next/link';
import { toast } from 'sonner';
import { Download, Eye, EyeOff, FileKey2, KeyRound, Loader2, Lock, LockOpen, ShieldAlert, ShieldCheck, Trash2, UserCheck, UserMinus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { CopyButton } from '@/components/client';
import { ago } from '@/lib/format';
import { cn } from '@/lib/utils';
import * as vc from '@/lib/vault-crypto';
import { vaultDeleteItem, vaultGetItem, vaultGrant, vaultInit, vaultPutItem, vaultRemoveMember, vaultSetupMember, type ActionResult } from '@/lib/actions';
import type { VaultItemMeta, VaultMemberSelf, VaultState } from '@/lib/types';

const isEnvName = (n: string) => /(^|\/)\.env([.\w-]*)?$/.test(n) || n.endsWith('.env');

function Box({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn('rounded-xl border bg-card p-5', className)}>{children}</div>;
}

/** End-to-end encrypted project secrets: all crypto runs here, in the browser. */
export function VaultPanel({ projectId, initial, initialMe, userId, canEdit }: { projectId: string; initial: VaultState; initialMe: VaultMemberSelf | null; userId: string; canEdit: boolean }) {
  const [state, setState] = useState(initial);
  const [me, setMe] = useState(initialMe);
  const [priv, setPriv] = useState<CryptoKey | null>(null);
  const [vaultKey, setVaultKey] = useState<Uint8Array | null>(null);
  const [busy, setBusy] = useState('');
  const [pass, setPass] = useState('');
  const [pass2, setPass2] = useState('');
  const [view, setView] = useState<{ item: VaultItemMeta; text: string } | null>(null);
  const [reveal, setReveal] = useState<Record<string, boolean>>({});
  const [form, setForm] = useState({ name: '.env', text: '' });

  // Runs one step; failures become a toast. Returns the action's data.
  async function step<T>(label: string, fn: () => Promise<T | ActionResult<T>>): Promise<T | undefined> {
    setBusy(label);
    try {
      const r = await fn();
      if (r && typeof r === 'object' && 'ok' in r) {
        if (!r.ok) throw new Error(r.error);
        return r.data;
      }
      return r as T;
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy('');
    }
  }

  async function openKey(p: CryptoKey, s: VaultState) {
    if (!s.my_key) return setVaultKey(null);
    setVaultKey(await vc.unwrapKey(p, s.my_key, projectId, userId));
  }
  const apply = async (s: VaultState | undefined) => {
    if (!s) return;
    setState(s);
    if (priv) await openKey(priv, s);
  };

  const createPassphrase = () =>
    step('setup', async () => {
      if (pass.length < 12) throw new Error('Use at least 12 characters');
      if (pass !== pass2) throw new Error('The passphrases do not match');
      const m = await vc.newMember(pass);
      const r = await vaultSetupMember(m.publicKey, m.wrapped);
      if (!r.ok) throw new Error(r.error);
      setMe(r.data.member);
      setPriv(m.privateKey);
      setPass('');
      setPass2('');
      await openKey(m.privateKey, state);
      toast.success('Vault key created');
    });

  const unlock = () =>
    step('unlock', async () => {
      const p = await vc.unwrapPrivate(me!.wrapped_private, pass);
      setPriv(p);
      setPass('');
      await openKey(p, state);
    });

  const createVault = () =>
    step('init', async () => {
      const key = vc.newVaultKey();
      const s = await vaultInit(projectId, await vc.wrapKey(key, me!.public_key, projectId, userId));
      if (!s.ok) throw new Error(s.error);
      setState(s.data);
      setVaultKey(key);
      toast.success('Vault created');
    });

  const save = () =>
    step('save', async () => {
      const name = form.name.trim();
      if (!name || !form.text) throw new Error('Add a name and the file contents');
      const data = new TextEncoder().encode(form.text);
      if (data.length > 1_000_000) throw new Error('Files are limited to 1 MB');
      const kind = isEnvName(name) ? 'env' : 'file';
      const sealed = await vc.encryptItem(vaultKey!, data, projectId, name);
      const r = await vaultPutItem(projectId, { name, kind, ...sealed, size: data.length, key_version: state.key_version, fingerprints: kind === 'env' ? await vc.fingerprints(form.text) : [] });
      if (!r.ok) throw new Error(r.error);
      await apply(r.data);
      setForm({ name: '.env', text: '' });
      toast.success(`${name} saved, encrypted`);
    });

  const decrypt = async (item: VaultItemMeta) => {
    const r = await vaultGetItem(projectId, item.id);
    if (!r.ok) throw new Error(r.error);
    return vc.decryptItem(vaultKey!, r.data.iv, r.data.ciphertext, projectId, item.name);
  };
  const show = (item: VaultItemMeta) => step('view:' + item.id, async () => setView({ item, text: new TextDecoder().decode(await decrypt(item)) }));
  const download = (item: VaultItemMeta) =>
    step('dl:' + item.id, async () => {
      const url = URL.createObjectURL(new Blob([(await decrypt(item)) as BlobPart]));
      Object.assign(document.createElement('a'), { href: url, download: item.name.split('/').pop() }).click();
      URL.revokeObjectURL(url);
    });
  const remove = (item: VaultItemMeta) =>
    confirm(`Delete ${item.name} from the vault?`) &&
    step('del:' + item.id, async () => {
      const r = await vaultDeleteItem(projectId, item.id);
      if (!r.ok) throw new Error(r.error);
      await apply(r.data);
      if (view?.item.id === item.id) setView(null);
    });

  const approve = (userIdToAdd: string, publicKey: string) =>
    step('grant:' + userIdToAdd, async () => {
      const r = await vaultGrant(projectId, userIdToAdd, await vc.wrapKey(vaultKey!, publicKey, projectId, userIdToAdd), state.key_version);
      if (!r.ok) throw new Error(r.error);
      await apply(r.data);
      toast.success('Access granted');
    });

  // Removing a member rotates the key: new key, every item re-encrypted, re-wrapped for everyone who stays.
  const removeMember = (uid: string, email: string) =>
    confirm(`Remove ${email} from this vault? The vault key is rotated so old copies stop working.`) &&
    step('revoke:' + uid, async () => {
      const key = vc.newVaultKey();
      const items = [];
      for (const it of state.items) {
        const sealed = await vc.encryptItem(key, await decrypt(it), projectId, it.name);
        items.push({ id: it.id, ...sealed });
      }
      const grants = [];
      for (const m of state.members.filter((m) => m.has_access && m.user_id !== uid)) grants.push({ user_id: m.user_id, wrapped: await vc.wrapKey(key, m.public_key, projectId, m.user_id) });
      const r = await vaultRemoveMember(projectId, uid, { key_version: state.key_version + 1, grants, items });
      if (!r.ok) throw new Error(r.error);
      setState(r.data);
      setVaultKey(key);
      toast.success(`${email} removed; vault key rotated`);
    });

  const header = (
    <div className="flex flex-wrap items-start gap-3">
      <span className="flex size-10 items-center justify-center rounded-lg bg-primary/10 ring-1 ring-primary/25">
        <FileKey2 className="size-5 text-primary" aria-hidden />
      </span>
      <div className="min-w-0 flex-1">
        <h2 className="text-lg font-semibold">Project secrets</h2>
        <p className="text-sm text-muted-foreground">
          .env files, keys and certificates for {state.project}, end-to-end encrypted: they are encrypted in your browser and depguard&apos;s servers can never read them.
        </p>
      </div>
      {priv && (
        <Button variant="outline" size="sm" onClick={() => (setPriv(null), setVaultKey(null), setView(null))}>
          <Lock /> Lock
        </Button>
      )}
    </div>
  );

  if (!me)
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
        {header}
        <Box>
          <h3 className="font-medium">Create your vault passphrase</h3>
          <p className="mt-1 text-sm text-muted-foreground">It protects your personal vault key on every device. depguard cannot recover it; if you forget it, a teammate re-approves you.</p>
          <div className="mt-4 grid gap-3 sm:grid-cols-2">
            <div>
              <Label htmlFor="vp1">Passphrase (12+ characters)</Label>
              <Input id="vp1" type="password" autoComplete="new-password" className="mt-1.5" value={pass} onChange={(e) => setPass(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="vp2">Repeat it</Label>
              <Input id="vp2" type="password" autoComplete="new-password" className="mt-1.5" value={pass2} onChange={(e) => setPass2(e.target.value)} />
            </div>
          </div>
          <Button className="mt-4" disabled={!!busy} onClick={createPassphrase}>
            {busy === 'setup' ? <Loader2 className="animate-spin" /> : <KeyRound />} Create my vault key
          </Button>
        </Box>
      </div>
    );

  if (!priv)
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
        {header}
        <Box>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              unlock();
            }}
          >
            <div className="min-w-60 flex-1">
              <Label htmlFor="vpu">Vault passphrase</Label>
              <Input id="vpu" type="password" autoComplete="current-password" className="mt-1.5" value={pass} onChange={(e) => setPass(e.target.value)} />
            </div>
            <Button type="submit" disabled={!!busy || !pass}>
              {busy === 'unlock' ? <Loader2 className="animate-spin" /> : <LockOpen />} Unlock
            </Button>
          </form>
          <p className="mt-3 text-xs text-muted-foreground">
            {state.items.length} encrypted item{state.items.length === 1 ? '' : 's'} · {state.members.filter((m) => m.has_access).length} member(s) with access
          </p>
        </Box>
      </div>
    );

  if (!state.initialized)
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
        {header}
        <Box>
          {canEdit ? (
            <>
              <h3 className="font-medium">No vault for this project yet</h3>
              <p className="mt-1 text-sm text-muted-foreground">Creating it generates a project key in your browser. You can then add files and approve teammates.</p>
              <Button className="mt-4" disabled={!!busy} onClick={createVault}>
                {busy === 'init' ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Create vault
              </Button>
            </>
          ) : (
            <p className="text-sm text-muted-foreground">No vault for this project yet. An admin can create it here.</p>
          )}
        </Box>
      </div>
    );

  if (!vaultKey)
    return (
      <div className="mx-auto max-w-3xl space-y-4 p-4 md:p-6">
        {header}
        <Box>
          <h3 className="font-medium">Waiting for access</h3>
          <p className="mt-1 text-sm text-muted-foreground">
            Ask someone with access to open this tab and click <b>Approve</b> next to your name:{' '}
            {state.members.filter((m) => m.has_access).map((m) => m.email).join(', ') || 'nobody has access yet'}.
          </p>
        </Box>
      </div>
    );

  const vars = view && view.item.kind === 'env' ? vc.parseEnv(view.text) : [];
  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4 md:p-6">
      {header}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="text-base">Files</CardTitle>
          <CardDescription>
            In a terminal or for AI agents: <code className="rounded bg-muted px-1">depguard secrets run -- npm start</code> injects them without writing a .env.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {state.items.length === 0 ? (
            <p className="text-sm text-muted-foreground">No files yet.</p>
          ) : (
            <ul className="divide-y" aria-label="Vault items">
              {state.items.map((it) => (
                <li key={it.id} className="flex flex-wrap items-center gap-3 py-3">
                  <FileKey2 className="size-4 text-muted-foreground" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-sm font-medium">{it.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {it.kind === 'env' ? `${it.keys.length} key${it.keys.length === 1 ? '' : 's'}: ${it.keys.slice(0, 6).join(', ')}${it.keys.length > 6 ? '…' : ''}` : `${it.size.toLocaleString('en-GB')} bytes`} · v{it.version} · {it.updated_by} · {ago(it.updated_at)}
                    </p>
                    {it.leaks.map((l, i) => (
                      <p key={i} className="mt-1 flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-300">
                        <ShieldAlert className="size-3.5" aria-hidden /> {l.key} leaked in{' '}
                        {l.project_id ? (
                          <Link className="underline" href={`/pull-requests/${l.project_id}/${l.pr}`}>
                            {l.repo} #{l.pr}
                          </Link>
                        ) : (
                          `${l.repo} #${l.pr}`
                        )}{' '}
                        ({l.file}:{l.line}): rotate it at the provider, then update this file.
                      </p>
                    ))}
                  </div>
                  <Button variant="outline" size="sm" disabled={!!busy} onClick={() => show(it)}>
                    {busy === 'view:' + it.id ? <Loader2 className="animate-spin" /> : <Eye />} View
                  </Button>
                  <Button variant="outline" size="sm" disabled={!!busy} onClick={() => download(it)} aria-label={`Download ${it.name}`}>
                    <Download />
                  </Button>
                  {canEdit && (
                    <Button variant="ghost" size="sm" disabled={!!busy} onClick={() => remove(it)} aria-label={`Delete ${it.name}`}>
                      <Trash2 />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}

          {view && (
            <div className="mt-4 rounded-lg border bg-muted/30 p-3" aria-label={`Contents of ${view.item.name}`}>
              <div className="mb-2 flex items-center justify-between">
                <span className="font-mono text-sm font-medium">{view.item.name}</span>
                <Button variant="ghost" size="sm" onClick={() => setView(null)}>
                  Close
                </Button>
              </div>
              {view.item.kind === 'env' ? (
                <table className="w-full table-fixed text-sm">
                  <tbody>
                    {vars.map((v) => (
                      <tr key={v.key} className="border-t first:border-0">
                        <td className="w-1/3 py-1.5 pr-3 font-mono text-xs font-medium break-all">{v.key}</td>
                        <td className="py-1.5 font-mono text-xs break-all">{reveal[v.key] ? v.value : '•'.repeat(Math.min(24, Math.max(8, v.value.length)))}</td>
                        <td className="w-20 py-1.5 text-right whitespace-nowrap">
                          <Button variant="ghost" size="icon" className="size-7" aria-label={`${reveal[v.key] ? 'Hide' : 'Show'} ${v.key}`} onClick={() => setReveal({ ...reveal, [v.key]: !reveal[v.key] })}>
                            {reveal[v.key] ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                          </Button>
                          <CopyButton value={v.value} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <pre className="max-h-64 overflow-auto font-mono text-xs whitespace-pre-wrap">{view.text}</pre>
              )}
            </div>
          )}

          {canEdit && (
            <div className="mt-5 space-y-2 border-t pt-4">
              <h3 className="text-sm font-medium">Add or replace a file</h3>
              <div className="flex flex-wrap items-center gap-2">
                <Input aria-label="File name" className="w-56 font-mono" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                <Input
                  aria-label="Choose a file"
                  type="file"
                  className="w-64"
                  onChange={async (e) => {
                    const f = e.target.files?.[0];
                    if (f) setForm({ name: f.name, text: await f.text() });
                  }}
                />
              </div>
              <Textarea aria-label="File contents" rows={6} className="font-mono text-xs" placeholder={'STRIPE_SECRET_KEY=sk_live_…\nDATABASE_URL=postgres://…'} value={form.text} onChange={(e) => setForm({ ...form, text: e.target.value })} />
              <Button disabled={!!busy} onClick={save}>
                {busy === 'save' ? <Loader2 className="animate-spin" /> : <Lock />} Encrypt and save
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="text-base">Who can decrypt</CardTitle>
          <CardDescription>Teammates appear here after they create their vault passphrase on this tab. Removing someone rotates the vault key.</CardDescription>
        </CardHeader>
        <CardContent>
          <ul className="divide-y" aria-label="Vault members">
            {state.members.map((m) => (
              <li key={m.user_id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                <span className="min-w-0 flex-1">
                  {m.email || m.user_id} {m.user_id === userId && <span className="text-xs text-muted-foreground">(you)</span>}
                  <span className="block text-xs text-muted-foreground">{m.has_access ? `Access · approved by ${m.granted_by}` : 'Waiting for approval'}</span>
                </span>
                {canEdit && !m.has_access && (
                  <Button size="sm" disabled={!!busy} onClick={() => approve(m.user_id, m.public_key)}>
                    {busy === 'grant:' + m.user_id ? <Loader2 className="animate-spin" /> : <UserCheck />} Approve
                  </Button>
                )}
                {canEdit && m.has_access && m.user_id !== userId && (
                  <Button size="sm" variant="outline" disabled={!!busy} onClick={() => removeMember(m.user_id, m.email)}>
                    {busy === 'revoke:' + m.user_id ? <Loader2 className="animate-spin" /> : <UserMinus />} Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
