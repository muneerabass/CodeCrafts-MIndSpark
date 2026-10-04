import Link from 'next/link';
import { ArrowRight, FileKey2, KeyRound, Lock, ShieldAlert, ShieldCheck, Users } from 'lucide-react';
import { api } from '@/lib/api';
import { PageHeader, PageIntro, StatTiles, type StatTile } from '@/components/page';
import { SourceIcon } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { ago } from '@/lib/format';

export const metadata = { title: 'Secrets' };

type VaultRow = { project_id: string; project: string; source: string; initialized: boolean; has_access: boolean; items: number; members: number; leaks: number; updated_at: string | null };

export default async function SecretsPage() {
  const { items } = await api<{ items: VaultRow[] }>('/vaults');
  const withVault = items.filter((v) => v.initialized);
  const tiles: StatTile[] = [
    { label: 'Projects with a vault', value: withVault.length, icon: FileKey2, tone: 'primary', href: '/secrets' },
    { label: 'Encrypted files', value: items.reduce((n, v) => n + v.items, 0), icon: Lock, tone: 'sky', href: '/secrets' },
    { label: 'Vaults you can open', value: items.filter((v) => v.has_access).length, icon: KeyRound, tone: 'amber', href: '/secrets' },
    { label: 'Leaked secrets to rotate', value: items.reduce((n, v) => n + v.leaks, 0), icon: ShieldAlert, tone: 'red', href: '/secrets' },
  ];
  return (
    <>
      <PageHeader crumbs={[{ label: 'Secrets' }]} info="End-to-end encrypted .env files, keys and certificates per project. Encrypted in your browser; depguard's servers can never read them." actions={null} />
      <PageIntro title="Secrets" description="Share each project's private files safely: end-to-end encrypted, approved per teammate, every read audited." />
      <StatTiles label="Secrets summary" tiles={tiles} />
      <div className="mx-auto w-full max-w-5xl space-y-3 p-4 md:p-6">
        <div className="flex flex-wrap items-center gap-3 rounded-xl border bg-gradient-to-r from-primary/10 to-transparent p-4 text-sm">
          <ShieldCheck className="size-5 text-primary" aria-hidden />
          <p className="min-w-0 flex-1">
            Developers and AI agents use them without a .env on disk: <code className="rounded bg-muted px-1">depguard secrets run -- npm start</code>
          </p>
        </div>
        {items.length === 0 ? (
          <p className="rounded-xl border bg-card p-8 text-center text-sm text-muted-foreground">No projects yet. Connect a repository first.</p>
        ) : (
          <ul className="divide-y rounded-xl border bg-card" aria-label="Project vaults">
            {items.map((v) => (
              <li key={v.project_id} className="flex flex-wrap items-center gap-3 p-4">
                <SourceIcon source={v.source} className="size-5" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{v.project}</p>
                  <p className="text-xs text-muted-foreground">
                    {v.initialized ? (
                      <>
                        {v.items} file{v.items === 1 ? '' : 's'} · <Users className="inline size-3" aria-hidden /> {v.members} with access{v.updated_at && ` · updated ${ago(v.updated_at)}`}
                        {!v.has_access && ' · you are not approved yet'}
                      </>
                    ) : (
                      'No vault yet'
                    )}
                  </p>
                  {v.leaks > 0 && (
                    <p className="mt-1 flex items-center gap-1 text-xs font-medium text-red-700 dark:text-red-300">
                      <ShieldAlert className="size-3.5" aria-hidden /> {v.leaks} stored secret{v.leaks === 1 ? ' was' : 's were'} found in a pull request: rotate {v.leaks === 1 ? 'it' : 'them'}
                    </p>
                  )}
                </div>
                <Button asChild size="sm" variant={v.initialized ? 'outline' : 'default'}>
                  <Link href={`/projects/${v.project_id}?tab=secrets`}>
                    {v.initialized ? 'Open vault' : 'Create vault'} <ArrowRight className="size-3.5" aria-hidden />
                  </Link>
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}
