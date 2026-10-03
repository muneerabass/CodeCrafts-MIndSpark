import Link from 'next/link';
import { ArrowRight, Check, ExternalLink } from 'lucide-react';
import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { Integrations } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { Button } from '@/components/ui/button';
import { ScanRepoDialog } from '@/components/scan-repo-dialog';
import { titleCase } from '@/lib/format';
import { guides, IconTile } from '../catalog';

export const metadata = { title: 'Integrations' };

function GuideLink({ slug, className }: { slug: string; className?: string }) {
  return (
    <Link href={`/setup/guides/${slug}`} className={className ?? 'inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline'}>
      View setup guide <ArrowRight className="size-4" aria-hidden />
    </Link>
  );
}

function Section({ title, count, children }: { title: string; count?: number; children: React.ReactNode }) {
  return (
    <section className="mt-8" aria-label={title}>
      <h2 className="mb-3 flex items-center gap-2 font-medium">
        {title} {count !== undefined && <span className="rounded-md border px-1.5 text-xs text-muted-foreground">{count}</span>}
      </h2>
      {children}
    </section>
  );
}

function GridCards({ slugs }: { slugs: string[] }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {slugs.map((s) => {
        const g = guides[s];
        return (
          <div key={s} className="flex flex-col rounded-xl border bg-card p-5">
            <IconTile Icon={g.Icon} />
            <h3 className="mt-4 font-medium">{g.title}</h3>
            <p className="mt-1 flex-1 text-sm text-muted-foreground">{g.desc}</p>
            <GuideLink slug={s} className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline" />
          </div>
        );
      })}
    </div>
  );
}

export default async function IntegrationsPage() {
  const { role } = await requireOrg();
  const { github } = await api<Integrations>('/integrations');
  const connected = github.installations.length > 0;
  const gh = guides['github-app'];

  return (
    <>
      <PageHeader crumbs={[{ label: 'Setup', href: '/setup' }, { label: 'Integrations' }]} actions={null} />
      <div className="mx-auto w-full max-w-5xl px-4 py-8">
        <h1 className="text-2xl font-semibold">Integrations</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          Hook depguard into your code hosts, CI pipelines and developer machines. Every integration comes with a step-by-step guide, so you can
          be scanning in a few minutes.
        </p>

        <Section title="Source Control">
          <div className="flex flex-col gap-4">
            <div className="rounded-xl border bg-card p-5">
              <div className="flex flex-wrap items-start gap-4">
                <IconTile Icon={gh.Icon} />
                <div className="min-w-0 flex-1">
                  <h3 className="font-medium">{gh.title}</h3>
                  <p className="mt-1 text-sm text-muted-foreground">{gh.desc}</p>
                </div>
                {connected && (
                  <span className="inline-flex items-center gap-1 rounded-md bg-emerald-50 px-2 py-1 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
                    <Check className="size-3.5" aria-hidden /> Connected
                  </span>
                )}
              </div>
              {connected && (
                <ul className="mt-4 divide-y rounded-lg border text-sm" aria-label="GitHub installations">
                  {github.installations.map((i) => (
                    <li key={i.id} className="flex items-center justify-between gap-2 px-3 py-2">
                      <span className="font-medium">{i.account_login}</span>
                      <span className="text-muted-foreground">
                        {i.repos} {i.repos === 1 ? 'repository' : 'repositories'} · {titleCase(i.status)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              <div className="mt-4 flex flex-wrap items-center gap-3 border-t pt-4">
                {connected && <ScanRepoDialog label="Scan repositories" disabled={!canWrite(role)} />}
                <Button asChild variant={connected ? 'ghost' : 'default'} size="sm">
                  <a href={github.install_url} target="_blank" rel="noreferrer">
                    {connected ? 'Add another organization' : 'Install GitHub App'} <ExternalLink aria-hidden />
                  </a>
                </Button>
                <GuideLink slug="github-app" className="ml-auto inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline" />
              </div>
            </div>

            <div className="rounded-xl border bg-card p-5 opacity-80">
              <div className="flex flex-wrap items-start gap-4">
                <IconTile Icon={guides['bitbucket-pipes'].Icon} />
                <div className="min-w-0 flex-1">
                  <h3 className="font-medium">Bitbucket App</h3>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Pull-request scanning for Bitbucket Cloud workspaces, with results synced to Projects. Until it ships, use Bitbucket Pipes.
                  </p>
                </div>
                <span className="rounded-md bg-muted px-2 py-1 text-xs font-medium text-muted-foreground">Coming soon</span>
              </div>
              <div className="mt-4 flex border-t pt-4">
                <Button size="sm" disabled>
                  Install Bitbucket App
                </Button>
                <GuideLink slug="bitbucket-pipes" className="ml-auto inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline" />
              </div>
            </div>
          </div>
        </Section>

        <Section title="CI/CD Pipelines" count={3}>
          <GridCards slugs={['github-actions', 'gitlab-ci', 'bitbucket-pipes']} />
        </Section>

        <Section title="Developer Tools" count={3}>
          <GridCards slugs={['cli', 'pmg', 'mcp']} />
        </Section>

        <Section title="AI Governance & Endpoints">
          <div className="flex flex-wrap items-center gap-4 rounded-xl border bg-card p-5">
            <IconTile Icon={guides['ai-tools'].Icon} />
            <div className="min-w-0 flex-1">
              <h3 className="font-medium">{guides['ai-tools'].title}</h3>
              <p className="mt-1 text-sm text-muted-foreground">{guides['ai-tools'].desc}</p>
            </div>
            <Button asChild size="sm">
              <Link href="/setup/guides/ai-tools">
                View setup guide <ArrowRight aria-hidden />
              </Link>
            </Button>
          </div>
        </Section>
      </div>
    </>
  );
}
