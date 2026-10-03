import { ExternalLink } from 'lucide-react';
import { api } from '@/lib/api';
import type { FailedJob, FeedStatus, List, WebhookDelivery } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { Button } from '@/components/ui/button';
import { FeedsTable, JobsTable, WebhooksTable } from '../tables';

export const metadata = { title: 'Ops health' };

function Panel({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border bg-card" aria-label={title}>
      <div className="border-b px-4 py-3">
        <h2 className="font-medium">{title}</h2>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {children}
    </section>
  );
}

const STALE_MS = 24 * 3600_000;
const markStale = (feeds: FeedStatus[]) => feeds.map((f) => ({ ...f, stale: !f.last_ok || Date.now() - Date.parse(f.last_ok) > STALE_MS }));

export default async function AdminHealthPage() {
  const [feeds, jobs, hooks] = await Promise.all([
    api<FeedStatus[]>('/admin/feeds').then(markStale),
    api<List<FailedJob>>('/admin/jobs/failed'),
    api<List<WebhookDelivery>>('/admin/webhooks'),
  ]);
  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Admin', href: '/admin' }, { label: 'Ops health' }]}
        info="Advisory feed freshness, failed background jobs and GitHub webhook deliveries."
        actions={
          <Button asChild size="sm" variant="outline">
            <a href="/admin/river" target="_blank" rel="noreferrer">
              Open River UI <ExternalLink aria-hidden />
            </a>
          </Button>
        }
      />
      <div className="flex flex-col gap-6 p-4">
        <Panel title="Feed sync" description="OSV, KEV and EPSS mirrors. Sources not refreshed in 24 hours are flagged stale.">
          <FeedsTable data={feeds} />
        </Panel>
        <Panel title="Failed jobs" description="Recently failed or discarded River jobs.">
          <JobsTable data={jobs.items} />
        </Panel>
        <Panel title="Webhook deliveries" description="GitHub App deliveries received by the API. Redeliver asks GitHub to send one again.">
          <WebhooksTable data={hooks.items} />
        </Panel>
      </div>
    </>
  );
}
