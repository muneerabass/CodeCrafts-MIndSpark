import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { Settings, SLA } from '@/lib/types';
import { AlarmClock } from 'lucide-react';
import { DeadlinesForm } from './deadlines';
import { PageHeader, SectionHeader } from '@/components/page';
import { GitHubIcon } from '@/components/icons';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PreferencesForm } from '../client';

export const metadata = { title: 'Preferences' };

export default async function PreferencesPage() {
  const { role } = await requireOrg();
  const [s, sla] = await Promise.all([api<Settings>('/settings'), api<SLA>('/settings/sla')]);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Preferences' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Tenant Preferences" description="Tenant-wide switches that change how depguard behaves" />
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <GitHubIcon /> GitHub Integration
            </CardTitle>
          </CardHeader>
          <CardContent>
            <PreferencesForm settings={s} canEdit={canWrite(role)} />
          </CardContent>
        </Card>
        <Card id="deadlines" className="mt-4 scroll-mt-20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <AlarmClock className="size-4 text-primary" /> Fix deadlines
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DeadlinesForm initial={sla} canEdit={canWrite(role)} />
          </CardContent>
        </Card>
        {!canWrite(role) && <p className="mt-3 text-sm text-muted-foreground">Only owners and admins can change preferences.</p>}
      </div>
    </>
  );
}
