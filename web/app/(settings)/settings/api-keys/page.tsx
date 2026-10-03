import { api } from '@/lib/api';
import { canWrite, requireOrg } from '@/lib/session';
import type { ApiKey, List, Settings } from '@/lib/types';
import { PageHeader, SectionHeader } from '@/components/page';
import { CopyButton } from '@/components/client';
import { Card } from '@/components/ui/card';
import { ApiKeysTable, CreateApiKeyButton } from '../client';

export const metadata = { title: 'API keys' };

export default async function ApiKeysPage() {
  const { role } = await requireOrg();
  const [s, keys] = await Promise.all([api<Settings>('/settings'), api<List<ApiKey>>('/api-keys')]);
  const can = canWrite(role);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'API Keys' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader
          title="API Keys"
          description="Keys for the CLI, CI pipelines, endpoint agents and MCP clients of this tenant"
          actions={
            <>
              <CopyButton value={s.tenant_id} label="Tenant ID" variant="outline" />
              <CreateApiKeyButton disabled={!can} />
            </>
          }
        />
        <Card className="overflow-hidden py-0">
          <ApiKeysTable keys={keys.items} canEdit={can} />
        </Card>
      </div>
    </>
  );
}
