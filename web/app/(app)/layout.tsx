import { AppSidebar } from '@/components/app-sidebar';
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar';
import { canWrite, requireOrg } from '@/lib/session';
import { sidebarCtx } from '@/lib/shell';
import { api, tenantDisabled } from '@/lib/api';
import type { PRSummaryCounts } from '@/lib/types';
import { TenantDisabled } from '@/components/tenant-disabled';
import { AssistantWidget } from '@/components/assistant/widget';

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireOrg();
  const [disabled, prs] = await Promise.all([tenantDisabled(), api<PRSummaryCounts>('/pull-requests/summary').catch(() => null)]);
  const urgentPRs = prs ? (prs.by_level.critical ?? 0) + (prs.by_level.high ?? 0) : 0;
  return (
    <SidebarProvider>
      <AppSidebar mode="app" ctx={{ ...sidebarCtx(ctx), badges: { '/pull-requests': urgentPRs } }} />
      <SidebarInset className="min-w-0">{disabled ? <TenantDisabled name={ctx.org.name} sa={ctx.sa} /> : children}</SidebarInset>
      {!disabled && <AssistantWidget isAdmin={canWrite(ctx.role)} />}
    </SidebarProvider>
  );
}
