import { AppSidebar } from '@/components/app-sidebar';
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar';
import { requireOrg } from '@/lib/session';
import { sidebarCtx } from '@/lib/shell';
import { tenantDisabled } from '@/lib/api';
import { TenantDisabled } from '@/components/tenant-disabled';

export default async function SettingsLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireOrg();
  const disabled = await tenantDisabled();
  return (
    <SidebarProvider>
      <AppSidebar mode="settings" ctx={sidebarCtx(ctx)} />
      <SidebarInset className="min-w-0 bg-muted/30">{disabled ? <TenantDisabled name={ctx.org.name} sa={ctx.sa} /> : children}</SidebarInset>
    </SidebarProvider>
  );
}
