import { AppSidebar } from '@/components/app-sidebar';
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar';
import { requireSA } from '@/lib/session';
import { sidebarCtx } from '@/lib/shell';

export const metadata = { title: 'Platform admin' };

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireSA();
  return (
    <SidebarProvider>
      <AppSidebar mode="admin" ctx={sidebarCtx(ctx)} />
      <SidebarInset className="min-w-0">{children}</SidebarInset>
    </SidebarProvider>
  );
}
