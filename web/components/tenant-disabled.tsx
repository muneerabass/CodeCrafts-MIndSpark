import Link from 'next/link';
import { Ban } from 'lucide-react';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { EmptyState } from '@/components/page';

export function TenantDisabled({ name, sa }: { name: string; sa: boolean }) {
  return (
    <>
      <header className="flex h-14 items-center border-b px-4">
        <SidebarTrigger className="-ml-1" />
      </header>
      <EmptyState icon={Ban} title="This tenant is disabled" className="py-24">
        <p>
          A platform administrator has disabled <b>{name}</b>. Scans, data and settings are unavailable until it is re-enabled. If you belong to another
          organization, switch to it from the menu at the top of the sidebar.
        </p>
        {sa && (
          <Link href="/admin" className="mt-4 inline-block text-sm font-medium text-primary hover:underline">
            Manage tenants in the admin panel
          </Link>
        )}
      </EmptyState>
    </>
  );
}
