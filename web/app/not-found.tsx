import Link from 'next/link';
import { SearchX } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/page';

export default function NotFound() {
  return (
    <main className="flex min-h-dvh items-center justify-center">
      <EmptyState icon={SearchX} title="Page not found">
        <p>The page or record you are looking for does not exist, or you do not have access to it.</p>
        <Button asChild className="mt-4">
          <Link href="/dashboard">Go to dashboard</Link>
        </Button>
      </EmptyState>
    </main>
  );
}
