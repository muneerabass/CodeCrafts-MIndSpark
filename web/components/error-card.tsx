'use client';

import { startTransition, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { RefreshCw, ServerCrash } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { SidebarTrigger } from '@/components/ui/sidebar';

/** Route error boundary: shown when the Go API is down or a request fails. */
export default function ErrorCard({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const router = useRouter();
  useEffect(() => console.error(error), [error]);
  return (
    <>
      <header className="flex h-14 items-center border-b px-4">
        <SidebarTrigger className="-ml-1" />
      </header>
      <div className="flex flex-1 items-center justify-center p-6">
        <div role="alert" className="w-full max-w-md rounded-xl border bg-card p-6 text-center shadow-xs">
          <div className="mx-auto mb-4 flex size-12 items-center justify-center rounded-xl bg-red-50 text-red-600">
            <ServerCrash className="size-6" />
          </div>
          <h2 className="font-semibold">We couldn&apos;t load this page</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            The depguard API did not respond as expected. It may be restarting — try again in a moment.
          </p>
          {error.digest && <p className="mt-2 font-mono text-xs text-muted-foreground">Ref: {error.digest}</p>}
          <Button
            className="mt-4"
            onClick={() =>
              startTransition(() => {
                router.refresh();
                reset();
              })
            }
          >
            <RefreshCw /> Retry
          </Button>
        </div>
      </div>
    </>
  );
}
