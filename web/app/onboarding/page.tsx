import Link from 'next/link';
import { redirect } from 'next/navigation';
import { UserRoundX } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Logo } from '@/components/icons';
import { getCtx } from '@/lib/session';
import { SignOutButton } from './sign-out';

export const metadata = { title: 'Waiting for an invitation' };

export default async function OnboardingPage() {
  const ctx = await getCtx();
  if (!ctx) redirect('/sign-in');
  if (ctx.org) redirect('/dashboard');
  return (
    <main className="flex min-h-dvh items-center justify-center bg-muted/40 p-4">
      <div className="w-full max-w-md rounded-xl border bg-card p-6 text-center shadow-sm">
        <Logo className="mx-auto mb-4 size-10" />
        <div className="mx-auto mb-3 flex size-12 items-center justify-center rounded-xl border bg-accent text-primary">
          <UserRoundX className="size-6" />
        </div>
        <h1 className="text-lg font-semibold">Ask your administrator for an invitation</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          You&apos;re signed in as <span className="font-medium text-foreground">{ctx.user.email}</span>, but this account doesn&apos;t belong to any
          tenant yet. Once someone invites this address, open the link in the invitation email to get access.
        </p>
        <div className="mt-5 flex flex-col gap-2">
          {ctx.sa && (
            <Button asChild>
              <Link href="/admin">Open platform admin</Link>
            </Button>
          )}
          <SignOutButton />
        </div>
      </div>
    </main>
  );
}
