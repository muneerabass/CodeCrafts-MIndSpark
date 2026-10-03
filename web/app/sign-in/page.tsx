import Link from 'next/link';
import { redirect } from 'next/navigation';
import { Logo } from '@/components/icons';
import { enabledProviders } from '@/lib/auth';
import { one, type SearchParams } from '@/lib/api';
import { authBypass, getCtx } from '@/lib/session';
import { SignInForm } from './form';

export const metadata = { title: 'Sign in' };

const safeNext = (v: string | undefined) => (v && /^\/(?![/\\])/.test(v) ? v : '/dashboard');

function errorMessage(code: string) {
  const c = code.toLowerCase();
  if (c.includes('invite') || c.includes('unable_to_create_user') || c.includes('signup') || c.includes('forbidden'))
    return 'depguard is invite-only. Ask your administrator for an invitation, then sign in with the invited email address.';
  if (c.includes('expired')) return 'That sign-in link has expired. Request a new one below.';
  if (c.includes('invalid_token') || c.includes('invalid')) return 'That sign-in link is invalid or was already used. Request a new one below.';
  return `Sign-in failed (${code.replace(/_/g, ' ')}). Please try again.`;
}

export default async function SignInPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const next = safeNext(one(sp.next));
  const error = one(sp.error);
  if (!authBypass) {
    const ctx = await getCtx();
    if (ctx) redirect(ctx.org ? next : '/onboarding');
  }
  return (
    <main className="flex min-h-dvh flex-col items-center justify-center bg-muted/40 p-4">
      <div className="w-full max-w-sm rounded-xl border bg-card p-6 shadow-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <Logo className="mb-3 size-10" />
          <h1 className="text-xl font-semibold">Sign in to depguard</h1>
          <p className="mt-1 text-sm text-muted-foreground">Supply-chain security for your code, pipelines and machines.</p>
        </div>
        {error && (
          <p role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {errorMessage(error)}
          </p>
        )}
        <SignInForm providers={enabledProviders} next={next} />
        <p className="mt-6 text-center text-xs text-muted-foreground">
          Access is by invitation only. New accounts are created when you accept an invite.
        </p>
      </div>
      <Link href="/attributions" className="mt-6 text-xs text-muted-foreground hover:text-foreground hover:underline">
        Data sources &amp; attributions
      </Link>
    </main>
  );
}
