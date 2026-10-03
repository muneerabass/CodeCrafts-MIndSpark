import '../landing.css';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { ArrowLeft, Check } from 'lucide-react';
import { Logo } from '@/components/icons';
import { enabledProviders } from '@/lib/auth';
import { one, type SearchParams } from '@/lib/api';
import { landingFonts } from '@/lib/landing-fonts';
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

const POINTS = [
  'Full dependency graph for every repository',
  'Malicious-package and vulnerability checks',
  'Attack paths back to the direct dependency',
  'Policy enforced on every pull request',
];

export default async function SignInPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const next = safeNext(one(sp.next));
  const error = one(sp.error);
  const signup = one(sp.mode) === 'signup';
  const provider = one(sp.provider);
  const autoProvider = provider === 'github' || provider === 'google' ? provider : undefined;
  if (!authBypass) {
    const ctx = await getCtx();
    if (ctx) redirect(ctx.org ? next : '/onboarding');
  }
  const q = (mode?: string) => {
    const p = new URLSearchParams();
    if (mode) p.set('mode', mode);
    if (next !== '/dashboard') p.set('next', next);
    const s = p.toString();
    return `/sign-in${s ? `?${s}` : ''}`;
  };

  return (
    <div className={`lp ${landingFonts} min-h-dvh`}>
      <div className="grid min-h-dvh lg:grid-cols-[1.05fr_1fr]">
        {/* Brand panel */}
        <aside className="relative hidden overflow-hidden border-r border-[var(--lp-line)] lg:block">
          <div aria-hidden className="lp-hero-bg pointer-events-none absolute inset-0" />
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 opacity-60"
            style={{
              backgroundImage: 'linear-gradient(rgb(255 255 255 / 3%) 1px, transparent 1px), linear-gradient(90deg, rgb(255 255 255 / 3%) 1px, transparent 1px)',
              backgroundSize: '56px 56px',
              maskImage: 'radial-gradient(70% 60% at 40% 50%, black, transparent)',
              WebkitMaskImage: 'radial-gradient(70% 60% at 40% 50%, black, transparent)',
            }}
          />
          <div className="relative flex h-full flex-col justify-between p-12">
            <Link href="/" className="flex w-fit items-center gap-2">
              <Logo className="size-6" />
              <span className="lp-display text-xl">depguard</span>
            </Link>

            <div className="max-w-md">
              <p className="lp-eyebrow text-[12px] text-[var(--lp-teal)]">Supply-chain security</p>
              <h2 className="lp-display mt-5 text-[40px] leading-[1.1]">
                Every dependency,
                <br />
                <span className="text-[var(--lp-dim)]">accounted for.</span>
              </h2>
              <ul className="mt-10 space-y-4">
                {POINTS.map((p) => (
                  <li key={p} className="flex gap-3 text-[16px] text-[var(--lp-fg)]">
                    <Check className="mt-1 size-4 shrink-0 text-[var(--lp-teal)]" /> {p}
                  </li>
                ))}
              </ul>

              <div className="mt-12 overflow-hidden border border-[var(--lp-line-2)] bg-[#05080a]">
                <div className="flex items-center gap-2 border-b border-[var(--lp-line)] px-4 py-2.5">
                  <span className="size-2 rounded-full bg-white/20" />
                  <span className="size-2 rounded-full bg-white/20" />
                  <span className="size-2 rounded-full bg-white/20" />
                </div>
                <pre className="lp-mono overflow-x-auto px-4 py-4 text-[13px] leading-6 text-[var(--lp-muted)]">
                  <span className="text-[var(--lp-teal)]">$</span> depguard scan .{'\n'}
                  <span className="text-white">resolved</span> 1,204 components{'\n'}
                  <span className="text-[var(--lp-red)]">blocked </span> colors-utils@3.4.1{'  '}
                  <span className="text-[var(--lp-dim)]">install script</span>
                  {'\n'}
                  <span className="text-[var(--lp-teal)]">pass    </span> policy: no-critical-vulns
                </pre>
              </div>
            </div>

            <p className="lp-mono text-xs text-[var(--lp-dim)]">Sample output</p>
          </div>
        </aside>

        {/* Form panel */}
        <main className="flex flex-col px-5 py-8 sm:px-10">
          <div className="flex items-center justify-between">
            <Link href="/" className="lp-nudge inline-flex items-center gap-2 text-sm text-[var(--lp-muted)] hover:text-white">
              <ArrowLeft className="size-4" /> Back to home
            </Link>
            <Link href="/" className="flex items-center gap-2 lg:hidden">
              <Logo className="size-5" />
              <span className="lp-display text-lg">depguard</span>
            </Link>
          </div>

          <div className="mx-auto flex w-full max-w-sm flex-1 flex-col justify-center py-12">
            {/* Sign in / Get started switch */}
            <div role="tablist" aria-label="Account" className="grid grid-cols-2 border border-[var(--lp-line-2)] p-1 text-[15px]">
              <Link
                role="tab"
                aria-selected={!signup}
                href={q()}
                className={`py-2 text-center ${!signup ? 'border border-[var(--lp-line-2)] bg-white/[0.06] text-white' : 'border border-transparent text-[var(--lp-muted)] hover:text-white'}`}
              >
                Sign in
              </Link>
              <Link
                role="tab"
                aria-selected={signup}
                href={q('signup')}
                className={`py-2 text-center ${signup ? 'border border-[var(--lp-line-2)] bg-white/[0.06] text-white' : 'border border-transparent text-[var(--lp-muted)] hover:text-white'}`}
              >
                Get started
              </Link>
            </div>

            <p className="lp-eyebrow mt-10 text-[11px] text-[var(--lp-teal)]">{signup ? 'Join your workspace' : 'Welcome back'}</p>
            <h1 className="lp-display mt-3 text-[32px] leading-tight">{signup ? 'Get started with depguard' : 'Sign in to depguard'}</h1>
            <p className="mt-3 text-[15px] leading-relaxed text-[var(--lp-muted)]">
              {signup
                ? 'Use the GitHub account or work email your team invited. Your account is created the first time you sign in.'
                : 'No password needed. Continue with GitHub or get a one-time link by email.'}
            </p>

            {error && (
              <p role="alert" className="mt-6 border border-[var(--lp-red)]/40 bg-[var(--lp-red)]/[0.06] p-3 text-sm text-[var(--lp-red)]">
                {errorMessage(error)}
              </p>
            )}

            <div className="mt-8">
              <SignInForm providers={enabledProviders} next={next} signup={signup} autoProvider={error ? undefined : autoProvider} />
            </div>

            <p className="mt-8 text-[13px] leading-relaxed text-[var(--lp-dim)]">
              depguard workspaces are invite-only. Not invited yet? Ask a workspace owner to send an invitation to your email address.
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--lp-dim)]">
            <span className="lp-mono">© {new Date().getFullYear()} depguard</span>
            <Link href="/attributions" className="hover:text-white">
              Data sources &amp; attributions
            </Link>
          </div>
        </main>
      </div>
    </div>
  );
}
