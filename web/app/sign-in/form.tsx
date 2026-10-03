'use client';

import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Loader2, MailCheck } from 'lucide-react';
import { GitHubIcon, GoogleIcon } from '@/components/icons';
import { createClient } from '@/lib/supabase/client';

type Provider = 'github' | 'google';

export function SignInForm({
  providers,
  next,
  signup = false,
  autoProvider,
}: {
  providers: Provider[];
  next: string;
  signup?: boolean;
  /** Start this OAuth flow immediately (e.g. the landing page's "Sign in with GitHub" link). */
  autoProvider?: Provider;
}) {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  async function social(provider: Provider) {
    setBusy(provider);
    setError(null);
    const supabase = createClient();
    const { error: err } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}` },
    });
    if (err) {
      setError(err.message ?? 'Could not start sign-in.');
      setBusy(null);
    }
  }

  useEffect(() => {
    if (autoProvider && providers.includes(autoProvider) && !started.current) {
      started.current = true;
      void social(autoProvider);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoProvider]);

  async function magic(e: React.FormEvent) {
    e.preventDefault();
    setBusy('email');
    setError(null);
    const supabase = createClient();
    const { error: err } = await supabase.auth.signInWithOtp({
      email: email.trim(),
      options: { emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}` },
    });
    setBusy(null);
    if (err) setError(err.message ?? 'Could not send the link.');
    else setSent(true);
  }

  if (sent)
    return (
      <div className="border border-[var(--lp-teal)]/40 bg-[var(--lp-teal)]/[0.05] p-6" role="status">
        <MailCheck className="size-6 text-[var(--lp-teal)]" />
        <p className="lp-display mt-4 text-xl">Check your inbox</p>
        <p className="mt-2 text-[15px] leading-relaxed text-[var(--lp-muted)]">
          If <span className="text-white">{email}</span> has access, a sign-in link is on its way. It expires in a few minutes.
        </p>
        <button type="button" className="mt-4 text-sm text-[var(--lp-teal)] hover:text-white" onClick={() => setSent(false)}>
          Use a different email
        </button>
      </div>
    );

  const label = signup ? 'Sign up' : 'Continue';

  return (
    <div className="flex flex-col gap-3">
      {providers.includes('github') && (
        <button type="button" className="lp-btn lp-btn-ghost h-11 justify-center text-[15px]" disabled={!!busy} onClick={() => social('github')}>
          {busy === 'github' ? <Loader2 className="size-4 animate-spin" /> : <GitHubIcon />} {label} with GitHub
        </button>
      )}
      {providers.includes('google') && (
        <button type="button" className="lp-btn lp-btn-ghost h-11 justify-center text-[15px]" disabled={!!busy} onClick={() => social('google')}>
          {busy === 'google' ? <Loader2 className="size-4 animate-spin" /> : <GoogleIcon />} {label} with Google
        </button>
      )}
      {providers.length > 0 && (
        <div className="lp-eyebrow my-3 flex items-center gap-4 text-[10px] text-[var(--lp-dim)]">
          <span className="h-px flex-1 bg-[var(--lp-line-2)]" /> or <span className="h-px flex-1 bg-[var(--lp-line-2)]" />
        </div>
      )}
      <form onSubmit={magic} className="flex flex-col gap-3">
        <label htmlFor="email" className="lp-eyebrow text-[10px] text-[var(--lp-muted)]">
          Work email
        </label>
        <input
          id="email"
          type="email"
          required
          autoComplete="email"
          placeholder="you@company.com"
          className="lp-input text-[15px]"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <button type="submit" className="lp-btn lp-btn-primary lp-nudge h-11 justify-center text-[15px]" disabled={!!busy || !email}>
          {busy === 'email' ? <Loader2 className="size-4 animate-spin" /> : null}
          Email me a {signup ? 'sign-up' : 'sign-in'} link
          {busy !== 'email' && <ArrowRight className="size-4" />}
        </button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-[var(--lp-red)]">
          {error}
        </p>
      )}
    </div>
  );
}
