'use client';

import { useState } from 'react';
import { Loader2, Mail, MailCheck } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { GitHubIcon, GoogleIcon } from '@/components/icons';
import { authClient } from '@/lib/auth-client';

export function SignInForm({ providers, next }: { providers: ('github' | 'google')[]; next: string }) {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errorCallbackURL = `/sign-in?next=${encodeURIComponent(next)}`;

  async function social(provider: 'github' | 'google') {
    setBusy(provider);
    setError(null);
    const r = await authClient.signIn.social({ provider, callbackURL: next, errorCallbackURL });
    if (r.error) {
      setError(r.error.message ?? 'Could not start sign-in.');
      setBusy(null);
    }
  }

  async function magic(e: React.FormEvent) {
    e.preventDefault();
    setBusy('email');
    setError(null);
    const r = await authClient.signIn.magicLink({ email: email.trim(), callbackURL: next, errorCallbackURL });
    setBusy(null);
    if (r.error) setError(r.error.message ?? 'Could not send the link.');
    else setSent(true);
  }

  if (sent)
    return (
      <div className="flex flex-col items-center text-center" role="status">
        <MailCheck className="mb-2 size-8 text-primary" />
        <p className="font-medium">Check your inbox</p>
        <p className="mt-1 text-sm text-muted-foreground">
          If <span className="font-medium text-foreground">{email}</span> has access, a sign-in link is on its way. It expires in a few minutes.
        </p>
        <Button variant="link" className="mt-2" onClick={() => setSent(false)}>
          Use a different email
        </Button>
      </div>
    );

  return (
    <div className="flex flex-col gap-3">
      {providers.includes('github') && (
        <Button variant="outline" disabled={!!busy} onClick={() => social('github')}>
          {busy === 'github' ? <Loader2 className="animate-spin" /> : <GitHubIcon />} Continue with GitHub
        </Button>
      )}
      {providers.includes('google') && (
        <Button variant="outline" disabled={!!busy} onClick={() => social('google')}>
          {busy === 'google' ? <Loader2 className="animate-spin" /> : <GoogleIcon />} Continue with Google
        </Button>
      )}
      {providers.length > 0 && (
        <div className="my-1 flex items-center gap-3 text-xs text-muted-foreground">
          <span className="h-px flex-1 bg-border" /> or <span className="h-px flex-1 bg-border" />
        </div>
      )}
      <form onSubmit={magic} className="flex flex-col gap-2">
        <Label htmlFor="email">Work email</Label>
        <Input id="email" type="email" required autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
        <Button type="submit" disabled={!!busy || !email}>
          {busy === 'email' ? <Loader2 className="animate-spin" /> : <Mail />} Email me a sign-in link
        </Button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
