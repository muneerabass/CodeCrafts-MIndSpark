'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { authClient } from '@/lib/auth-client';

export function InvitationActions({ id }: { id: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState<'accept' | 'decline' | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function act(kind: 'accept' | 'decline') {
    setBusy(kind);
    setError(null);
    const r =
      kind === 'accept'
        ? await authClient.organization.acceptInvitation({ invitationId: id })
        : await authClient.organization.rejectInvitation({ invitationId: id });
    if (r.error) {
      setError(r.error.message ?? 'Something went wrong.');
      setBusy(null);
      return;
    }
    router.push(kind === 'accept' ? '/dashboard' : '/onboarding');
    router.refresh();
  }

  return (
    <div className="mt-5 flex flex-col gap-2">
      <Button disabled={!!busy} onClick={() => act('accept')}>
        {busy === 'accept' && <Loader2 className="animate-spin" />} Accept invitation
      </Button>
      <Button variant="ghost" disabled={!!busy} onClick={() => act('decline')}>
        {busy === 'decline' && <Loader2 className="animate-spin" />} Decline
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
