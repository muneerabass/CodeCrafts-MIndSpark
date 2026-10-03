import Link from 'next/link';
import { eq } from 'drizzle-orm';
import { MailX } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Logo } from '@/components/icons';
import { RoleBadge } from '@/components/badges';
import { db, schema } from '@/lib/db';
import { supabaseAdmin } from '@/lib/supabase/admin';
import { authBypass, getCtx } from '@/lib/session';
import { InvitationActions } from './actions';

export const metadata = { title: 'Accept invitation' };

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-dvh items-center justify-center bg-muted/40 p-4">
      <div className="w-full max-w-md rounded-xl border bg-card p-6 text-center shadow-sm">
        <Logo className="mx-auto mb-4 size-10" />
        {children}
      </div>
    </main>
  );
}

function Problem({ title, text, email }: { title: string; text: string; email?: string }) {
  return (
    <Shell>
      <MailX className="mx-auto mb-2 size-6 text-muted-foreground" />
      <h1 className="text-lg font-semibold">{title}</h1>
      <p className="mt-1 text-sm text-muted-foreground">{text}</p>
      {email && <p className="mt-2 text-sm">Signed in as {email}</p>}
      <Button asChild variant="outline" className="mt-4">
        <Link href="/dashboard">Go to depguard</Link>
      </Button>
    </Shell>
  );
}

async function getInviterName(inviterId: string): Promise<string | null> {
  try {
    const { data } = await supabaseAdmin.auth.admin.getUserById(inviterId);
    return data.user?.user_metadata?.full_name || data.user?.user_metadata?.name || null;
  } catch {
    return null;
  }
}

export default async function AcceptInvitationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const here = `/accept-invitation/${encodeURIComponent(id)}`;

  if (authBypass)
    return (
      <Shell>
        <h1 className="text-lg font-semibold">Join Acme Corp on depguard</h1>
        <p className="mt-1 text-sm text-muted-foreground">Preview (E2E bypass mode) — invitation actions are disabled.</p>
      </Shell>
    );

  const ctx = await getCtx();
  if (!ctx)
    return (
      <Shell>
        <h1 className="text-lg font-semibold">You&apos;ve been invited to depguard</h1>
        <p className="mt-1 text-sm text-muted-foreground">Sign in with the email address the invitation was sent to, and you&apos;ll come straight back here to accept it.</p>
        <Button asChild className="mt-4 w-full">
          <Link href={`/sign-in?next=${encodeURIComponent(here)}`}>Sign in to continue</Link>
        </Button>
      </Shell>
    );

  const [inv] = await db
    .select({
      email: schema.invitation.email,
      role: schema.invitation.role,
      status: schema.invitation.status,
      expiresAt: schema.invitation.expiresAt,
      orgName: schema.organization.name,
      inviterId: schema.invitation.inviterId,
    })
    .from(schema.invitation)
    .innerJoin(schema.organization, eq(schema.invitation.organizationId, schema.organization.id))
    .where(eq(schema.invitation.id, id))
    .limit(1);

  if (!inv || inv.status !== 'pending' || inv.expiresAt < new Date())
    return <Problem title="This invitation is no longer valid" text="It may have expired, been cancelled, or already been accepted. Ask the person who invited you to send a new one." />;
  if (inv.email.toLowerCase() !== ctx.user.email.toLowerCase())
    return (
      <Problem
        title="This invitation is for someone else"
        text={`It was sent to ${inv.email}. Sign out and sign in with that address to accept it.`}
        email={ctx.user.email}
      />
    );

  const inviterName = await getInviterName(inv.inviterId);

  return (
    <Shell>
      <h1 className="text-lg font-semibold">Join {inv.orgName} on depguard</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        {inviterName ? `${inviterName} invited you` : 'You have been invited'} to join as <RoleBadge role={inv.role ?? 'member'} />
      </p>
      <InvitationActions id={id} />
    </Shell>
  );
}
