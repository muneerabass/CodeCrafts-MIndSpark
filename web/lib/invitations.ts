import 'server-only';
import { and, eq, gt, sql } from 'drizzle-orm';
import { db, schema } from './db';
import { publicUrl } from './auth';
import { emailConfigured, sendMail } from './email';

const INVITE_DAYS = 7;

/**
 * Creates a pending invitation, or refreshes the existing pending one for the same
 * email in this tenant (new role, new expiry) so repeated invites never pile up.
 */
export async function upsertInvitation(orgId: string, email: string, role: string, inviterId: string): Promise<string> {
  const lower = email.toLowerCase();
  const expiresAt = new Date(Date.now() + INVITE_DAYS * 86_400_000);
  const [existing] = await db
    .select({ id: schema.invitation.id })
    .from(schema.invitation)
    .where(and(eq(schema.invitation.organizationId, orgId), eq(schema.invitation.email, lower), eq(schema.invitation.status, 'pending')));
  if (existing) {
    await db.update(schema.invitation).set({ role, expiresAt, inviterId }).where(eq(schema.invitation.id, existing.id));
    // Older duplicates from before this fix: keep only the refreshed one.
    await db
      .update(schema.invitation)
      .set({ status: 'cancelled' })
      .where(
        and(
          eq(schema.invitation.organizationId, orgId),
          eq(schema.invitation.email, lower),
          eq(schema.invitation.status, 'pending'),
          sql`${schema.invitation.id} <> ${existing.id}`,
        ),
      );
    return existing.id;
  }
  const id = crypto.randomUUID().replaceAll('-', '');
  await db.insert(schema.invitation).values({
    id,
    organizationId: orgId,
    email: lower,
    role,
    status: 'pending',
    expiresAt,
    inviterId,
  });
  return id;
}

export type InviteDelivery = { emailed: boolean; link: string; signInUrl: string; emailError?: string };

/**
 * Emails the invitation when SMTP is configured. Delivery never fails the invite:
 * the invitee is admitted automatically on sign-in with the invited address, so the
 * inviter can also just share the sign-in link.
 */
export async function deliverInvitation(email: string, orgName: string, id: string): Promise<InviteDelivery> {
  const link = `${publicUrl}/accept-invitation/${id}`;
  const signInUrl = `${publicUrl}/sign-in`;
  if (!emailConfigured()) return { emailed: false, link, signInUrl };
  try {
    await sendMail(
      email,
      `You're invited to ${orgName} on depguard`,
      `You have been invited to join ${orgName} on depguard. Sign in with GitHub or Google using this email address (${email}) and you will get access automatically.`,
      { label: 'Accept invitation', url: link },
    );
    return { emailed: true, link, signInUrl };
  } catch (e) {
    console.error('[invite] email delivery failed:', e instanceof Error ? e.message : e);
    return { emailed: false, link, signInUrl, emailError: 'The email could not be sent; share the link instead.' };
  }
}

/**
 * Admits a signed-in user to every tenant that has a pending, unexpired invitation
 * for their verified email, with the invited role. Idempotent; called on sign-in and
 * whenever the session is loaded.
 */
export async function acceptPendingInvitations(user: { id: string; email?: string | null; emailVerified: boolean }): Promise<number> {
  if (!user.email || !user.emailVerified) return 0;
  const pending = await db
    .select({ id: schema.invitation.id, organizationId: schema.invitation.organizationId, role: schema.invitation.role })
    .from(schema.invitation)
    .where(
      and(
        sql`lower(${schema.invitation.email}) = ${user.email.toLowerCase()}`,
        eq(schema.invitation.status, 'pending'),
        gt(schema.invitation.expiresAt, new Date()),
      ),
    );
  let joined = 0;
  for (const inv of pending) {
    await db.transaction(async (tx) => {
      const [member] = await tx
        .select({ id: schema.member.id })
        .from(schema.member)
        .where(and(eq(schema.member.organizationId, inv.organizationId), eq(schema.member.userId, user.id)));
      if (!member) {
        await tx.insert(schema.member).values({
          id: crypto.randomUUID().replaceAll('-', ''),
          organizationId: inv.organizationId,
          userId: user.id,
          role: inv.role ?? 'member',
          createdAt: new Date(),
        });
        joined++;
      }
      await tx.update(schema.invitation).set({ status: 'accepted' }).where(eq(schema.invitation.id, inv.id));
    });
  }
  return joined;
}
