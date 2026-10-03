import { betterAuth, APIError } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { nextCookies } from 'better-auth/next-js';
import { admin, magicLink, organization } from 'better-auth/plugins';
import { and, eq, gt, sql } from 'drizzle-orm';
import { db, schema } from './db';
import { sendMail } from './email';

export const publicUrl = process.env.PUBLIC_URL ?? process.env.BETTER_AUTH_URL ?? 'http://localhost:3000';

export const superadminEmails = (process.env.SUPERADMIN_EMAILS ?? '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

/** Invite-only: a new account is allowed for bootstrap super-admins or emails with a live invitation. */
async function mayRegister(email: string) {
  const e = email.toLowerCase();
  if (superadminEmails.includes(e)) return true;
  const [row] = await db
    .select({ id: schema.invitation.id })
    .from(schema.invitation)
    .where(and(sql`lower(${schema.invitation.email}) = ${e}`, eq(schema.invitation.status, 'pending'), gt(schema.invitation.expiresAt, new Date())))
    .limit(1);
  return !!row;
}

const social = {
  ...(process.env.GITHUB_CLIENT_ID && {
    github: { clientId: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET ?? '' },
  }),
  ...(process.env.GOOGLE_CLIENT_ID && {
    google: { clientId: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '' },
  }),
};
export const enabledProviders = Object.keys(social) as ('github' | 'google')[];

export const auth = betterAuth({
  appName: 'depguard',
  baseURL: publicUrl,
  database: drizzleAdapter(db, { provider: 'pg', schema }),
  socialProviders: social,
  account: { accountLinking: { enabled: true, trustedProviders: ['github', 'google'] } },
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          if (!(await mayRegister(user.email))) {
            throw new APIError('FORBIDDEN', { message: 'depguard is invite-only. Ask your administrator for an invitation.' });
          }
          return { data: { ...user, role: superadminEmails.includes(user.email.toLowerCase()) ? 'admin' : 'user' } };
        },
      },
    },
    session: {
      create: {
        // Land every new session in the user's first organization.
        before: async (session) => {
          const [m] = await db
            .select({ orgId: schema.member.organizationId })
            .from(schema.member)
            .where(eq(schema.member.userId, session.userId))
            .orderBy(schema.member.createdAt)
            .limit(1);
          return { data: { ...session, activeOrganizationId: m?.orgId ?? null } };
        },
      },
    },
  },
  plugins: [
    organization({
      allowUserToCreateOrganization: false, // tenants are created by super-admins only (/admin)
      invitationExpiresIn: 7 * 24 * 3600,
      sendInvitationEmail: async ({ id, email, organization: org, inviter }) => {
        await sendMail(email, `You're invited to ${org.name} on depguard`, `${inviter.user.name} invited you to join ${org.name} on depguard.`, {
          label: 'Accept invitation',
          url: `${publicUrl}/accept-invitation/${id}`,
        });
      },
    }),
    admin(),
    magicLink({
      sendMagicLink: async ({ email, url }) => {
        // Don't mail strangers: only existing users or invited/bootstrap emails get a link.
        const [u] = await db.select({ id: schema.user.id }).from(schema.user).where(sql`lower(${schema.user.email}) = ${email.toLowerCase()}`).limit(1);
        if (!u && !(await mayRegister(email))) return;
        await sendMail(email, 'Your depguard sign-in link', 'Use this link to sign in to depguard. It expires in 5 minutes.', { label: 'Sign in', url });
      },
    }),
    nextCookies(),
  ],
});

export type Session = typeof auth.$Infer.Session;
