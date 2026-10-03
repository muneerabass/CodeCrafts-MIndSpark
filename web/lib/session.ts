import 'server-only';
import { cache } from 'react';
import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';
import { eq } from 'drizzle-orm';
import { auth, superadminEmails } from './auth';
import { db, schema } from './db';
import type { Role } from './types';

/**
 * Test-only auth bypass for Playwright. Impossible in production builds: requires
 * NODE_ENV !== 'production' (next build/start always set production) AND E2E_AUTH_BYPASS=1.
 */
export const authBypass = process.env.NODE_ENV !== 'production' && process.env.E2E_AUTH_BYPASS === '1';

export type Org = { id: string; name: string; slug: string; role: Role };
export type Ctx = {
  user: { id: string; name: string; email: string; image: string | null };
  org: Org | null;
  role: Role | null;
  sa: boolean;
  orgs: Org[];
};

export const tenantDomain = (slug: string) => `${slug}.${process.env.TENANT_DOMAIN_SUFFIX ?? 'depguard.dev'}`;

export const getCtx = cache(async (): Promise<Ctx | null> => {
  if (authBypass) {
    // Tests may pick the role / super-admin flag per browser context via cookies.
    const jar = await cookies();
    const role = (jar.get('e2e_role')?.value as Role) || (process.env.E2E_ROLE as Role) || 'owner';
    const sa = (jar.get('e2e_sa')?.value ?? process.env.E2E_SA) !== '0';
    const orgs: Org[] = [
      { id: 'org_mock_acme', name: 'Acme Corp', slug: 'acme', role },
      { id: 'org_mock_globex', name: 'Globex', slug: 'globex', role: 'member' },
    ];
    return { user: { id: 'u_mock', name: 'Ada Lovelace', email: 'ada@acme.dev', image: null }, org: orgs[0], role, sa, orgs };
  }
  const s = await auth.api.getSession({ headers: await headers() });
  if (!s) return null;
  const orgs = await db
    .select({ id: schema.organization.id, name: schema.organization.name, slug: schema.organization.slug, role: schema.member.role })
    .from(schema.member)
    .innerJoin(schema.organization, eq(schema.member.organizationId, schema.organization.id))
    .where(eq(schema.member.userId, s.user.id))
    .orderBy(schema.organization.name);
  const typed = orgs as Org[];
  const org = typed.find((o) => o.id === s.session.activeOrganizationId) ?? typed[0] ?? null;
  return {
    user: { id: s.user.id, name: s.user.name, email: s.user.email, image: s.user.image ?? null },
    org,
    role: org?.role ?? null,
    sa: s.user.role === 'admin' || superadminEmails.includes(s.user.email.toLowerCase()),
    orgs: typed,
  };
});

/** For pages inside the tenant app: signed in and member of an organization. */
export async function requireOrg() {
  const ctx = await getCtx();
  if (!ctx) redirect('/sign-in');
  if (!ctx.org) redirect('/onboarding');
  return ctx as Ctx & { org: Org; role: Role };
}

export const canWrite = (role: Role | null) => role === 'owner' || role === 'admin';

/** Server actions: owner/admin (or owner only) for the active organization. */
export async function requireRole(min: 'admin' | 'owner') {
  const ctx = await requireOrg();
  if (min === 'owner' ? ctx.role !== 'owner' : !canWrite(ctx.role)) throw new Error('You do not have permission to do that.');
  return ctx;
}

export async function requireSA() {
  const ctx = await getCtx();
  if (!ctx?.sa) redirect('/dashboard');
  return ctx;
}
