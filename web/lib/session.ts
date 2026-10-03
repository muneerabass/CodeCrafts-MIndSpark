import 'server-only';
import { cache } from 'react';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { eq } from 'drizzle-orm';
import { createClient } from './supabase/server';
import { superadminEmails } from './auth';
import { db, schema } from './db';
import type { Role } from './types';

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
    const jar = await cookies();
    const role = (jar.get('e2e_role')?.value as Role) || (process.env.E2E_ROLE as Role) || 'owner';
    const sa = (jar.get('e2e_sa')?.value ?? process.env.E2E_SA) !== '0';
    const orgs: Org[] = [
      { id: 'org_mock_acme', name: 'Acme Corp', slug: 'acme', role },
      { id: 'org_mock_globex', name: 'Globex', slug: 'globex', role: 'member' },
    ];
    return { user: { id: 'u_mock', name: 'Ada Lovelace', email: 'ada@acme.dev', image: null }, org: orgs[0], role, sa, orgs };
  }

  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return null;

  const name = (user.user_metadata?.full_name as string) || (user.user_metadata?.name as string) || user.email?.split('@')[0] || '';
  const email = user.email ?? '';
  const image = (user.user_metadata?.avatar_url as string) || null;

  const orgs = (await db
    .select({ id: schema.organization.id, name: schema.organization.name, slug: schema.organization.slug, role: schema.member.role })
    .from(schema.member)
    .innerJoin(schema.organization, eq(schema.member.organizationId, schema.organization.id))
    .where(eq(schema.member.userId, user.id))
    .orderBy(schema.organization.name)) as Org[];

  const jar = await cookies();
  const activeOrgId = jar.get('active-org')?.value;
  const org = orgs.find((o) => o.id === activeOrgId) ?? orgs[0] ?? null;

  return {
    user: { id: user.id, name: name.trim() || email.split('@')[0], email, image },
    org,
    role: org?.role ?? null,
    sa: (user.app_metadata?.role === 'admin') || superadminEmails.includes(email.toLowerCase()),
    orgs,
  };
});

export async function requireOrg() {
  const ctx = await getCtx();
  if (!ctx) redirect('/sign-in');
  if (!ctx.org) redirect('/onboarding');
  return ctx as Ctx & { org: Org; role: Role };
}

export const canWrite = (role: Role | null) => role === 'owner' || role === 'admin';

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
