'use server';

import { cookies } from 'next/headers';
import { unstable_rethrow } from 'next/navigation';
import { eq, and } from 'drizzle-orm';
import { z } from 'zod';
import { api } from './api';
import { createClient } from './supabase/server';
import { supabaseAdmin } from './supabase/admin';
import { db, schema } from './db';
import { deliverInvitation, upsertInvitation } from './invitations';
import { authBypass, getCtx, requireOrg, requireRole } from './session';
import type { List, Repository, ApiKey, Exclusion, PackageAnalysis, Policy, ProjectSettings, QueryResult, SavedQuery, Settings } from './types';

export type ActionResult<T> = { ok: true; data: T } | { ok: false; error: string };

async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (e) {
    unstable_rethrow(e);
    const msg = e instanceof z.ZodError ? e.issues[0]?.message ?? 'Invalid input' : e instanceof Error ? e.message : 'Something went wrong';
    return { ok: false, error: msg };
  }
}

const noBypass = () => {
  if (authBypass) throw new Error('Not available in E2E bypass mode.');
};

// ---------- session / profile ----------
export const switchOrg = async (organizationId: string) =>
  run(async () => {
    noBypass();
    const ctx = await getCtx();
    if (!ctx?.orgs.some((o) => o.id === organizationId)) throw new Error('Not a member of that organization.');
    const jar = await cookies();
    jar.set('active-org', organizationId, { path: '/', httpOnly: true, sameSite: 'lax', maxAge: 365 * 86400 });
  });

export const updateProfile = async (name: string) =>
  run(async () => {
    noBypass();
    const validated = z.string().trim().min(1, 'Name is required').max(100).parse(name);
    const supabase = await createClient();
    const { error } = await supabase.auth.updateUser({ data: { full_name: validated, name: validated } });
    if (error) throw new Error(error.message);
  });

export const revokeOtherSessions = async () =>
  run(async () => {
    noBypass();
    const supabase = await createClient();
    const { error } = await supabase.auth.signOut({ scope: 'others' });
    if (error) throw new Error(error.message);
  });

// ---------- tenant (organization) ----------
export const updateOrgName = async (name: string) =>
  run(async () => {
    const ctx = await requireRole('admin');
    noBypass();
    const validated = z.string().trim().min(2, 'Name is too short').max(80).parse(name);
    await db.update(schema.organization).set({ name: validated }).where(eq(schema.organization.id, ctx.org.id));
  });

const roleSchema = z.enum(['owner', 'admin', 'member']);

export const inviteMember = async (email: string, role: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    const validEmail = z.email('Enter a valid email').parse(email.trim());
    const validRole = roleSchema.parse(role);
    const id = await upsertInvitation(ctx.org.id, validEmail, validRole, ctx.user.id);
    return deliverInvitation(validEmail, ctx.org.name, id);
  });

export const resendInvitation = async (email: string, role: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    const validEmail = z.email('Enter a valid email').parse(email.trim());
    const id = await upsertInvitation(ctx.org.id, validEmail, roleSchema.parse(role), ctx.user.id);
    return deliverInvitation(validEmail, ctx.org.name, id);
  });

export const cancelInvitation = async (invitationId: string) =>
  run(async () => {
    await requireRole('owner');
    noBypass();
    await db.update(schema.invitation).set({ status: 'cancelled' }).where(eq(schema.invitation.id, invitationId));
  });

export const updateMemberRole = async (memberId: string, role: string) =>
  run(async () => {
    await requireRole('owner');
    noBypass();
    const validRole = roleSchema.parse(role);
    await db.update(schema.member).set({ role: validRole }).where(eq(schema.member.id, memberId));
  });

export const removeMember = async (memberIdOrEmail: string) =>
  run(async () => {
    await requireRole('owner');
    noBypass();
    await db.delete(schema.member).where(eq(schema.member.id, memberIdOrEmail));
  });

// ---------- Go API ----------
export const listRepositories = async () =>
  run(async () => {
    await requireOrg();
    return (await api<List<Repository>>('/repositories', { query: { page_size: 50 } })).items;
  });

export const startScan = async (repo_id: string, branch?: string) =>
  run(async () => {
    await requireRole('admin');
    return api<{ scan_id: string }>('/scans', { method: 'POST', body: { repo_id, ...(branch && { branch }) } });
  });

export const verifyAnalysis = async (id: string, status: 'malicious' | 'clean') =>
  run(async () => {
    await requireRole('admin');
    return api<PackageAnalysis>(`/package-analyses/${encodeURIComponent(id)}/verify`, { method: 'POST', body: { status } });
  });

export const createApiKey = async (name: string, expires_at?: string) =>
  run(async () => {
    await requireRole('admin');
    const body = { name: z.string().trim().min(1, 'Name is required').max(80).parse(name), ...(expires_at && { expires_at: new Date(expires_at).toISOString() }) };
    return api<ApiKey>('/api-keys', { method: 'POST', body });
  });

export const revokeApiKey = async (id: string) =>
  run(async () => {
    await requireRole('admin');
    await api(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
  });

const exclusionSchema = z.object({
  ecosystem: z.string().min(1, 'Ecosystem is required'),
  name: z.string().trim().min(1, 'Package name is required'),
  version: z.string().trim(),
  reason: z.string().trim().min(1, 'Reason is required').max(500),
  expires_at: z.string().nullable(),
});

export const saveExclusion = async (id: string | null, data: z.input<typeof exclusionSchema>) =>
  run(async () => {
    await requireRole('admin');
    const body = exclusionSchema.parse(data);
    if (body.expires_at) body.expires_at = new Date(body.expires_at).toISOString();
    return id
      ? api<Exclusion>(`/exclusions/${encodeURIComponent(id)}`, { method: 'PUT', body })
      : api<Exclusion>('/exclusions', { method: 'POST', body });
  });

export const deleteExclusion = async (id: string) =>
  run(async () => {
    await requireRole('admin');
    await api(`/exclusions/${encodeURIComponent(id)}`, { method: 'DELETE' });
  });

export const saveSettings = async (patch: Partial<Pick<Settings, 'block_mode' | 'scan_draft_prs' | 'suppress_clean_comments'>>) =>
  run(async () => {
    await requireRole('admin');
    const current = await api<Settings>('/settings');
    return api<Settings>('/settings', { method: 'PUT', body: { ...current, ...patch } });
  });

export const savePolicy = async (policy: Policy) =>
  run(async () => {
    await requireRole('admin');
    return api<Policy>('/policy', { method: 'PUT', body: policy });
  });

const projectSettingsSchema = z.object({
  license: z
    .string()
    .trim()
    .max(200)
    .regex(/^[A-Za-z0-9.+\-() ]*$/, 'License must be an SPDX expression such as MIT or Apache-2.0 OR MIT')
    .transform((v) => v || null)
    .nullable(),
  usage_model: z.enum(['internal', 'saas', 'distributed_binary', 'distributed_source']),
});

export const saveProjectSettings = async (projectId: string, data: z.input<typeof projectSettingsSchema>) =>
  run(async () => {
    await requireRole('admin');
    return api<ProjectSettings>(`/projects/${encodeURIComponent(projectId)}/settings`, { method: 'PUT', body: projectSettingsSchema.parse(data) });
  });

export const testPolicy = async (input: { expr: string; ecosystem: string; name: string; version: string }) =>
  run(async () => {
    await requireOrg();
    return api<{ matched: boolean; error?: string }>('/policy/test', { method: 'POST', body: input });
  });

export const runQuery = async (sql: string) =>
  run(async () => {
    await requireOrg();
    return api<QueryResult>('/query', { method: 'POST', body: { sql } });
  });

export const saveQuery = async (name: string, sql: string) =>
  run(async () => {
    await requireOrg();
    return api<SavedQuery>('/queries', { method: 'POST', body: { name: z.string().trim().min(1, 'Name is required').parse(name), sql } });
  });

export const deleteQuery = async (id: string) =>
  run(async () => {
    await requireOrg();
    await api(`/queries/${encodeURIComponent(id)}`, { method: 'DELETE' });
  });

// ---------- Accept / decline invitation ----------
export const acceptInvitation = async (invitationId: string) =>
  run(async () => {
    noBypass();
    const ctx = await getCtx();
    if (!ctx) throw new Error('Not signed in.');
    const [inv] = await db
      .select()
      .from(schema.invitation)
      .where(and(eq(schema.invitation.id, invitationId), eq(schema.invitation.status, 'pending')))
      .limit(1);
    if (!inv || inv.expiresAt < new Date()) throw new Error('Invitation is no longer valid.');
    if (inv.email.toLowerCase() !== ctx.user.email.toLowerCase()) throw new Error('This invitation is for a different email address.');
    const memberId = crypto.randomUUID().replaceAll('-', '');
    await db.insert(schema.member).values({
      id: memberId,
      organizationId: inv.organizationId,
      userId: ctx.user.id,
      role: inv.role ?? 'member',
      createdAt: new Date(),
    });
    await db.update(schema.invitation).set({ status: 'accepted' }).where(eq(schema.invitation.id, invitationId));
    const jar = await cookies();
    jar.set('active-org', inv.organizationId, { path: '/', httpOnly: true, sameSite: 'lax', maxAge: 365 * 86400 });
  });

export const declineInvitation = async (invitationId: string) =>
  run(async () => {
    noBypass();
    await db.update(schema.invitation).set({ status: 'rejected' }).where(eq(schema.invitation.id, invitationId));
  });
