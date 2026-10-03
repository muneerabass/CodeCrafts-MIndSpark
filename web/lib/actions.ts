'use server';

import { headers } from 'next/headers';
import { unstable_rethrow } from 'next/navigation';
import { z } from 'zod';
import { api } from './api';
import { auth } from './auth';
import { authBypass, getCtx, requireOrg, requireRole } from './session';
import type { List, Repository, ApiKey, Exclusion, PackageAnalysis, Policy, QueryResult, SavedQuery, Settings } from './types';

export type ActionResult<T> = { ok: true; data: T } | { ok: false; error: string };

/** Server action errors are scrubbed in production builds, so return them as values. */
async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (e) {
    unstable_rethrow(e);
    const msg = e instanceof z.ZodError ? e.issues[0]?.message ?? 'Invalid input' : e instanceof Error ? e.message : 'Something went wrong';
    return { ok: false, error: msg };
  }
}

const h = async () => ({ headers: await headers() });
const noBypass = () => {
  if (authBypass) throw new Error('Not available in E2E bypass mode.');
};

// ---------- session / profile ----------
export const switchOrg = async (organizationId: string) =>
  run(async () => {
    noBypass();
    const ctx = await getCtx();
    if (!ctx?.orgs.some((o) => o.id === organizationId)) throw new Error('Not a member of that organization.');
    await auth.api.setActiveOrganization({ ...(await h()), body: { organizationId } });
  });

export const updateProfile = async (name: string) =>
  run(async () => {
    noBypass();
    await auth.api.updateUser({ ...(await h()), body: { name: z.string().trim().min(1, 'Name is required').max(100).parse(name) } });
  });

export const revokeOtherSessions = async () =>
  run(async () => {
    noBypass();
    await auth.api.revokeOtherSessions(await h());
  });

// ---------- tenant (Better Auth organization) ----------
export const updateOrgName = async (name: string) =>
  run(async () => {
    const ctx = await requireRole('admin');
    noBypass();
    await auth.api.updateOrganization({ ...(await h()), body: { organizationId: ctx.org.id, data: { name: z.string().trim().min(2, 'Name is too short').max(80).parse(name) } } });
  });

const roleSchema = z.enum(['owner', 'admin', 'member']);

export const inviteMember = async (email: string, role: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    await auth.api.createInvitation({
      ...(await h()),
      body: { email: z.email('Enter a valid email').parse(email.trim()), role: roleSchema.parse(role), organizationId: ctx.org.id },
    });
  });

export const resendInvitation = async (email: string, role: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    await auth.api.createInvitation({ ...(await h()), body: { email, role: roleSchema.parse(role), organizationId: ctx.org.id, resend: true } });
  });

export const cancelInvitation = async (invitationId: string) =>
  run(async () => {
    await requireRole('owner');
    noBypass();
    await auth.api.cancelInvitation({ ...(await h()), body: { invitationId } });
  });

export const updateMemberRole = async (memberId: string, role: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    await auth.api.updateMemberRole({ ...(await h()), body: { memberId, role: roleSchema.parse(role), organizationId: ctx.org.id } });
  });

export const removeMember = async (memberIdOrEmail: string) =>
  run(async () => {
    const ctx = await requireRole('owner');
    noBypass();
    await auth.api.removeMember({ ...(await h()), body: { memberIdOrEmail, organizationId: ctx.org.id } });
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
