'use server';

import { eq } from 'drizzle-orm';
import { unstable_rethrow } from 'next/navigation';
import { z } from 'zod';
import { api, ApiError } from './api';
import { publicUrl } from './auth';
import { db, schema } from './db';
import { sendMail } from './email';
import { authBypass, requireSA, tenantDomain } from './session';
import type { ActionResult } from './actions';

async function run<T>(fn: () => Promise<T>): Promise<ActionResult<T>> {
  try {
    return { ok: true, data: await fn() };
  } catch (e) {
    unstable_rethrow(e);
    return { ok: false, error: e instanceof z.ZodError ? e.issues[0]?.message ?? 'Invalid input' : e instanceof Error ? e.message : 'Something went wrong' };
  }
}

const tenantSchema = z.object({
  name: z.string().trim().min(2, 'Name is too short').max(80),
  slug: z.string().trim().regex(/^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/, 'Slug: lowercase letters, digits and dashes'),
  ownerEmail: z.email('Enter the owner’s email'),
});

export const createTenant = async (input: z.input<typeof tenantSchema>) =>
  run(async () => {
    const ctx = await requireSA();
    const t = tenantSchema.parse(input);
    const id = crypto.randomUUID().replaceAll('-', '');
    if (authBypass) {
      await api('/admin/tenants', { method: 'POST', body: { tenant_id: id, domain: tenantDomain(t.slug) } });
      return { id };
    }
    const [taken] = await db.select({ id: schema.organization.id }).from(schema.organization).where(eq(schema.organization.slug, t.slug)).limit(1);
    if (taken) throw new Error('That slug is already taken.');
    await db.insert(schema.organization).values({ id, name: t.name, slug: t.slug, createdAt: new Date() });
    try {
      await api('/admin/tenants', { method: 'POST', body: { tenant_id: id, domain: tenantDomain(t.slug) } });
    } catch (e) {
      await db.delete(schema.organization).where(eq(schema.organization.id, id));
      if (e instanceof ApiError && e.status === 409) throw new Error(`The domain ${tenantDomain(t.slug)} already belongs to another tenant. Pick a different slug.`);
      throw e;
    }
    const invitationId = crypto.randomUUID().replaceAll('-', '');
    await db.insert(schema.invitation).values({
      id: invitationId,
      organizationId: id,
      email: t.ownerEmail.toLowerCase(),
      role: 'owner',
      status: 'pending',
      expiresAt: new Date(Date.now() + 7 * 86_400_000),
      inviterId: ctx.user.id,
    });
    await sendMail(t.ownerEmail, `Your depguard tenant ${t.name} is ready`, `You have been invited as the owner of ${t.name} on depguard.`, {
      label: 'Accept invitation',
      url: `${publicUrl}/accept-invitation/${invitationId}`,
    });
    return { id };
  });

export const setTenantDisabled = async (tenantId: string, disabled: boolean) =>
  run(async () => {
    await requireSA();
    await api(`/admin/tenants/${encodeURIComponent(tenantId)}`, { method: 'PATCH', body: { disabled } });
  });

export const linkInstallation = async (installationId: string, tenantId: string) =>
  run(async () => {
    await requireSA();
    await api(`/admin/installations/${encodeURIComponent(installationId)}/link`, { method: 'POST', body: { tenant_id: z.string().min(1, 'Pick a tenant').parse(tenantId) } });
  });

export const unlinkInstallation = async (installationId: string) =>
  run(async () => {
    await requireSA();
    await api(`/admin/installations/${encodeURIComponent(installationId)}/unlink`, { method: 'POST' });
  });

export const redeliverWebhook = async (deliveryId: string) =>
  run(async () => {
    await requireSA();
    await api(`/admin/webhooks/${encodeURIComponent(deliveryId)}/redeliver`, { method: 'POST' });
  });
