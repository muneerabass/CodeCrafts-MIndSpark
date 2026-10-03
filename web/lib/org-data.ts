import 'server-only';
import { and, eq } from 'drizzle-orm';
import { db, schema } from './db';
import { authBypass } from './session';
import type { Role } from './types';

export type MemberRow = { id: string; userId: string; name: string; email: string; role: Role; createdAt: string };
export type InvitationRow = { id: string; email: string; role: Role; status: string; createdAt: string; expiresAt: string };

export async function listMembers(orgId: string): Promise<MemberRow[]> {
  if (authBypass)
    return [
      { id: 'm_1', userId: 'u_mock', name: 'Ada Lovelace', email: 'ada@acme.dev', role: 'owner', createdAt: '2026-08-01T10:00:00Z' },
      { id: 'm_2', userId: 'u_2', name: 'Grace Hopper', email: 'grace@acme.dev', role: 'admin', createdAt: '2026-08-12T10:00:00Z' },
      { id: 'm_3', userId: 'u_3', name: 'Alan Turing', email: 'alan@acme.dev', role: 'member', createdAt: '2026-09-02T10:00:00Z' },
    ];
  const rows = await db
    .select({ id: schema.member.id, userId: schema.user.id, name: schema.user.name, email: schema.user.email, role: schema.member.role, createdAt: schema.member.createdAt })
    .from(schema.member)
    .innerJoin(schema.user, eq(schema.member.userId, schema.user.id))
    .where(eq(schema.member.organizationId, orgId))
    .orderBy(schema.member.createdAt);
  return rows.map((r) => ({ ...r, role: r.role as Role, createdAt: r.createdAt.toISOString() }));
}

export async function listInvitations(orgId: string): Promise<InvitationRow[]> {
  if (authBypass)
    return [{ id: 'inv_1', email: 'linus@acme.dev', role: 'member', status: 'pending', createdAt: '2026-09-28T10:00:00Z', expiresAt: '2026-10-05T10:00:00Z' }];
  const rows = await db
    .select()
    .from(schema.invitation)
    .where(and(eq(schema.invitation.organizationId, orgId), eq(schema.invitation.status, 'pending')))
    .orderBy(schema.invitation.createdAt);
  return rows.map((r) => ({
    id: r.id,
    email: r.email,
    role: (r.role ?? 'member') as Role,
    status: r.expiresAt < new Date() ? 'expired' : r.status,
    createdAt: r.createdAt.toISOString(),
    expiresAt: r.expiresAt.toISOString(),
  }));
}
