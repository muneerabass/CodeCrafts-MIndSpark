import { MailPlus } from 'lucide-react';
import { requireOrg } from '@/lib/session';
import { listInvitations } from '@/lib/org-data';
import { fmtDate, titleCase } from '@/lib/format';
import { EmptyState, PageHeader, SectionHeader } from '@/components/page';
import { Card } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { InvitationActions, InviteDialog } from '../client';

export const metadata = { title: 'Team invitations' };

export default async function InvitationsPage() {
  const ctx = await requireOrg();
  const invites = await listInvitations(ctx.org.id);
  const isOwner = ctx.role === 'owner';
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Team Invitation' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Team Invitations" description="Invitations that have been sent but not accepted yet" actions={isOwner && <InviteDialog />} />
        <Card className="py-0">
          {invites.length === 0 ? (
            <EmptyState icon={MailPlus} title="No pending invitations">
              Invite teammates from here or from Team Members. Pending invitations are listed until they are accepted, cancelled or expire.
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Email</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Invited At</TableHead>
                  <TableHead>Expires At</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {invites.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="font-medium">{i.email}</TableCell>
                    <TableCell>{titleCase(i.role)}</TableCell>
                    <TableCell>{fmtDate(i.createdAt)}</TableCell>
                    <TableCell>{fmtDate(i.expiresAt)}</TableCell>
                    <TableCell className={i.status === 'expired' ? 'text-muted-foreground' : 'text-primary'}>{titleCase(i.status)}</TableCell>
                    <TableCell>{isOwner && <InvitationActions inv={i} />}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}
