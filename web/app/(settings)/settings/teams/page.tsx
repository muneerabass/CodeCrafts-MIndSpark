import { requireOrg } from '@/lib/session';
import { listMembers } from '@/lib/org-data';
import { titleCase } from '@/lib/format';
import { PageHeader, SectionHeader } from '@/components/page';
import { Card } from '@/components/ui/card';
import { InviteDialog, MemberMenu } from '../client';

export const metadata = { title: 'Team members' };

export default async function TeamsPage() {
  const ctx = await requireOrg();
  const members = await listMembers(ctx.org.id);
  const isOwner = ctx.role === 'owner';
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Team Members' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Team Members" description="Everyone who can sign in to this tenant, and what they can do" actions={isOwner && <InviteDialog />} />
        <Card className="py-0">
          <ul className="divide-y" aria-label="Team members">
            {members.map((m) => (
              <li key={m.id} className="flex items-center gap-3 px-4 py-3">
                <span className="flex size-9 shrink-0 items-center justify-center rounded-full bg-accent font-medium text-primary" aria-hidden>
                  {m.name.charAt(0).toUpperCase()}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">
                    {m.name} {m.userId === ctx.user.id && <span className="text-xs text-muted-foreground">(you)</span>}
                  </p>
                  <p className="truncate text-sm text-muted-foreground">{m.email}</p>
                </div>
                <span className="text-sm font-medium">{titleCase(m.role)}</span>
                {isOwner && m.userId !== ctx.user.id ? <MemberMenu m={m} /> : <span className="size-9" />}
              </li>
            ))}
          </ul>
        </Card>
        {!isOwner && <p className="mt-3 text-sm text-muted-foreground">Only owners can invite, remove or change the role of members.</p>}
      </div>
    </>
  );
}
