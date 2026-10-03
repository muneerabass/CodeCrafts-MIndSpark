import { requireOrg } from '@/lib/session';
import { PageHeader, SectionHeader } from '@/components/page';
import { RoleBadge } from '@/components/badges';
import { Card, CardContent } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { ProfileForm, SessionButtons } from '../client';

export const metadata = { title: 'Your profile' };

export default async function ProfilePage() {
  const ctx = await requireOrg();
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Your Profile' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Your Profile" description="How you appear to your team, and where you are signed in" />
        <Card>
          <CardContent className="grid gap-6">
            <div className="flex items-center gap-4">
              {ctx.user.image ? (
                // eslint-disable-next-line @next/next/no-img-element -- avatar from the OAuth provider, any host
                <img src={ctx.user.image} alt="" className="size-14 rounded-full" />
              ) : (
                <span className="flex size-14 items-center justify-center rounded-full bg-accent text-xl font-semibold text-primary" aria-hidden>
                  {ctx.user.name.charAt(0).toUpperCase()}
                </span>
              )}
              <div>
                <p className="font-semibold">{ctx.user.name}</p>
                <p className="flex items-center gap-2 text-sm text-muted-foreground">
                  {ctx.org.name} <RoleBadge role={ctx.role} />
                </p>
              </div>
            </div>
            <ProfileForm name={ctx.user.name} />
            <div className="grid gap-2">
              <Label htmlFor="profile-email">Email</Label>
              <Input id="profile-email" value={ctx.user.email} readOnly className="bg-muted text-muted-foreground" />
            </div>
            <div className="grid gap-2 border-t pt-6">
              <p className="font-medium">Sessions</p>
              <p className="text-sm text-muted-foreground">Signed in on a shared or lost device? Sign out everywhere except this browser.</p>
              <SessionButtons />
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
