import { Check, Gem } from 'lucide-react';
import { PageHeader, SectionHeader } from '@/components/page';
import { Card, CardContent } from '@/components/ui/card';

export const metadata = { title: 'Billing' };

const included = ['Unlimited projects, scans and team members', 'GitHub App pull request checks and comments', 'Package Analysis, vulnerabilities and policy engine', 'CLI, CI, endpoint agent and MCP integrations'];

export default function BillingPage() {
  return (
    <>
      <PageHeader crumbs={[{ label: 'Settings', href: '/settings/general' }, { label: 'Billing' }]} actions={null} />
      <div className="mx-auto w-full max-w-4xl p-6">
        <SectionHeader title="Billing" description="Your plan for this tenant" />
        <Card>
          <CardContent className="grid gap-4">
            <div className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-lg bg-accent text-primary">
                <Gem className="size-5" />
              </span>
              <div>
                <p className="font-semibold">Free plan</p>
                <p className="text-sm text-muted-foreground">This is a self-hosted depguard instance — there is nothing to pay and no payment method to manage.</p>
              </div>
            </div>
            <ul className="grid gap-2 text-sm">
              {included.map((i) => (
                <li key={i} className="flex items-center gap-2">
                  <Check className="size-4 text-primary" /> {i}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
