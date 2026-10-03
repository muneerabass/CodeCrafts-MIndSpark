import 'server-only';
import type { SidebarCtx } from '@/components/app-sidebar';
import { tenantDomain, type Ctx } from './session';

export function sidebarCtx(ctx: Ctx): SidebarCtx {
  const org = (o: { id: string; name: string; slug: string }) => ({ id: o.id, name: o.name, domain: tenantDomain(o.slug) });
  return {
    user: { name: ctx.user.name, email: ctx.user.email },
    role: ctx.role,
    sa: ctx.sa,
    org: ctx.org && org(ctx.org),
    orgs: ctx.orgs.map(org),
    links: {
      docs: process.env.DOCS_URL ?? '/setup/integrations',
      github: process.env.GITHUB_REPO_URL ?? 'https://github.com/depguard/depguard',
      video: process.env.VIDEO_URL || undefined,
      support: process.env.SUPPORT_URL ?? 'https://github.com/depguard/depguard/issues',
    },
  };
}
