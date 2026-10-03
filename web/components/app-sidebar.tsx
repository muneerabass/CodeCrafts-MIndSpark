'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { Activity, ArrowLeft, BookOpen, Bug, Building2, Check, ChevronDown, ChevronsUpDown, CreditCard, DatabaseZap, FileChartLine, FileCode2, FileSearch, FileSliders, FolderGit2, Gem, GitPullRequest, Hexagon, KeyRound, LayoutDashboard, LifeBuoy, LogOut, Monitor, Plug, ScanLine, Settings, ShieldBan, ShieldCheck, ShieldHalf, SlidersHorizontal, User, UserPlus, Users, Video, Webhook } from 'lucide-react';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarSeparator,
} from '@/components/ui/sidebar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { GitHubIcon, Logo } from '@/components/icons';
import { RoleBadge } from '@/components/badges';
import { createClient } from '@/lib/supabase/client';
import { switchOrg } from '@/lib/actions';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { ThemeSwitcher } from '@/components/theme-switcher';

type Item = { href: string; label: string; icon: React.ComponentType<{ className?: string }> };
type Group = { label?: string; items: Item[] };

const APP: Group[] = [
  { items: [{ href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard }] },
  {
    label: 'Inventory',
    items: [
      { href: '/projects', label: 'Projects', icon: FolderGit2 },
      { href: '/components', label: 'Components', icon: Hexagon },
      { href: '/query', label: 'Query', icon: FileCode2 },
      { href: '/scans', label: 'Scans', icon: ScanLine },
      { href: '/pull-requests', label: 'Pull Requests', icon: GitPullRequest },
    ],
  },
  {
    label: 'Threat & Compliance',
    items: [
      { href: '/package-analysis', label: 'Package Analysis', icon: FileSearch },
      { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
      { href: '/policy/violations', label: 'Policy Violations', icon: FileChartLine },
      { href: '/endpoints', label: 'Endpoints', icon: Monitor },
    ],
  },
  {
    items: [
      { href: '/settings/general', label: 'Settings', icon: Settings },
      { href: '/setup/integrations', label: 'Setup', icon: Plug },
    ],
  },
];

const SETTINGS: Group[] = [
  {
    label: 'Tenant',
    items: [
      { href: '/settings/general', label: 'General', icon: Building2 },
      { href: '/settings/api-keys', label: 'API Keys', icon: KeyRound },
      { href: '/settings/package-exclusions', label: 'Malicious Package Exclusion', icon: ShieldBan },
      { href: '/policy', label: 'Policy', icon: FileSliders },
      { href: '/settings/teams', label: 'Team Members', icon: Users },
      { href: '/settings/invitations', label: 'Team Invitation', icon: UserPlus },
      { href: '/settings/billing', label: 'Billing', icon: CreditCard },
      { href: '/settings/preferences', label: 'Preferences', icon: SlidersHorizontal },
      { href: '/settings/pull-requests', label: 'Pull Requests', icon: GitPullRequest },
    ],
  },
  { label: 'Personal', items: [{ href: '/settings/profile', label: 'Your Profile', icon: User }] },
];

const ADMIN: Group[] = [
  {
    label: 'Platform admin',
    items: [
      { href: '/admin', label: 'Tenants', icon: Building2 },
      { href: '/admin/installations', label: 'GitHub installations', icon: Webhook },
      { href: '/admin/health', label: 'Ops health', icon: Activity },
      { href: '/admin/river', label: 'Job queue (River)', icon: DatabaseZap },
    ],
  },
];

export type SidebarCtx = {
  user: { name: string; email: string };
  role: string | null;
  sa: boolean;
  org: { id: string; name: string; domain: string } | null;
  orgs: { id: string; name: string; domain: string }[];
  links: { docs: string; github: string; video?: string; support: string };
};

export function AppSidebar({ mode, ctx }: { mode: 'app' | 'settings' | 'admin'; ctx: SidebarCtx }) {
  const pathname = usePathname();
  const groups = mode === 'settings' ? SETTINGS : mode === 'admin' ? ADMIN : APP;
  const isActive = (href: string) =>
    href === '/admin' ? pathname === '/admin' : pathname === href || (pathname.startsWith(`${href}/`) && !(href === '/policy' && pathname.startsWith('/policy/violations')));

  return (
    <Sidebar variant="inset" collapsible="offcanvas">
      <SidebarHeader>
        {mode === 'app' ? (
          <TenantSwitcher ctx={ctx} />
        ) : (
          <Link href="/dashboard" className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="size-4" /> Back to app
          </Link>
        )}
      </SidebarHeader>
      <SidebarContent>
        {groups.map((g, i) => (
          <div key={i}>
            {i > 0 && mode === 'app' && <SidebarSeparator />}
            <SidebarGroup>
              {g.label && <SidebarGroupLabel>{g.label}</SidebarGroupLabel>}
              <SidebarMenu>
                {g.items.map((it) => {
                  const active = isActive(it.href);
                  return (
                    <SidebarMenuItem key={it.href}>
                      <SidebarMenuButton
                        asChild
                        isActive={active}
                        className={cn('h-9', active && 'border-l-2 border-primary bg-sidebar-accent font-medium text-primary shadow-xs')}
                      >
                        <Link href={it.href} aria-current={active ? 'page' : undefined}>
                          <it.icon className="size-4" />
                          <span>{it.label}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroup>
          </div>
        ))}
      </SidebarContent>
      {mode === 'app' && (
        <SidebarFooter>
          <div className="flex justify-around py-1">
            <FooterLink href={ctx.links.docs} label="Documentation" icon={BookOpen} />
            <FooterLink href={ctx.links.github} label="GitHub" icon={GitHubIcon} />
            {ctx.links.video && <FooterLink href={ctx.links.video} label="Video walkthroughs" icon={Video} />}
            <FooterLink href={ctx.links.support} label="Support" icon={LifeBuoy} />
          </div>
          <SidebarMenu>
            <SidebarMenuItem>
              <ThemeSwitcher />
            </SidebarMenuItem>
          </SidebarMenu>
          <UserCard ctx={ctx} />
          <Link href="/settings/billing" className="flex items-center gap-2 rounded-lg border bg-background px-3 py-2 text-sm font-medium text-primary">
            <Gem className="size-4" /> Free plan
          </Link>
        </SidebarFooter>
      )}
    </Sidebar>
  );
}

function FooterLink({ href, label, icon: Icon }: { href: string; label: string; icon: React.ComponentType<{ className?: string }> }) {
  const external = href.startsWith('http') || href.startsWith('mailto:');
  return (
    <a
      href={href}
      {...(external && { target: '_blank', rel: 'noreferrer' })}
      aria-label={label}
      title={label}
      className="rounded-md p-2 text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
    >
      <Icon className="size-4" />
    </a>
  );
}

function TenantSwitcher({ ctx }: { ctx: SidebarCtx }) {
  const router = useRouter();
  const org = ctx.org;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex w-full items-center gap-2 rounded-lg border bg-background p-2 text-left shadow-xs outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-accent text-sm font-semibold text-primary">
          {org?.name.charAt(0).toUpperCase() ?? <Logo className="size-5" />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold text-primary">{org?.name ?? 'depguard'}</span>
          <span className="block truncate text-xs text-muted-foreground">{org?.domain}</span>
        </span>
        <ChevronsUpDown className="size-4 shrink-0 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel className="text-xs text-muted-foreground">Organizations</DropdownMenuLabel>
        {ctx.orgs.map((o) => (
          <DropdownMenuItem
            key={o.id}
            onSelect={async () => {
              if (o.id === org?.id) return;
              const r = await switchOrg(o.id);
              if (r.ok) router.refresh();
              else toast.error(r.error);
            }}
          >
            <span className="min-w-0 flex-1">
              <span className="block truncate">{o.name}</span>
              <span className="block truncate text-xs text-muted-foreground">{o.domain}</span>
            </span>
            {o.id === org?.id && <Check className="size-4" />}
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link href="/settings/general">
            <Settings /> Tenant settings
          </Link>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function UserCard({ ctx }: { ctx: SidebarCtx }) {
  const router = useRouter();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="w-full rounded-lg border bg-background p-2.5 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring">
        <span className="flex items-center justify-between gap-2">
          <span className="truncate text-sm font-medium text-primary">{ctx.user.name}</span>
          <ChevronDown className="size-4 shrink-0 text-muted-foreground" />
        </span>
        <span className="block truncate text-xs text-muted-foreground">{ctx.user.email}</span>
        <span className="mt-1.5 flex gap-1">
          {ctx.role && <RoleBadge role={ctx.role} />}
          {ctx.sa && (
            <span className="inline-flex items-center gap-1 rounded-md bg-accent px-1.5 py-0.5 text-xs font-medium text-accent-foreground">
              <ShieldHalf className="size-3" /> Super-admin
            </span>
          )}
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="start" className="w-56">
        <DropdownMenuItem asChild>
          <Link href="/settings/profile">
            <User /> Your profile
          </Link>
        </DropdownMenuItem>
        {ctx.sa && (
          <DropdownMenuItem asChild>
            <Link href="/admin">
              <ShieldCheck /> Platform admin
            </Link>
          </DropdownMenuItem>
        )}
        <DropdownMenuItem asChild>
          <Link href="/attributions">
            <BookOpen /> Data attributions
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={async () => {
            const supabase = createClient();
            await supabase.auth.signOut();
            router.push('/sign-in');
          }}
        >
          <LogOut /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
