'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Activity,
  ArrowLeft,
  BookOpen,
  Bug,
  Bell,
  Building2,
  Check,
  ChevronsUpDown,
  CreditCard,
  DatabaseZap,
  FileChartLine,
  FileCode2,
  FileSearch,
  FileSliders,
  FolderGit2,
  Gem,
  GitPullRequest,
  Hexagon,
  KeyRound,
  LayoutDashboard,
  LifeBuoy,
  LogOut,
  Monitor,
  Plug,
  ScanLine,
  Settings,
  ShieldBan,
  ShieldCheck,
  ShieldHalf,
  SlidersHorizontal,
  User,
  UserPlus,
  Users,
  Video,
  FileKey2,
  ListOrdered,
  ScrollText,
  Wand2,
  Webhook,
} from 'lucide-react';
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
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
      { href: '/fix-queue', label: 'Fix First', icon: ListOrdered },
      { href: '/secrets', label: 'Secrets', icon: FileKey2 },
      { href: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
      { href: '/policy/violations', label: 'Policy Violations', icon: FileChartLine },
      { href: '/endpoints', label: 'Endpoints', icon: Monitor },
    ],
  },
  {
    label: 'Configure',
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
      { href: '/settings/auto-fix', label: 'Auto-fix', icon: Wand2 },
      { href: '/settings/notifications', label: 'Notifications', icon: Bell },
      { href: '/settings/audit-log', label: 'Audit Log', icon: ScrollText },
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
  /** Live counts shown next to nav items (href -> count). */
  badges?: Record<string, number>;
};

export function AppSidebar({ mode, ctx }: { mode: 'app' | 'settings' | 'admin'; ctx: SidebarCtx }) {
  const pathname = usePathname();
  const groups = mode === 'settings' ? SETTINGS : mode === 'admin' ? ADMIN : APP;
  const isActive = (href: string) =>
    href === '/admin' ? pathname === '/admin' : pathname === href || (pathname.startsWith(`${href}/`) && !(href === '/policy' && pathname.startsWith('/policy/violations')));

  return (
    <Sidebar variant="inset" collapsible="icon">
      <SidebarHeader className="gap-3">
        <Link href="/dashboard" className="flex items-center gap-2 px-2 pt-1 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:px-0" aria-label="depguard home">
          <Logo className="size-6 shrink-0" />
          <span className="text-base font-semibold tracking-tight group-data-[collapsible=icon]:hidden">depguard</span>
        </Link>
        {mode === 'app' ? (
          <TenantSwitcher ctx={ctx} />
        ) : (
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton asChild tooltip="Back to app" className="text-muted-foreground">
                <Link href="/dashboard">
                  <ArrowLeft /> <span>Back to app</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        )}
      </SidebarHeader>
      <SidebarContent className="gap-0">
        {groups.map((g, i) => (
          <SidebarGroup key={i} className="py-1.5">
            {g.label && <SidebarGroupLabel className="text-[11px] font-semibold tracking-wider uppercase">{g.label}</SidebarGroupLabel>}
            <SidebarMenu className="gap-0.5">
              {g.items.map((it) => {
                const active = isActive(it.href);
                return (
                  <SidebarMenuItem key={it.href}>
                    <SidebarMenuButton
                      asChild
                      isActive={active}
                      tooltip={it.label}
                      className={cn(
                        'h-9 rounded-lg text-sidebar-foreground/75 transition-all hover:bg-sidebar-accent hover:text-sidebar-foreground',
                        active &&
                          'bg-primary font-medium text-primary-foreground shadow-sm shadow-primary/20 hover:bg-primary/90 hover:text-primary-foreground data-[active=true]:bg-primary data-[active=true]:text-primary-foreground',
                      )}
                    >
                      <Link href={it.href} aria-current={active ? 'page' : undefined}>
                        <it.icon className="size-4" />
                        <span>{it.label}</span>
                      </Link>
                    </SidebarMenuButton>
                    {!!ctx.badges?.[it.href] && (
                      <SidebarMenuBadge
                        className={cn(
                          'rounded-full bg-red-500 px-1.5 text-[10px] font-semibold text-white peer-hover/menu-button:text-white',
                          active && 'bg-primary-foreground text-primary peer-hover/menu-button:text-primary',
                        )}
                        aria-label={`${ctx.badges[it.href]} need attention`}
                      >
                        {ctx.badges[it.href]}
                      </SidebarMenuBadge>
                    )}
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroup>
        ))}
      </SidebarContent>
      {mode === 'app' && (
        <SidebarFooter className="gap-2">
          <div className="flex items-center rounded-lg border bg-background/50 p-0.5 group-data-[collapsible=icon]:hidden">
            <FooterLink href={ctx.links.docs} label="Documentation" icon={BookOpen} />
            <FooterLink href={ctx.links.github} label="GitHub" icon={GitHubIcon} />
            {ctx.links.video && <FooterLink href={ctx.links.video} label="Video walkthroughs" icon={Video} />}
            <FooterLink href={ctx.links.support} label="Support" icon={LifeBuoy} />
            <ThemeSwitcher compact />
          </div>
          <SidebarMenu className="hidden group-data-[collapsible=icon]:flex">
            <SidebarMenuItem>
              <ThemeSwitcher />
            </SidebarMenuItem>
          </SidebarMenu>
          <Link
            href="/settings/billing"
            className="group/plan flex items-center gap-2.5 rounded-xl border border-primary/30 bg-gradient-to-br from-primary/20 via-primary/5 to-transparent p-2.5 transition-colors hover:border-primary/60 group-data-[collapsible=icon]:hidden"
          >
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <Gem className="size-4" />
            </span>
            <span className="min-w-0 flex-1 leading-tight">
              <span className="block text-sm font-semibold">Free plan</span>
              <span className="block truncate text-xs text-muted-foreground">Current plan</span>
            </span>
            <span className="shrink-0 text-xs font-medium whitespace-nowrap text-primary">
              Upgrade <span className="inline-block transition-transform group-hover/plan:translate-x-0.5">→</span>
            </span>
          </Link>
          <UserCard ctx={ctx} />
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
      className="flex flex-1 justify-center rounded-md p-2 text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-foreground"
    >
      <Icon className="size-4" />
    </a>
  );
}

const initials = (name: string) =>
  name
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join('') || '?';

function TenantSwitcher({ ctx }: { ctx: SidebarCtx }) {
  const router = useRouter();
  const { isMobile } = useSidebar();
  const org = ctx.org;
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" tooltip={org?.name ?? 'Organization'} className="border bg-background shadow-xs data-[state=open]:bg-sidebar-accent group-data-[collapsible=icon]:border-0">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-md bg-primary/15 text-sm font-semibold text-primary">
                {org?.name.charAt(0).toUpperCase() ?? <Logo className="size-5" />}
              </span>
              <span className="grid min-w-0 flex-1 leading-tight">
                <span className="truncate text-sm font-semibold">{org?.name ?? 'depguard'}</span>
                <span className="truncate text-xs text-muted-foreground">{org?.domain}</span>
              </span>
              <ChevronsUpDown className="ml-auto size-4 shrink-0 text-muted-foreground" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" side={isMobile ? 'bottom' : 'right'} className="w-64">
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
                <span className="flex size-6 shrink-0 items-center justify-center rounded border text-xs font-semibold">{o.name.charAt(0).toUpperCase()}</span>
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
      </SidebarMenuItem>
    </SidebarMenu>
  );
}

function UserCard({ ctx }: { ctx: SidebarCtx }) {
  const router = useRouter();
  const { isMobile } = useSidebar();
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" tooltip={ctx.user.name} className="data-[state=open]:bg-sidebar-accent">
              <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/15 text-xs font-semibold text-primary">{initials(ctx.user.name)}</span>
              <span className="grid min-w-0 flex-1 leading-tight">
                <span className="truncate text-sm font-medium">{ctx.user.name}</span>
                <span className="truncate text-xs text-muted-foreground">{ctx.user.email}</span>
              </span>
              <ChevronsUpDown className="ml-auto size-4 shrink-0 text-muted-foreground" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent side={isMobile ? 'bottom' : 'right'} align="end" className="w-60">
            <DropdownMenuLabel className="font-normal">
              <div className="truncate text-sm font-medium">{ctx.user.name}</div>
              <div className="truncate text-xs text-muted-foreground">{ctx.user.email}</div>
              <div className="mt-1.5 flex gap-1">
                {ctx.role && <RoleBadge role={ctx.role} />}
                {ctx.sa && (
                  <span className="inline-flex items-center gap-1 rounded-md bg-accent px-1.5 py-0.5 text-xs font-medium text-accent-foreground">
                    <ShieldHalf className="size-3" /> Super-admin
                  </span>
                )}
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
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
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
