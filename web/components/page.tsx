import Link from 'next/link';
import { ArrowRight, ChevronRight, Info, Package } from 'lucide-react';
import { SidebarTrigger } from '@/components/ui/sidebar';
import { Separator } from '@/components/ui/separator';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export type Crumb = { label: string; href?: string };

/** Top bar: sidebar toggle, breadcrumb, page info tooltip, and right-hand actions. */
export function PageHeader({ crumbs, info, actions }: { crumbs: Crumb[]; info?: string; actions?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur print:hidden">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-5" />
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((c, i) => (
          <span key={i} className="flex min-w-0 items-center gap-1.5">
            {i > 0 && <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />}
            {c.href ? (
              <Link href={c.href} className="truncate text-muted-foreground hover:text-foreground">
                {c.label}
              </Link>
            ) : (
              <span className="truncate font-medium" aria-current={i === crumbs.length - 1 ? 'page' : undefined}>
                {c.label}
              </span>
            )}
          </span>
        ))}
        {info && (
          <Tooltip>
            <TooltipTrigger asChild>
              <button type="button" aria-label="About this page" className="rounded-full p-1 text-muted-foreground hover:bg-muted hover:text-foreground">
                <Info className="size-4" />
              </button>
            </TooltipTrigger>
            <TooltipContent className="max-w-xs">{info}</TooltipContent>
          </Tooltip>
        )}
      </nav>
      <div className="ml-auto flex items-center gap-2">
        {actions === undefined ? (
          <Button asChild variant="outline" size="sm" className="border-primary/30 text-primary hover:text-primary">
            <Link href="/setup/integrations">
              <Package /> <span className="hidden sm:inline">Set up more integrations</span> <ArrowRight />
            </Link>
          </Button>
        ) : (
          actions
        )}
      </div>
    </header>
  );
}

/** Icon + title + explanation + CTA. No illustrations. */
export function EmptyState({ icon: Icon, title, children, className }: { icon: React.ComponentType<{ className?: string }>; title: string; children?: React.ReactNode; className?: string }) {
  return (
    <div className={cn('mx-auto flex max-w-xl flex-col items-center px-4 py-16 text-center', className)}>
      <div className="mb-4 flex size-14 items-center justify-center rounded-xl border bg-accent text-primary">
        <Icon className="size-6" />
      </div>
      <h2 className="text-lg font-semibold">{title}</h2>
      <div className="mt-2 text-sm text-muted-foreground">{children}</div>
    </div>
  );
}

/** Centered settings-style page section with title, subtitle and actions. */
export function SectionHeader({ title, description, actions }: { title: string; description?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold">{title}</h1>
        {description && <p className="text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

/** Page title with a one-line description and optional actions (under the breadcrumb header). */
export function PageIntro({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4 px-4 pt-6 pb-2 md:px-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      {children}
    </div>
  );
}

const tileTone = {
  primary: 'text-primary bg-primary/10 ring-primary/25',
  red: 'text-red-600 dark:text-red-400 bg-red-500/10 ring-red-500/25',
  amber: 'text-amber-600 dark:text-amber-400 bg-amber-500/10 ring-amber-500/25',
  sky: 'text-sky-600 dark:text-sky-400 bg-sky-500/10 ring-sky-500/25',
  orange: 'text-orange-600 dark:text-orange-400 bg-orange-500/10 ring-orange-500/25',
};
export type StatTile = { label: string; value: number; icon: React.ComponentType<{ className?: string }>; href: string; active?: boolean; tone: keyof typeof tileTone; share?: number };

/** Clickable summary numbers that double as filters. */
export function StatTiles({ label, tiles }: { label: string; tiles: StatTile[] }) {
  return (
    <nav aria-label={label} className={cn('grid grid-cols-2 gap-2 border-b px-4 pt-2 pb-4 sm:gap-3 md:px-6', tiles.length === 4 ? 'lg:grid-cols-4' : 'sm:grid-cols-3')}>
      {tiles.map((t) => (
        <Link
          key={t.label}
          href={t.href}
          aria-current={t.active ? 'true' : undefined}
          className={cn('flex items-center gap-3 rounded-xl border bg-card p-2.5 transition-colors hover:border-primary/40 sm:p-3', t.active && 'border-primary/50 bg-primary/5')}
        >
          <span className={cn('hidden size-10 shrink-0 items-center justify-center rounded-lg ring-1 sm:flex', tileTone[t.tone])}>
            <t.icon className="size-5" aria-hidden />
          </span>
          <span>
            <span className="block text-2xl leading-none font-semibold tabular-nums">{t.value.toLocaleString('en-GB')}</span>
            <span className="mt-1 block text-xs text-muted-foreground">{t.label}</span>
          </span>
          {t.share !== undefined && <span className="ml-auto hidden text-xs text-muted-foreground tabular-nums md:inline">{Math.round(t.share * 100)}%</span>}
        </Link>
      ))}
    </nav>
  );
}
