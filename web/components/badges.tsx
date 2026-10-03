import { Bug, Check, CircleAlert, FileChartLine, Flame, Info, ShieldAlert, Skull, TriangleAlert, BadgeCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { titleCase } from '@/lib/format';
import type { Risk } from '@/lib/types';

const pill = 'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap [&>svg]:size-3.5';

const risks: Record<string, { label: string; cls: string; Icon: typeof Flame }> = {
  CRITICAL: { label: 'Critical', cls: 'bg-red-100 text-red-800 ring-1 ring-red-300 dark:bg-red-950 dark:text-red-200', Icon: Flame },
  HIGH: { label: 'High', cls: 'bg-orange-50 text-orange-700 dark:bg-orange-950 dark:text-orange-200', Icon: TriangleAlert },
  MEDIUM: { label: 'Medium', cls: 'bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-200', Icon: CircleAlert },
  LOW: { label: 'Low', cls: 'bg-sky-50 text-sky-700 dark:bg-sky-950 dark:text-sky-200', Icon: Info },
};

export function RiskBadge({ risk }: { risk: Risk | string }) {
  const r = risks[risk?.toUpperCase()] ?? { label: titleCase(risk || 'Unknown'), cls: 'bg-muted text-muted-foreground', Icon: Info };
  return (
    <span className={cn(pill, r.cls)}>
      <r.Icon aria-hidden />
      {r.label}
    </span>
  );
}

export function ViolationCount({ n }: { n: number }) {
  return (
    <span className={cn(pill, n ? 'bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-200' : 'bg-muted text-muted-foreground')} title="Policy violations">
      <FileChartLine aria-hidden />
      {n}
    </span>
  );
}

export function VulnCount({ n }: { n: number }) {
  return (
    <span className={cn(pill, n ? 'bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-200' : 'bg-muted text-muted-foreground')} title="Vulnerabilities">
      <Bug aria-hidden />
      {n}
    </span>
  );
}

/** Grey monospace chip for versions, branches and triggers. */
export function Chip({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn('inline-flex rounded-md bg-muted px-1.5 py-0.5 text-xs text-foreground/80', className)}>{children}</span>;
}

export function ScanStatus({ status }: { status: string }) {
  const cls =
    status === 'success' || status === 'completed'
      ? 'text-emerald-600'
      : status === 'failed' || status === 'error'
        ? 'text-red-600'
        : status === 'running' || status === 'queued' || status === 'pending'
          ? 'text-primary'
          : 'text-muted-foreground';
  return <span className={cn('text-sm font-medium', cls)}>{titleCase(status)}</span>;
}

export const triggerLabel = (t: string) => ({ pull_request: 'Pull request', push: 'Push', manual: 'Manual', cli: 'CLI', ci: 'CI' })[t] ?? titleCase(t);

export function AnalysisStatus({ status }: { status: string }) {
  if (status === 'malicious')
    return (
      <span className={cn(pill, 'bg-red-50 text-red-700 ring-1 ring-red-200')}>
        <Skull aria-hidden /> Malicious
      </span>
    );
  if (status === 'suspicious')
    return (
      <span className={cn(pill, 'bg-amber-50 text-amber-700 ring-1 ring-amber-200')}>
        <ShieldAlert aria-hidden /> Suspicious
      </span>
    );
  return (
    <span className={cn(pill, 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200')}>
      <Check aria-hidden /> Clean
    </span>
  );
}

export function Verification({ verified }: { verified: boolean }) {
  return verified ? (
    <span className={cn(pill, 'bg-accent text-accent-foreground ring-1 ring-primary/20')}>
      <BadgeCheck aria-hidden /> Verified
    </span>
  ) : (
    <span className={cn(pill, 'ring-1 ring-border')}>Unverified</span>
  );
}

export function RoleBadge({ role }: { role: string }) {
  return <span className="inline-flex rounded-md border bg-background px-1.5 py-0.5 text-xs font-medium">{titleCase(role)}</span>;
}

/** Direct / Transitive · depth n / Unknown (no dependency graph for this manifest). */
export function DependencyBadge({ direct, depth, dev }: { direct: boolean | null; depth: number | null; dev?: boolean | null }) {
  const label = direct === null ? 'Unknown' : direct ? 'Direct' : `Transitive · depth ${depth ?? '?'}`;
  return (
    <span className={cn(pill, direct === null ? 'text-muted-foreground ring-1 ring-border' : direct ? 'bg-accent text-accent-foreground' : 'bg-muted text-foreground/80')}>
      {label}
      {dev && <span className="text-muted-foreground">· dev</span>}
    </span>
  );
}
