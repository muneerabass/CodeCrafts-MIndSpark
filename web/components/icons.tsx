import { useId, type SVGProps } from 'react';
import { cn } from '@/lib/utils';

type P = SVGProps<SVGSVGElement>;

/** depguard mark: a shield holding a small dependency graph. */
export function Logo({ className, ...p }: P) {
  // Unique per instance: a shared id breaks the fill when the first copy is display:none.
  const gid = `dg-g-${useId().replace(/:/g, '')}`;
  return (
    <svg viewBox="0 0 32 32" fill="none" aria-hidden className={cn('size-6', className)} {...p}>
      <defs>
        <linearGradient id={gid} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop style={{ stopColor: 'var(--logo-a, #818cf8)' }} />
          <stop offset="1" style={{ stopColor: 'var(--logo-b, #6d28d9)' }} />
        </linearGradient>
      </defs>
      <path d="M16 2.5 27 6.6v8.2c0 6.9-4.6 12.2-11 14.7C9.6 27 5 21.7 5 14.8V6.6L16 2.5Z" fill={`url(#${gid})`} />
      <path d="M11 11.5 16 19l5-7.5M16 19v-7.5" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="11" cy="11.5" r="2" fill="#fff" />
      <circle cx="21" cy="11.5" r="2" fill="#fff" />
      <circle cx="16" cy="11.5" r="1.6" fill="#fff" />
      <circle cx="16" cy="20" r="2.4" fill="#fff" />
    </svg>
  );
}

export function GitHubIcon(p: P) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden width="1em" height="1em" {...p}>
      <path d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.26 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z" />
    </svg>
  );
}

export function GitLabIcon(p: P) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden width="1em" height="1em" {...p}>
      <path d="m23.6 9.6-.03-.09-3.26-8.5a.85.85 0 0 0-1.62.06l-2.2 6.74H7.5L5.3 1.07a.85.85 0 0 0-1.62-.06L.43 9.5l-.03.09a6.05 6.05 0 0 0 2 7l.01.01.03.02 4.97 3.72 2.46 1.86 1.5 1.13a1 1 0 0 0 1.22 0l1.5-1.13 2.46-1.86 5-3.74a6.06 6.06 0 0 0 2.05-7Z" />
    </svg>
  );
}

export function BitbucketIcon(p: P) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden width="1em" height="1em" {...p}>
      <path d="M.78 1.2a.77.77 0 0 0-.77.9l3.26 19.73c.08.5.51.86 1.01.87h15.66a.77.77 0 0 0 .77-.65l3.27-19.95a.77.77 0 0 0-.77-.9H.78Zm13.75 14.26H9.53l-1.36-7.1h7.58l-1.22 7.1Z" />
    </svg>
  );
}

export function GoogleIcon(p: P) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden width="1em" height="1em" {...p}>
      <path fill="#4285F4" d="M23.5 12.27c0-.85-.08-1.67-.22-2.45H12v4.64h6.45a5.5 5.5 0 0 1-2.4 3.61v3h3.88c2.27-2.09 3.57-5.17 3.57-8.8Z" />
      <path fill="#34A853" d="M12 24c3.24 0 5.96-1.07 7.95-2.9l-3.88-3.02c-1.08.72-2.45 1.15-4.07 1.15-3.13 0-5.78-2.11-6.73-4.95H1.27v3.11A12 12 0 0 0 12 24Z" />
      <path fill="#FBBC05" d="M5.27 14.28a7.2 7.2 0 0 1 0-4.56V6.61h-4a12 12 0 0 0 0 10.78l4-3.11Z" />
      <path fill="#EA4335" d="M12 4.77c1.76 0 3.34.61 4.59 1.8l3.44-3.44A11.5 11.5 0 0 0 12 0 12 12 0 0 0 1.27 6.61l4 3.11C6.22 6.88 8.87 4.77 12 4.77Z" />
    </svg>
  );
}

/** Small ecosystem tag; text instead of third-party logos. */
export function Ecosystem({ name }: { name: string }) {
  return (
    <span className="inline-flex rounded border bg-muted/60 px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground" title={name}>
      {name}
    </span>
  );
}

const ecoTile: Record<string, [string, string]> = {
  npm: ['npm', 'bg-red-500/15 text-red-600 dark:text-red-400'],
  PyPI: ['py', 'bg-sky-500/15 text-sky-600 dark:text-sky-400'],
  Go: ['go', 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-400'],
  Maven: ['mvn', 'bg-orange-500/15 text-orange-600 dark:text-orange-400'],
  'crates.io': ['rs', 'bg-amber-500/15 text-amber-700 dark:text-amber-400'],
  RubyGems: ['rb', 'bg-rose-500/15 text-rose-600 dark:text-rose-400'],
  Packagist: ['php', 'bg-indigo-500/15 text-indigo-600 dark:text-indigo-400'],
  NuGet: ['nu', 'bg-violet-500/15 text-violet-600 dark:text-violet-400'],
  GitHubActions: ['gha', 'bg-slate-500/15 text-slate-600 dark:text-slate-300'],
};

/** Small coloured square naming a package ecosystem. */
export function EcosystemTile({ name, className }: { name: string; className?: string }) {
  const [abbr, cls] = ecoTile[name] ?? [name.slice(0, 3).toLowerCase(), 'bg-muted text-muted-foreground'];
  return (
    <span className={cn('flex size-9 shrink-0 items-center justify-center rounded-lg font-mono text-[11px] font-semibold', cls, className)} title={name} aria-hidden>
      {abbr}
    </span>
  );
}

export function SourceIcon({ source, className }: { source: string; className?: string }) {
  const c = cn('size-4', className);
  if (source === 'github') return <GitHubIcon className={c} aria-label="GitHub" />;
  if (source === 'gitlab') return <GitLabIcon className={cn(c, 'text-orange-600')} aria-label="GitLab" />;
  if (source === 'bitbucket') return <BitbucketIcon className={cn(c, 'text-blue-600')} aria-label="Bitbucket" />;
  return <span className="font-mono text-[10px] uppercase text-muted-foreground">{source}</span>;
}
