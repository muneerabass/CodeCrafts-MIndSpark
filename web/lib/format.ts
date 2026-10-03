import type { UsageModel } from './types';

// Dates render as DD/MM/YYYY (en-GB) in UTC so server and client output match.
const d = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', timeZone: 'UTC' });
const dt = new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' });

const parse = (v: string | null | undefined) => (v ? new Date(v) : null);
export const fmtDate = (v: string | null | undefined) => {
  const x = parse(v);
  return x && !isNaN(+x) ? d.format(x) : '—';
};
export const fmtDateTime = (v: string | null | undefined) => {
  const x = parse(v);
  return x && !isNaN(+x) ? `${dt.format(x)} UTC` : '—';
};
/** "3h ago", "2d ago", or the date for older items. */
export function ago(v: string | null | undefined) {
  if (!v) return '';
  const m = Math.round((Date.now() - new Date(v).getTime()) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  if (m < 60 * 24) return `${Math.round(m / 60)}h ago`;
  if (m < 60 * 24 * 30) return `${Math.round(m / 1440)}d ago`;
  return fmtDate(v);
}

export const titleCase = (s: string) => s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

export const DIRECT_OPTIONS = [
  { value: 'true', label: 'Direct' },
  { value: 'false', label: 'Transitive' },
];

export const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info'].map((v) => ({ value: v, label: titleCase(v) }));

export const USAGE_MODELS: { value: UsageModel; label: string; hint: string }[] = [
  { value: 'internal', label: 'Internal only', hint: 'Used inside your organisation, never shipped to others.' },
  { value: 'saas', label: 'SaaS / network service', hint: 'Users reach it over a network; code is not distributed.' },
  { value: 'distributed_binary', label: 'Distributed binary', hint: 'Shipped to customers as an app, binary or container.' },
  { value: 'distributed_source', label: 'Distributed source', hint: 'Published as source code (e.g. an open-source library).' },
];
export const usageLabel = (u: string) => USAGE_MODELS.find((m) => m.value === u)?.label ?? titleCase(u);

/** Plain-English reason for a suspicious finding, from its rule-specific details. */
export function suspiciousReason(rule: string, d: Record<string, unknown> = {}, fallback = ''): string {
  const s = (k: string) => (d[k] == null || d[k] === '' ? '' : String(d[k]));
  switch (rule) {
    case 'typosquat':
      return s('similar_to') ? `Name looks like the popular package ${s('similar_to')}${s('technique') ? ` (${s('technique')})` : ''}` : fallback;
    case 'deprecated':
      return (s('reason') || 'Deprecated by its maintainers') + (s('default_version') ? ` (latest: ${s('default_version')})` : '');
    case 'unmaintained':
      return (
        [s('latest_published') && `Last release ${fmtDate(s('latest_published'))}`, s('maintained_score') && `Scorecard Maintained ${s('maintained_score')}/10`].filter(Boolean).join('; ') || fallback
      );
    case 'new-package':
      return s('age_days') ? `Version published ${s('age_days')} days ago` : s('published_at') ? `Version published ${fmtDate(s('published_at'))}` : fallback;
    case 'unusual-behaviour':
      return Array.isArray(d.rules) && d.rules.length ? `Heuristic analysis flagged: ${d.rules.join(', ')}${s('risk_score') ? ` (risk ${s('risk_score')})` : ''}` : fallback;
    case 'no-source-repo':
      return 'No linked source repository to review';
  }
  return s('reason') || s('explanation') || fallback;
}

export const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'Packagist', 'NuGet', 'GitHubActions'].map((v) => ({ value: v, label: v }));

/** Whole days from now until an ISO date (negative when past). */
export function daysUntil(v: string) {
  return Math.round((Date.parse(v) - Date.now()) / 86_400_000);
}
