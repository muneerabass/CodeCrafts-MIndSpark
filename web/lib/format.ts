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
export const titleCase = (s: string) => s.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

export const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'Packagist', 'NuGet', 'GitHubActions'].map((v) => ({ value: v, label: v }));
