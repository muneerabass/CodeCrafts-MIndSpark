// MOCK_API=1: in-memory fixtures shaped like docs/CONTRACTS.md so the UI runs without the Go API.
// State lives in module scope (resets on server restart / HMR).
import type * as T from './types';

const day = 86_400_000;
const now = Date.UTC(2026, 9, 1, 12, 0, 0);
const iso = (daysAgo: number) => new Date(now - daysAgo * day).toISOString();

const P1 = { id: '01JB7Q3M1K8Z4XW2N5R6T9V0AA', name: 'acme/storefront' };
const P2 = { id: '01JB7Q3M1K8Z4XW2N5R6T9V0AB', name: 'acme/payments-api' };
const P3 = { id: '01JB7Q3M1K8Z4XW2N5R6T9V0AC', name: 'acme/infra-tools' };

const projects: T.Project[] = [
  { ...P1, source: 'github', url: 'https://github.com/acme/storefront', versions: 2, components: 1204, violations: 3, vulns: 41, created_at: iso(40) },
  { ...P2, source: 'github', url: 'https://github.com/acme/payments-api', versions: 1, components: 312, violations: 1, vulns: 6, created_at: iso(20) },
  { ...P3, source: 'cli', url: '', versions: 1, components: 88, violations: 0, vulns: 0, created_at: iso(3) },
];

const versionsOf: Record<string, T.ProjectVersion[]> = {
  [P1.id]: [
    { id: 'v-main-1', name: 'main', last_scan_at: iso(1), updated_at: iso(1) },
    { id: 'v-rel-1', name: 'release/2.4', last_scan_at: iso(9), updated_at: iso(9) },
  ],
  [P2.id]: [{ id: 'v-main-2', name: 'main', last_scan_at: iso(2), updated_at: iso(2) }],
  [P3.id]: [{ id: 'v-main-3', name: 'main', last_scan_at: iso(3), updated_at: iso(3) }],
};

const npmNames = ['react', 'lodash', 'axios', 'minimist', 'express', 'vite', 'semver', 'debug', 'ws', 'follow-redirects', 'path-to-regexp', 'cookie', 'braces', 'micromatch', 'tar', 'undici', 'jsonwebtoken', 'qs', 'body-parser', 'send', 'esbuild', 'postcss', 'nanoid', 'ip', 'tough-cookie'];
const pyNames = ['requests', 'urllib3', 'jinja2', 'cryptography', 'pyyaml', 'django', 'flask', 'certifi'];

// Realistic versions and graph position (direct, depth, dev) for packages on the storefront attack paths.
const realVersion: Record<string, string> = { express: '4.17.1', 'body-parser': '1.19.0', qs: '6.7.0', 'path-to-regexp': '0.1.7', minimist: '1.2.5', axios: '0.21.1', 'follow-redirects': '1.14.0', react: '18.2.0', lodash: '4.17.21' };
const depOf: Record<string, [boolean | null, number | null, boolean | null]> = {
  express: [true, 1, false], 'body-parser': [false, 2, false], qs: [false, 3, false], 'path-to-regexp': [false, 2, false], minimist: [false, 2, false],
  axios: [true, 1, false], 'follow-redirects': [false, 2, false], react: [true, 1, false], lodash: [true, 1, false], vite: [true, 1, true], esbuild: [false, 2, true],
  lodahs: [true, 1, false], request: [true, 1, false], 'ffmpeg-static': [true, 1, false], mkdirp: [true, 1, false], 'event-stream-lite': [false, 2, false],
};
const dep = (n: string, i: number): T.DepInfo => {
  const d = depOf[n] ?? (i % 3 === 0 ? [true, 1, false] : i % 3 === 1 ? [false, 2 + (i % 2), false] : [null, null, null]);
  return { direct: d[0], depth: d[1], dev: d[2] };
};

const components: T.ComponentRow[] = [
  ...npmNames.map((n, i) => ({ id: `c-npm-${i}`, name: n, version: realVersion[n] ?? `${(i % 7) + 1}.${i % 5}.${i % 3}`, ecosystem: 'npm', type: 'Library', projects: (i % 3) + 1, violations: i % 9 === 0 ? 1 : 0, vulns: i % 4 === 0 ? (i % 3) + 1 : 0, updated_at: iso(i % 10), ...dep(n, i) })),
  ...pyNames.map((n, i) => ({ id: `c-py-${i}`, name: n, version: `${i + 1}.${i}.0`, ecosystem: 'PyPI', type: 'Library', projects: 1, violations: 0, vulns: i % 3 === 0 ? 1 : 0, updated_at: iso(i), ...dep(n, i) })),
  { id: 'c-go-0', name: 'golang.org/x/net', version: '0.17.0', ecosystem: 'Go', type: 'Library', projects: 1, violations: 0, vulns: 2, updated_at: iso(2), direct: false, depth: 2, dev: false },
  { id: 'c-gha-0', name: 'actions/checkout', version: '4.1.1', ecosystem: 'GitHubActions', type: 'Action', projects: 2, violations: 0, vulns: 0, updated_at: iso(1), direct: true, depth: 1, dev: false },
  { id: 'c-npm-lodahs', name: 'lodahs', version: '4.17.21', ecosystem: 'npm', type: 'Library', projects: 1, violations: 1, vulns: 0, updated_at: iso(1), ...dep('lodahs', 0) },
  { id: 'c-npm-request', name: 'request', version: '2.88.2', ecosystem: 'npm', type: 'Library', projects: 2, violations: 2, vulns: 0, updated_at: iso(1), ...dep('request', 0) },
  { id: 'c-npm-ffmpeg', name: 'ffmpeg-static', version: '5.2.0', ecosystem: 'npm', type: 'Library', projects: 1, violations: 2, vulns: 0, updated_at: iso(1), ...dep('ffmpeg-static', 0) },
  { id: 'c-npm-mkdirp', name: 'mkdirp', version: '0.5.5', ecosystem: 'npm', type: 'Library', projects: 1, violations: 0, vulns: 0, updated_at: iso(3), ...dep('mkdirp', 0) },
  { id: 'c-npm-x', name: 'event-stream-lite', version: '1.0.2', ecosystem: 'npm', type: 'Library', projects: 1, violations: 2, vulns: 1, updated_at: iso(1), ...dep('event-stream-lite', 0) },
];
const comp = (name: string) => components.find((c) => c.name === name)!;
const ref = (name: string): T.ComponentRef => {
  const c = comp(name);
  return { id: c.id, name: c.name, version: c.version, ecosystem: c.ecosystem };
};

const vulns: T.VulnerabilityRow[] = [
  { id: 'GHSA-3xgq-45jj-v275', summary: 'Prototype pollution in minimist allows attackers to modify object properties', risk: 'CRITICAL', affected_components: 1, affected_projects: 2, published: iso(300), modified: iso(30), first_seen: iso(12), open: true, due_at: iso(5), overdue: true },
  { id: 'GHSA-wf5p-g6vw-rhxx', summary: 'axios is vulnerable to cross-site request forgery when credentials are sent', risk: 'MEDIUM', affected_components: 1, affected_projects: 1, published: iso(200), modified: iso(25), first_seen: iso(20), open: true, due_at: iso(-70), overdue: false },
  { id: 'GHSA-9wv6-86v2-598j', summary: 'path-to-regexp produces regular expressions prone to catastrophic backtracking', risk: 'HIGH', affected_components: 1, affected_projects: 2, published: iso(120), modified: iso(12), first_seen: iso(10), open: true, due_at: iso(-20), overdue: false },
  { id: 'GHSA-952p-6rrq-rcjv', summary: 'micromatch vulnerable to regular expression denial of service', risk: 'MEDIUM', affected_components: 1, affected_projects: 1, published: iso(150), modified: iso(40), first_seen: iso(20), open: true, due_at: iso(-70), overdue: false },
  { id: 'GHSA-grv7-fg5c-xmjg', summary: 'Uncontrolled resource consumption in braces', risk: 'HIGH', affected_components: 1, affected_projects: 1, published: iso(160), modified: iso(20), first_seen: iso(10), open: true, due_at: iso(-20), overdue: false },
  { id: 'GHSA-jfh8-c2jp-5v3q', summary: 'Denial of service in follow-redirects when handling crafted headers', risk: 'LOW', affected_components: 1, affected_projects: 1, published: iso(90), modified: iso(14), first_seen: iso(5), open: true, due_at: null, overdue: false },
  { id: 'GHSA-9cwx-2883-4wfx', summary: 'urllib3 does not strip the Proxy-Authorization header on cross-origin redirects', risk: 'MEDIUM', affected_components: 1, affected_projects: 1, published: iso(80), modified: iso(10), first_seen: iso(20), open: true, due_at: iso(-70), overdue: false },
  { id: 'GHSA-4v7x-pqxf-cx7m', summary: 'golang.org/x/net HTTP/2 rapid reset can cause excessive work', risk: 'HIGH', affected_components: 1, affected_projects: 1, published: iso(400), modified: iso(60), first_seen: iso(10), open: true, due_at: iso(-20), overdue: false },
  { id: 'MAL-2026-1337', summary: 'Malicious code in event-stream-lite (npm)', risk: 'CRITICAL', affected_components: 1, affected_projects: 1, published: iso(5), modified: iso(5), first_seen: iso(5), open: true, due_at: iso(-2), overdue: false },
  { id: 'GHSA-hrpp-h998-j3pp', summary: 'qs vulnerable to prototype pollution via crafted query strings', risk: 'HIGH', affected_components: 1, affected_projects: 1, published: iso(500), modified: iso(45), first_seen: iso(10), open: true, due_at: iso(-20), overdue: false },
  { id: 'GHSA-8hc4-vh64-cxmj', summary: 'Server-side request forgery in undici when following redirects', risk: 'LOW', affected_components: 1, affected_projects: 1, published: iso(70), modified: iso(7), first_seen: iso(5), open: true, due_at: null, overdue: false },
];

const scans: T.ScanRow[] = [
  { id: 'S01JB8A0000000000000000001', project: P1, version: 'main', trigger: 'pull_request', violations: 2, vulns: 41, status: 'success', created_at: iso(1) },
  { id: 'S01JB8A0000000000000000002', project: P1, version: 'main', trigger: 'push', violations: 3, vulns: 41, status: 'success', created_at: iso(4) },
  { id: 'S01JB8A0000000000000000003', project: P1, version: 'release/2.4', trigger: 'manual', violations: 1, vulns: 38, status: 'success', created_at: iso(9) },
  { id: 'S01JB8A0000000000000000004', project: P2, version: 'main', trigger: 'manual', violations: 1, vulns: 6, status: 'success', created_at: iso(2) },
  { id: 'S01JB8A0000000000000000005', project: P3, version: 'main', trigger: 'cli', violations: 0, vulns: 0, status: 'failed', created_at: iso(3) },
  { id: 'S01JB8A0000000000000000006', project: P2, version: 'main', trigger: 'pull_request', violations: 0, vulns: 0, status: 'running', created_at: iso(0) },
];

const S1 = scans[0].id;
const violations: T.Violation[] = [
  { id: 'pv-1', rule_name: 'critical-or-high-vulns', category: 'vulnerability', severity: 'critical', blocking: true, details: {}, summary: 'Package has a CRITICAL vulnerability (GHSA-3xgq-45jj-v275)', component: ref('minimist'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-2', rule_name: 'malicious-package', category: 'malware', severity: 'critical', blocking: true, details: {}, summary: 'Package is listed as malicious (MAL-2026-1337)', component: ref('event-stream-lite'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-3', rule_name: 'license-denied', category: 'license', severity: 'high', blocking: true, details: { license: 'GPL-3.0-only' }, summary: 'License GPL-3.0-only is on the deny list', component: { id: 'c-py-5', name: 'flask', version: '6.5.0', ecosystem: 'PyPI' }, project: P2, version: 'main', scan_id: scans[3].id, created_at: iso(2) },
  { id: 'pv-4', rule_name: 'low-scorecard', category: 'maintenance', severity: 'medium', blocking: false, details: {}, summary: 'OpenSSF Scorecard 2.9 is below the minimum of 3.0', component: ref('qs'), project: P1, version: 'release/2.4', scan_id: scans[2].id, created_at: iso(9) },
  { id: 'pv-5', rule_name: 'typosquat', category: 'suspicious', severity: 'high', blocking: true, details: { similar_to: 'lodash', technique: 'swap' }, summary: 'lodahs looks like a typosquat of lodash', component: ref('lodahs'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-6', rule_name: 'deprecated', category: 'suspicious', severity: 'medium', blocking: false, details: { reason: 'request has been deprecated, see https://github.com/request/request/issues/3142', default_version: '2.88.2' }, summary: 'request is deprecated by its maintainers', component: ref('request'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-7', rule_name: 'unmaintained', category: 'suspicious', severity: 'medium', blocking: false, details: { latest_published: '2020-02-11T00:00:00Z', maintained_score: 0 }, summary: 'request has had no release in over 6 years', component: ref('request'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-8', rule_name: 'unusual-behaviour', category: 'suspicious', severity: 'high', blocking: true, details: { rules: ['npm-install-script', 'npm-obfuscation'], risk_score: 9 }, summary: 'event-stream-lite shows unusual install-time behaviour', component: ref('event-stream-lite'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-9', rule_name: 'new-package', category: 'suspicious', severity: 'low', blocking: false, details: { published_at: iso(6), age_days: 6 }, summary: 'lodahs@4.17.21 was published less than 30 days ago', component: ref('lodahs'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-10', rule_name: 'license-incompatible', category: 'license', severity: 'high', blocking: true, details: { license: 'GPL-3.0-or-later', category: 'strong_copyleft', project_license: 'MIT', usage_model: 'distributed_binary', osadl: 'No', explanation: 'GPL-3.0-or-later requires the whole distributed binary to be released under the GPL. Your project is MIT and shipped as a binary, so including this package would force you to relicense or remove it.' }, summary: 'GPL-3.0-or-later is incompatible with MIT when distributed as a binary', component: ref('ffmpeg-static'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
  { id: 'pv-11', rule_name: 'license-conflict', category: 'license', severity: 'medium', blocking: false, details: { license: 'GPL-3.0-or-later', category: 'strong_copyleft', conflicts_with: ['gpl2-bindings@1.0.0 (GPL-2.0-only)'], count: 1, explanation: 'GPL-2.0-only code cannot be combined with GPL-3.0 code in one work.' }, summary: 'ffmpeg-static (GPL-3.0-or-later) cannot be combined in one distributed work with 1 other dependency, e.g. gpl2-bindings@1.0.0 (GPL-2.0-only).', component: ref('ffmpeg-static'), project: P1, version: 'main', scan_id: S1, created_at: iso(1) },
];

// ---- attack paths (storefront main) ----
const nv = (name: string) => `${name}@${comp(name).version}`;
const pi = (chain: string[], advisories: T.PathAdvisory[], risk: T.Risk, score: number, imported: boolean | null, fix: string, approximate = false): T.PathItem => {
  const links = chain.map((n) => ({ name: n, version: comp(n).version, component_id: comp(n).id }));
  const t = links[links.length - 1];
  return { chain: links, target: { name: t.name, version: t.version, component_id: t.component_id! }, advisories, risk, score, depth: chain.length, direct_head: nv(chain[0]), imported, dev: false, approximate, fix };
};
const pathItems: T.PathItem[] = [
  pi(['request', 'event-stream-lite'], [{ id: 'MAL-2026-1337', risk: 'CRITICAL', epss: null, kev: false, fixed_in: null }], 'CRITICAL', 100, true, 'Remove event-stream-lite (malicious) by replacing request'),
  pi(['mkdirp', 'minimist'], [{ id: 'GHSA-3xgq-45jj-v275', risk: 'CRITICAL', epss: 0.0123, kev: true, fixed_in: '1.2.6' }], 'CRITICAL', 57, true, 'Upgrade minimist to ≥1.2.6 (via mkdirp ≥0.5.6)'),
  pi(['express', 'path-to-regexp'], [{ id: 'GHSA-9wv6-86v2-598j', risk: 'HIGH', epss: 0.05, kev: false, fixed_in: '0.1.10' }], 'HIGH', 29, true, 'Upgrade path-to-regexp to ≥0.1.10 (via express ≥4.20.0)'),
  pi(['express', 'body-parser', 'qs'], [{ id: 'GHSA-hrpp-h998-j3pp', risk: 'HIGH', epss: 0.02, kev: false, fixed_in: '6.7.3' }], 'HIGH', 27, true, 'Upgrade qs to ≥6.7.3 (via express ≥4.17.3)'),
  pi(['axios'], [{ id: 'GHSA-wf5p-g6vw-rhxx', risk: 'MEDIUM', epss: 0.01, kev: false, fixed_in: '1.6.0' }], 'MEDIUM', 15, true, 'Upgrade axios to ≥1.6.0'),
  pi(['axios', 'follow-redirects'], [{ id: 'GHSA-jfh8-c2jp-5v3q', risk: 'LOW', epss: 0.004, kev: false, fixed_in: '1.15.4' }], 'LOW', 3, null, 'Upgrade follow-redirects to ≥1.15.4 (via axios ≥1.6.4)', true),
];
const graphEdges: [string, string][] = [
  ['app', 'express'], ['app', 'react'], ['app', 'axios'], ['app', 'lodahs'], ['app', 'request'], ['app', 'ffmpeg-static'], ['app', 'mkdirp'], ['app', 'lodash'],
  ['express', 'body-parser'], ['body-parser', 'qs'], ['express', 'path-to-regexp'], ['express', 'debug'], ['body-parser', 'debug'], ['axios', 'follow-redirects'], ['request', 'event-stream-lite'], ['mkdirp', 'minimist'],
];
function pathGraph(): T.PathGraph {
  const names = [...new Set(graphEdges.flat().filter((n) => n !== 'app'))];
  const risky = (n: string) => pathItems.filter((p) => p.target.name === n);
  const viol = (n: string, cat: string) => violations.some((v) => v.component.name === n && v.category === cat && v.project?.id === P1.id);
  return {
    source: 'lockfile',
    nodes: names.map((n) => {
      const c = comp(n);
      const ps = risky(n);
      return { id: c.id, name: c.name, version: c.version, ecosystem: c.ecosystem, direct: c.direct, depth: c.depth, vulns: ps.filter((p) => !p.advisories[0].id.startsWith('MAL-')).length, max_risk: ps[0]?.risk ?? null, malware: ps.some((p) => p.advisories[0].id.startsWith('MAL-')), suspicious: viol(n, 'suspicious'), license_issue: viol(n, 'license') };
    }),
    edges: graphEdges.map(([a, b]) => ({ from: a === 'app' ? 'app' : comp(a).id, to: comp(b).id })),
    paths: pathItems,
  };
}

const projectSettings: Record<string, T.ProjectSettings> = {
  [P1.id]: { license: 'MIT', license_source: 'manifest', detected_license: 'MIT', usage_model: 'distributed_binary' },
  [P2.id]: { license: 'Apache-2.0', license_source: 'license_file', detected_license: 'Apache-2.0', usage_model: 'saas' },
  [P3.id]: { license: null, license_source: 'unknown', detected_license: null, usage_model: 'internal' },
};
const USAGE = ['internal', 'saas', 'distributed_binary', 'distributed_source'];

const analyses: T.PackageAnalysisDetail[] = components.slice(0, 24).map((c, i) => ({
  id: `pa-${i}`,
  component: { id: c.id, name: c.name, version: c.version, ecosystem: c.ecosystem },
  project: i % 2 ? P1 : P2,
  version: 'main',
  status: i === 2 ? 'malicious' : i === 5 || i === 11 ? 'suspicious' : 'clean',
  verified: i === 2,
  created_at: iso(i % 6),
  source: i === 2 ? 'osv' : 'guarddog',
  evidence: i === 5 || i === 11
    ? { rules: [{ rule: 'npm-install-script', message: 'postinstall script downloads and executes a remote payload', location: 'package.json:12' }, { rule: 'npm-obfuscation', message: 'Heavily obfuscated JavaScript in index.js', location: 'index.js:1' }] }
    : i === 2 ? { advisory: 'MAL-2026-1337', summary: 'Malicious code in package' } : { rules: [] },
  verified_by: i === 2 ? 'security@acme.dev' : null,
  verified_at: i === 2 ? iso(1) : null,
  scan_id: scans[0].id,
}));

const endpoints: T.Endpoint[] = [
  { id: 'ep-1', identifier: 'alice-mbp', endpoint_type: 'developer', hostname: 'alice-mbp.local', os: 'darwin', last_sync_at: iso(0), inventory_count: 14, created_at: iso(12) },
  { id: 'ep-2', identifier: 'ci-runner-07', endpoint_type: 'ci', hostname: 'runner-07', os: 'linux', last_sync_at: iso(1), inventory_count: 5, created_at: iso(30) },
];

let settings: T.Settings = { tenant_id: 'org_mock_acme', domain: 'acme.depguard.dev', plan: 'free', block_mode: true, scan_draft_prs: false, suppress_clean_comments: false, disabled_at: null };
let policy: T.Policy = {
  presets: {
    vulnerability: { min_risk: 'HIGH' },
    malware: { enabled: true },
    license: { deny: [], enabled: true, blocking_severity: 'high' },
    popularity: { enabled: false, min_stars: 10 },
    maintenance: { enabled: true, min_scorecard: 3 },
    packages: [
      { ecosystem: 'npm', name: 'lodash', versions: '>=4.17.21', reason: 'security baseline' },
      { name: 'request', deny: true, reason: 'deprecated, use undici' },
    ],
    suspicious: { typosquat: true, unmaintained: true, unmaintained_months: 24, deprecated: true, new_package: true, no_source_repo: false, unusual_behaviour: true, blocking: ['typosquat', 'unusual-behaviour'] },
  },
  custom: [{ name: 'no-install-scripts', category: 'malware', summary: 'Block packages that run install scripts', expr: 'pkg.ecosystem == "npm" && pkg.name.startsWith("evil-")' }],
};
const pullRequests: T.PRDetail[] = [
  {
    id: 'pr-1', repo_full_name: 'acme/payments-api', number: 482, title: 'Add Stripe webhooks and the payments SDK', author_login: 'mallory', author_avatar: '',
    html_url: 'https://github.com/acme/payments-api/pull/482', state: 'open', draft: false, base_ref: 'main', head_ref: 'feat/stripe', head_sha: 'a1b2c3d4e5f60718',
    latest_scan_id: 'S01JB8A0000000000000000001', urgency: 100, urgency_level: 'critical', labels: ['malware', 'blocked', 'urgent', 'security', 'backend', 'dependencies', 'size/M'],
    reasons: [
      { kind: 'malware', text: 'Remove malicious package event-stream-lite@1.0.2', score: 100 },
      { kind: 'code', text: 'AI: SQL injection in /refunds in api/refunds.ts:42', score: 70 },
      { kind: 'vulnerability', text: 'minimist@1.2.0 has 1 known vulnerability (GHSA-xvch-5gv4-984h)', score: 65 },
    ],
    gh_created_at: iso(3), gh_updated_at: iso(0), closed_at: null, merged_at: null, project: { id: P1.id, name: P1.name },
    scan: { id: 'S01JB8A0000000000000000001', status: 'success', conclusion: 'failure', vulns: 2, violations: 3, malicious: 1, suspicious: 1 },
    summary: {
      scan_id: 'S01JB8A0000000000000000001', no_changes: false, conclusion: 'failure', packages: 4, labels: ['dependencies', 'malware', 'vulnerable'],
      checks: { malware: 'fail', vulnerability: 'fail', license: 'pass', suspicious: 'warn' },
      fixes: [
        { kind: 'malware', severity: 'critical', blocking: true, title: 'Remove malicious package `event-stream-lite@1.0.2`', command: 'npm uninstall event-stream-lite', note: 'Rotate any credentials the build environment had access to.' },
        { kind: 'vulnerability', severity: 'high', blocking: true, title: '`minimist@1.2.0` has 1 known vulnerability (GHSA-xvch-5gv4-984h)', command: 'npm install minimist@1.2.6' },
      ],
    },
    review: {
      head_sha: 'a1b2c3d4e5f60718', files_reviewed: 6, truncated: false, ai_status: 'done', ai_note: '', ai_model: 'qwen.qwen3-coder-30b-a3b-v1:0', ai_risk: 'high',
      ai_summary: 'Adds Stripe webhooks and a refunds endpoint; the refunds query is built from request input.', labels: ['feature', 'backend', 'security'], updated_at: iso(0),
      findings: [
        { source: 'ai', file: 'api/refunds.ts', line: 42, severity: 'high', category: 'injection', title: 'SQL injection in /refunds', explanation: 'req.query.order is concatenated into the SQL string.', suggestion: 'Use a parameterized query ($1).' },
        { source: 'rules', file: 'config/.env.production', line: 3, severity: 'critical', category: 'secrets', title: 'API token committed', fingerprint: 'f'.repeat(64), explanation: 'A token for Stripe is in the diff. Found: `sk_l…` (32 characters).', suggestion: 'Revoke the token now (it stays in git history even if removed), and read it from an environment variable or secret manager.' },
        { source: 'rules', file: 'api/stripe.ts', line: 7, severity: 'high', category: 'crypto', title: 'TLS certificate verification disabled', explanation: 'Turning off certificate checks allows man-in-the-middle attacks.', suggestion: 'Keep verification on.' },
      ],
    },
    history: [
      { id: 'S01JB8A0000000000000000001', head_sha: 'a1b2c3d4e5f60718', status: 'success', conclusion: 'failure', vulns: 2, violations: 3, malicious: 1, created_at: iso(0) },
      { id: 'S01JB8A0000000000000000006', head_sha: '0f9e8d7c6b5a4321', status: 'success', conclusion: 'failure', vulns: 2, violations: 2, malicious: 1, created_at: iso(1) },
    ],
    activity: [{ id: 'act-1', kind: 'comment', body: 'Please replace event-stream-lite before merging.', status: 'posted', actor: 'ada@acme.dev', error: '', created_at: iso(0) }],
  },
  {
    id: 'pr-2', repo_full_name: 'acme/web', number: 97, title: 'Bump next to 16.1', author_login: 'renovate[bot]', author_avatar: '', html_url: 'https://github.com/acme/web/pull/97',
    state: 'open', draft: false, base_ref: 'main', head_ref: 'renovate/next', head_sha: 'ccddeeff00112233', latest_scan_id: 'S01JB8A0000000000000000002', urgency: 35,
    urgency_level: 'medium', labels: ['dependencies', 'size/XS'], reasons: [{ kind: 'suspicious', text: 'busboy@1.6.0 looks unmaintained', score: 35 }],
    gh_created_at: iso(1), gh_updated_at: iso(1), closed_at: null, merged_at: null, project: { id: P2.id, name: P2.name },
    scan: { id: 'S01JB8A0000000000000000002', status: 'success', conclusion: 'neutral', vulns: 0, violations: 1, malicious: 0, suspicious: 1 },
    summary: { scan_id: 'S01JB8A0000000000000000002', no_changes: false, conclusion: 'neutral', packages: 3, labels: ['dependencies'], checks: { malware: 'pass', vulnerability: 'pass', license: 'pass', suspicious: 'warn' }, fixes: [] },
    review: { head_sha: 'ccddeeff00112233', findings: [], labels: ['chore'], files_reviewed: 1, truncated: false, ai_status: 'rate_limited', ai_note: 'all AI models are rate limited, retrying Oct 5 00:05 UTC', ai_model: '', ai_summary: '', ai_risk: '', updated_at: iso(1) },
    history: [], activity: [],
  },
  {
    id: 'pr-3', repo_full_name: 'acme/payments-api', number: 470, title: 'Docs: payment flow diagram', author_login: 'ada', author_avatar: '', html_url: 'https://github.com/acme/payments-api/pull/470',
    state: 'merged', draft: false, base_ref: 'main', head_ref: 'docs/flow', head_sha: '9988776655443322', latest_scan_id: null, urgency: 0, urgency_level: 'clean', labels: ['docs', 'clean'],
    reasons: [], gh_created_at: iso(9), gh_updated_at: iso(8), closed_at: iso(8), merged_at: iso(8), project: { id: P1.id, name: P1.name }, scan: null, summary: null, review: null, history: [], activity: [],
  },
];
let prSettings: T.PRSettings = {
  comment_mode: 'always', request_changes_on_block: false, mention_author_on_block: true, header: '', footer: '',
  sections: { fix_commands: true, code_review: true, vulnerabilities: true, licenses: true, suspicious: true, run_config: true },
  labels: { enabled: true, prefix: 'depguard:' }, ai_review: { enabled: true, max_diff_kb: 200 },
};
const prRow = (d: T.PRDetail): T.PullRequest => {
  const r = { ...d } as Partial<T.PRDetail>;
  delete r.summary;
  delete r.history;
  delete r.activity;
  return { ...(r as T.PRDetail), review: d.review ? { ai_status: d.review.ai_status, findings: d.review.findings.length, ai_risk: d.review.ai_risk } : null };
};
function filterPRs(q: URLSearchParams, project?: string) {
  const state = q.get('state') ?? 'open';
  return pullRequests
    .filter((p) => (state === 'all' || p.state === state) && (!project || p.project?.id === project))
    .filter((p) => (!q.get('level') || p.urgency_level === q.get('level')) && has(p.title + p.repo_full_name, q.get('q')) && (!q.get('author') || p.author_login === q.get('author')))
    .filter((p) => !q.get('project_id') || p.project?.id === q.get('project_id'))
    .sort((a, b) => Number(a.state !== 'open') - Number(b.state !== 'open') || b.urgency - a.urgency)
    .map(prRow);
}

let notif: T.NotificationsResponse = {
  settings: { email_to: ['security@acme.dev'], events: { malware: true, critical: true, kev: true, pr_blocked: true, overdue: true }, digest: { enabled: true, weekday: 1 }, jira: { base_url: '', email: '', project_key: '', issue_type: 'Task' } },
  slack_configured: false,
  slack_hint: '',
  jira_token_set: false,
  email_configured: true,
  secrets_enabled: true,
};
const jiraLinks: T.JiraLink[] = [{ ref_kind: 'vuln', ref: 'GHSA-9wv6-86v2-598j', issue_key: 'SEC-41', url: 'https://acme.atlassian.net/browse/SEC-41', created_by: 'ada@acme.dev', created_at: iso(2) }];
const auditLog: T.AuditEntry[] = [
  { id: 'au-3', actor_id: 'u-ada', actor_email: 'ada@acme.dev', actor_role: 'owner', actor_kind: 'user', action: 'PUT /policy', target_type: '', target_id: '', details: {}, ip: '', created_at: iso(0.1) },
  { id: 'au-2', actor_id: 'u-ada', actor_email: 'ada@acme.dev', actor_role: 'owner', actor_kind: 'user', action: 'web:member.role', target_type: 'member', target_id: 'm-2', details: { role: 'admin' }, ip: '', created_at: iso(1) },
  { id: 'au-1', actor_id: 'u-ci', actor_email: '', actor_role: 'member', actor_kind: 'api_key', action: 'POST /v1/scans', target_type: '', target_id: '', details: { api_key_id: 'k-1' }, ip: '203.0.113.7', created_at: iso(2) },
];
// Project vault (ciphertext and wrapped keys only, exactly like the real API).
let vaultMe: T.VaultMemberSelf | null = null;
const vaultMembers: { user_id: string; email: string; public_key: string }[] = [
  { user_id: 'u_grace', email: 'grace@acme.dev', public_key: 'BOp+nHjmdXQTqE/ItJC7DaLrQkaUBdse21hUrH6M2mwBEb5JrS9gIAOEaLl0gZxAco5h6KJ34wZbzdzNf3RK6nY=' },
];
const vaultKeys: Record<string, Record<string, { key_version: number; wrapped: T.VaultWrappedKey; granted_by: string; created_at: string }>> = {};
const vaultItems: Record<string, (T.VaultItemCipher & { keys: string[]; updated_by: string; updated_at: string; fingerprints: { name: string; sha256: string }[] })[]> = {};
function vaultState(pid: string): T.VaultState {
  const p = projects.find((x) => x.id === pid);
  if (!p) throw new MockNotFound();
  const keys = vaultKeys[pid] ?? {};
  const version = Math.max(0, ...Object.values(keys).map((k) => k.key_version));
  const members = [...(vaultMe ? [{ user_id: vaultMe.user_id, email: 'ada@acme.dev', public_key: vaultMe.public_key }] : []), ...vaultMembers];
  return {
    project_id: pid,
    project: p.name,
    initialized: version > 0,
    key_version: version,
    my_key: keys['u_mock']?.wrapped ?? null,
    items: (vaultItems[pid] ?? []).map((i) => ({ id: i.id, name: i.name, kind: i.kind, version: i.version, key_version: i.key_version, size: i.size, keys: i.keys, updated_by: i.updated_by, updated_at: i.updated_at, leaks: i.fingerprints.length ? [{ key: i.fingerprints[0].name, pr: 482, repo: 'acme/payments-api', file: 'config/.env.production', line: 3, project_id: P2.id }] : [] })),
    members: members.map((m) => ({ ...m, has_access: !!keys[m.user_id], key_version: keys[m.user_id]?.key_version ?? null, granted_by: keys[m.user_id]?.granted_by ?? null, granted_at: keys[m.user_id]?.created_at ?? null })),
  };
}
// Assistant (the chat stream itself is scripted in app/api/assistant/chat/route.ts via mockAssistantChat).
let assistantEnabled = true;
// On globalThis: the route handler and server actions load separate copies of this module in dev.
const assistantConvs: (T.AssistantConversationDetail & { updated_at: string })[] = ((globalThis as { __mockAssistantConvs?: [] }).__mockAssistantConvs ??= []);
export function mockAssistantChat(conversationId: string | undefined, message: string, answer: string, steps: T.AssistantStep[], sources: T.AssistantSource[]) {
  let c = assistantConvs.find((x) => x.id === conversationId);
  if (!c) {
    c = { id: `conv-${assistantConvs.length + 1}`, title: message.slice(0, 60), messages: [], updated_at: new Date().toISOString() };
    assistantConvs.unshift(c);
  }
  const now = new Date().toISOString();
  c.messages.push({ id: `m-${c.messages.length + 1}`, role: 'user', text: message, created_at: now }, { id: `m-${c.messages.length + 2}`, role: 'assistant', text: answer, steps, sources, created_at: now });
  c.updated_at = now;
  return { conversation_id: c.id, message_id: c.messages[c.messages.length - 1].id };
}
let sla: T.SLA = { critical: 7, high: 30, medium: 90, low: 0 };
let fixSettings: T.FixSettings = { auto: false, levels: ['critical'], kev: true, max_open: 5 };
const fixes: T.FixPR[] = [
  { id: 'fx-1', project_id: P1.id, project: P1.name, ecosystem: 'npm', name: 'minimist', from_version: '1.2.5', to_version: '1.2.6', manifest_path: 'package-lock.json', direct: false, advisories: ['GHSA-3xgq-45jj-v275'], branch: 'depguard/fix-minimist-1.2.6', pr_number: 512, pr_url: 'https://github.com/acme/shop/pull/512', status: 'open', error: '', trigger: 'auto', created_by: 'depguard', created_at: iso(1), updated_at: iso(1) },
];
let apiKeys: T.ApiKey[] = [{ id: 'k-1', name: 'GitHub Actions', prefix: 'dg_7Hq2aB9xK', created_at: iso(10), last_used_at: iso(1), expires_at: null }];
let exclusions: T.Exclusion[] = [{ id: 'ex-1', ecosystem: 'npm', name: 'left-pad', version: '1.3.0', reason: 'Internal fork reviewed by security', status: 'active', expires_at: iso(-60), created_at: iso(5) }];
let savedQueries: T.SavedQuery[] = [{ id: 'q-1', name: 'Critical vulns last 30 days', sql: "SELECT project_name, vuln_id, risk\nFROM q_findings\nWHERE risk = 'CRITICAL' AND created_at > now() - interval '30 days'\nLIMIT 100", created_at: iso(3) }];
let tenants: T.AdminTenant[] = [
  { tenant_id: 'org_mock_acme', domain: 'acme.depguard.dev', plan: 'free', disabled_at: null, projects: 3, installations: 1 },
  { tenant_id: 'org_mock_globex', domain: 'globex.depguard.dev', plan: 'free', disabled_at: null, projects: 0, installations: 0 },
];
let installations: T.AdminInstallation[] = [
  { id: '51234567', account_login: 'acme', account_type: 'Organization', status: 'active', tenant_id: 'org_mock_acme', repos: 12, created_at: iso(40) },
  { id: '51239999', account_login: 'initech', account_type: 'Organization', status: 'pending', tenant_id: null, repos: 4, created_at: iso(1) },
];

function paginate<X>(rows: X[], q: URLSearchParams): T.List<X> {
  const page = Math.max(1, Number(q.get('page') ?? 1));
  // Same rule as the real API (internal/httpapi/util.go), so a bad page_size fails in tests too.
  if (q.has('page_size') && ![10, 20, 50].includes(Number(q.get('page_size')))) throw new Error('page_size must be 10, 20 or 50');
  const size = Number(q.get('page_size') ?? 20);
  return { items: rows.slice((page - 1) * size, page * size), total: rows.length };
}

const has = (s: string, q: string | null) => !q || s.toLowerCase().includes(q.toLowerCase());
const inRange = (d: string, q: URLSearchParams) =>
  (!q.get('from') || d >= q.get('from')!) && (!q.get('to') || d <= q.get('to')! + 'T23:59:59Z');
const flag = (q: URLSearchParams, k: string) => q.get(k) === 'true';

function series(days: number) {
  return Array.from({ length: days }, (_, i) => {
    const d = new Date(now - (days - 1 - i) * day).toISOString().slice(0, 10);
    return { d, i };
  });
}

export class MockNotFound extends Error {}

export function mockApi(method: string, path: string, q: URLSearchParams, body: unknown): unknown {
  const b = (body ?? {}) as Record<string, unknown>;
  const seg = path.split('/').filter(Boolean);
  const route = `${method} /${seg.map((s, i) => (i > 0 && /^[A-Za-z0-9_.-]+$/.test(s) && !isStatic(seg[0], i, s) ? ':' : s)).join('/')}`;
  const id = seg[1];

  switch (route) {
    case 'GET /dashboard': {
      const days = q.get('range') === '7d' ? 7 : q.get('range') === '90d' ? 90 : 30;
      return {
        projects: projects.length,
        components: components.length,
        suspicious: analyses.filter((a) => a.status === 'suspicious').length,
        malicious: analyses.filter((a) => a.status === 'malicious').length,
        violations: violations.length,
        vulnerabilities: vulns.length,
        vulns_by_risk: {
          critical: vulns.filter((v) => v.risk === 'CRITICAL').length,
          high: vulns.filter((v) => v.risk === 'HIGH').length,
          medium: vulns.filter((v) => v.risk === 'MEDIUM').length,
          low: vulns.filter((v) => !['CRITICAL', 'HIGH', 'MEDIUM'].includes(v.risk)).length,
        },
        violations_over_time: series(days).map(({ d, i }) => ({ date: d, count: (i * 7) % 5 })),
        violations_by_check: [
          { check: 'vulnerability', count: 6 },
          { check: 'malware', count: 1 },
          { check: 'license', count: 2 },
          { check: 'maintenance', count: 1 },
          { check: 'suspicious', count: 5 },
        ],
        vulns_over_time: series(days).map(({ d, i }) => ({ date: d, critical: i % 9 === 0 ? 1 : 0, high: 2 + (i % 3), medium: 3 + (i % 4), low: 1 + (i % 2) })),
        top_projects: projects.filter((p) => p.vulns).map((p) => ({ id: p.id, name: p.name, vulns: p.vulns })),
        overdue: vulns.filter((v) => v.overdue).length,
        due_soon: 1,
        fixed: { resolved: 9, on_time: 7 },
        transitive_vulnerabilities: pathItems.filter((p) => p.depth > 1 && !p.target.name.startsWith('event-stream')).length,
        attack_paths: pathItems.length,
        suspicious_findings: violations.filter((v) => v.category === 'suspicious').length,
        license_issues: violations.filter((v) => v.category === 'license').length,
      } satisfies T.Dashboard;
    }
    case 'GET /projects':
      return paginate(projects.filter((p) => has(p.name, q.get('name')) && (!q.get('source') || p.source === q.get('source')) && inRange(p.created_at, q) && (!flag(q, 'has_vulns') || p.vulns > 0) && (!flag(q, 'has_violations') || p.violations > 0)), q);
    case 'GET /projects/:': {
      const p = projects.find((x) => x.id === id);
      if (!p) throw new MockNotFound();
      return { id: p.id, name: p.name, source: p.source, url: p.url, created_at: p.created_at, versions: versionsOf[p.id] } satisfies T.ProjectDetail;
    }
    case 'GET /projects/:/versions/:/summary': {
      const p = projects.find((x) => x.id === id)!;
      return { components: p.components, vulns: p.vulns, violations: p.violations, versions_available: p.versions, updated_at: iso(1) } satisfies T.VersionSummary;
    }
    case 'GET /projects/:/versions/:/components':
      return paginate(components.filter((c) => (!flag(q, 'has_vulns') || c.vulns > 0) && (!flag(q, 'has_violations') || c.violations > 0) && directOk(c, q)).map((c) => ({ id: c.id, name: c.name, version: c.version, type: c.type, ecosystem: c.ecosystem, violations: c.violations, vulns: c.vulns, created_at: iso(12), updated_at: c.updated_at, direct: c.direct, depth: c.depth, dev: c.dev })), q);
    case 'GET /projects/:/versions/:/vulnerabilities':
      return paginate(id === P3.id ? [] : vulns.map(({ id, summary, risk, published, modified }) => ({ id, summary, risk, published, modified })), q);
    case 'GET /projects/:/versions/:/violations':
      return paginate(violations.filter((v) => v.project?.id === id), q);
    case 'GET /projects/:/versions/:/scans':
      return paginate(scans.filter((s) => s.project.id === id).map(({ id, trigger, violations, vulns, status, created_at }) => ({ id, trigger, violations, vulns, status, created_at })), q);
    case 'GET /repositories':
      return { items: [
        { id: 'r-1', full_name: 'acme/storefront', default_branch: 'main', private: false, installation_id: '51234567' },
        { id: 'r-2', full_name: 'acme/payments-api', default_branch: 'main', private: true, installation_id: '51234567' },
        { id: 'r-3', full_name: 'acme/docs-site', default_branch: 'trunk', private: false, installation_id: '51234567' },
      ], total: 3 } satisfies T.List<T.Repository>;
    case 'POST /scans':
      return { scan_id: 'S01JB8A00000000000000NEW01' };
    case 'GET /components':
      return paginate(components.filter((c) => has(c.name, q.get('name')) && has(c.version, q.get('version')) && (!q.get('ecosystem') || c.ecosystem === q.get('ecosystem')) && inRange(c.updated_at, q) && (!flag(q, 'has_vulns') || c.vulns > 0) && (!flag(q, 'has_violations') || c.violations > 0) && directOk(c, q)), q);
    case 'GET /components/health': {
      const out: Record<string, T.HealthResult> = {};
      for (const cid of (q.get('ids') ?? '').split(',')) {
        const c = components.find((x) => x.id === cid);
        if (c) out[cid] = mockHealth(c.name);
      }
      return out;
    }
    case 'GET /components/:': {
      const c = components.find((x) => x.id === id);
      if (!c) throw new MockNotFound();
      const pis = pathItems.filter((p) => p.target.name === c.name);
      return {
        id: c.id, name: c.name, version: c.version, ecosystem: c.ecosystem, purl: `pkg:npm/${c.name}@${c.version}`, licenses: ['MIT'],
        vulns: pis.flatMap((p) => p.advisories.map((a) => ({ id: a.id, risk: a.risk, fixed_in: a.fixed_in, summary: vulns.find((v) => v.id === a.id)?.summary ?? null }))),
        projects: [{ id: P1.id, name: P1.name, version: 'main', version_id: 'v-main-1', manifest_path: 'package-lock.json', direct: c.direct }],
        analysis: c.name === 'event-stream-lite' ? { id: 'pa-1', status: 'malicious', verified: true } : null,
        health: mockHealth(c.name),
        meta: { repo: `github.com/${c.name}/${c.name}`, stars: 12400, forks: 800, published_at: iso(400), latest_published: iso(60), first_published: iso(3000), default_version: c.version, deprecated: c.name === 'request', deprecated_reason: c.name === 'request' ? 'request has been deprecated' : '' },
        scorecard: { score: 6.8, checks: { Maintained: 10, 'Code-Review': 7, Vulnerabilities: 6, 'Branch-Protection': 3, 'Signed-Releases': 0 } },
      } satisfies T.ComponentDetail;
    }
    case 'GET /scans':
      return paginate(scans.filter((s) => has(s.project.name, q.get('project')) && (!q.get('project_id') || s.project.id === q.get('project_id')) && has(s.version, q.get('version')) && (!q.get('trigger') || s.trigger === q.get('trigger')) && (!q.get('status') || s.status === q.get('status')) && inRange(s.created_at, q) && (!flag(q, 'has_vulns') || s.vulns > 0) && (!flag(q, 'has_violations') || s.violations > 0)), q);
    case 'GET /pull-requests':
      return paginate(filterPRs(q), q);
    case 'GET /pull-requests/summary': {
      const open = pullRequests.filter((p) => p.state === 'open' && (!q.get('project_id') || p.project?.id === q.get('project_id')));
      const by = Object.fromEntries((['critical', 'high', 'medium', 'low', 'clean', 'pending'] as const).map((l) => [l, open.filter((p) => p.urgency_level === l).length]));
      return { open: open.length, by_level: by, merged_with_issues: 0 } as T.PRSummaryCounts;
    }
    case 'GET /projects/:/pull-requests':
      return paginate(filterPRs(q, seg[1]), q);
    case 'GET /projects/:/pull-requests/:': {
      const pr = pullRequests.find((p) => p.project?.id === seg[1] && String(p.number) === seg[3]);
      if (!pr) throw new MockNotFound('pull request not found');
      return pr.number === 482 ? { ...pr, vault_matches: [{ fingerprint: 'f'.repeat(64), project_id: P2.id, project: P2.name, item: '.env.production', key: 'STRIPE_SECRET_KEY' }] } : pr;
    }
    case 'POST /projects/:/pull-requests/:/comment':
    case 'POST /projects/:/pull-requests/:/review':
    case 'POST /projects/:/pull-requests/:/rescan':
    case 'POST /projects/:/pull-requests/:/ai-review': {
      const pr = pullRequests.find((p) => p.project?.id === seg[1] && String(p.number) === seg[3]);
      if (!pr) throw new MockNotFound('pull request not found');
      const kind = ({ comment: 'comment', review: 'request_changes', rescan: 'rescan', 'ai-review': 'ai_review' } as Record<string, string>)[seg[4]];
      const text = String((body as { body?: string } | undefined)?.body ?? '');
      if ((kind === 'comment' || kind === 'request_changes') && !text.trim()) throw new Error('body is required (at most 60000 characters)');
      const id = `act-${pr.activity.length + 2}`;
      pr.activity.unshift({ id, kind, body: text, status: 'posted', actor: 'ada@acme.dev', error: '', created_at: new Date().toISOString() });
      return { activity_id: id, status: 'queued' };
    }
    case 'GET /fixes':
      return paginate(fixes.filter((f) => (!q.get('project_id') || f.project_id === q.get('project_id')) && (!q.get('status') || f.status === q.get('status'))), q);
    case 'POST /projects/:/fixes': {
      const f = b as { ecosystem: string; name: string; version: string; manifest_path: string };
      const to = ({ lodash: '4.17.21', minimist: '1.2.6', qs: '6.7.3', 'path-to-regexp': '0.1.10', axios: '1.6.0' } as Record<string, string>)[f.name] ?? '';
      if (!to) throw new Error(`${f.name}@${f.version} has no known fixed version in this project`);
      const command = `npm install ${f.name}@${to}`;
      const open = fixes.find((x) => x.project_id === id && x.name === f.name && x.to_version === to && ['queued', 'open'].includes(x.status));
      if (open) return { id: open.id, status: 'exists', to_version: to, command };
      const p = projects.find((x) => x.id === id)!;
      const nf: T.FixPR = { id: `fx-${fixes.length + 1}`, project_id: id, project: p.name, ecosystem: f.ecosystem, name: f.name, from_version: f.version, to_version: to, manifest_path: f.manifest_path, direct: true, advisories: [], branch: '', pr_number: null, pr_url: '', status: 'queued', error: '', trigger: 'manual', created_by: 'ada@acme.dev', created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
      fixes.unshift(nf);
      return { id: nf.id, status: 'queued', to_version: to, command };
    }
    case 'GET /settings/fixes':
      return fixSettings;
    case 'PUT /settings/fixes':
      fixSettings = { ...fixSettings, ...(body as T.FixSettings) };
      return fixSettings;
    case 'GET /settings/pr':
      return { settings: prSettings, ai_configured: true, ai_models: 'eu-west-1/qwen.qwen3-coder-30b-a3b-v1:0' } as T.PRSettingsResponse;
    case 'PUT /settings/pr':
      prSettings = { ...prSettings, ...(body as T.PRSettings) };
      return { settings: prSettings, ai_configured: true, ai_models: 'eu-west-1/qwen.qwen3-coder-30b-a3b-v1:0' } as T.PRSettingsResponse;
    case 'GET /scans/:': {
      const s = scans.find((x) => x.id === id);
      if (!s) throw new MockNotFound();
      return {
        ...s,
        conclusion: s.violations ? 'failure' : 'success',
        pr_number: s.trigger === 'pull_request' ? 482 : null,
        head_sha: '9f2c1e7a4b3d5c6e8f0a1b2c3d4e5f6a7b8c9d0e',
        finished_at: s.status === 'running' ? null : s.created_at,
        error: s.status === 'failed' ? 'lockfile parse error: package-lock.json: unexpected end of JSON input' : null,
        counts: { components: 1204, vulns: s.vulns, violations: s.violations, malicious: s.violations ? 1 : 0, suspicious: 2 },
        report_md: `## depguard: Supply Chain Security\n\n| Check | Result |\n|---|---|\n| Malware | ${s.violations ? '❌ 1 malicious package' : '✅ none'} |\n| Vulnerability | ${s.vulns ? `❌ ${s.vulns} found` : '✅ none'} |\n| License | ✅ none |\n\n<details><summary>Policy violations</summary>\n\n- **malicious-package**: event-stream-lite@1.0.2 is listed as malicious\n- **critical-or-high-vulns**: minimist@4.3.0 has GHSA-3xgq-45jj-v275\n\n</details>\n`,
        packages: scanPackages(s.id),
        findings: s.id === S1 ? violations.filter((v) => v.scan_id === S1 && (v.category === 'suspicious' || v.category === 'license')).map(toFinding) : [],
      } satisfies T.ScanDetail;
    }
    case 'GET /scans/:/paths':
      if (!scans.some((x) => x.id === id)) throw new MockNotFound();
      return { paths: id === S1 || id === scans[1].id ? pathItems : [] };
    case 'GET /projects/:/versions/:/paths': {
      if (!projects.some((p) => p.id === id)) throw new MockNotFound();
      return id === P1.id ? pathGraph() : ({ source: 'none', nodes: [], edges: [], paths: [] } satisfies T.PathGraph);
    }
    case 'GET /projects/:/settings': {
      const st = projectSettings[id];
      if (!st) throw new MockNotFound();
      return st;
    }
    case 'PUT /projects/:/settings': {
      const st = projectSettings[id];
      if (!st) throw new MockNotFound();
      if (b.usage_model !== undefined && !USAGE.includes(String(b.usage_model))) throw new Error('usage_model must be internal, saas, distributed_binary or distributed_source');
      const lic = b.license === undefined ? st.license : (b.license as string | null) || null;
      if (lic && !/^[A-Za-z0-9.+\-() ]{1,200}$/.test(lic)) throw new Error('license must be an SPDX expression');
      projectSettings[id] = { ...st, usage_model: (b.usage_model as T.UsageModel) ?? st.usage_model, license: lic ?? st.detected_license, license_source: lic ? 'override' : st.detected_license ? 'manifest' : 'unknown' };
      return projectSettings[id];
    }
    case 'GET /projects/:/versions/:/licenses': {
      const st = projectSettings[id];
      if (!st) throw new MockNotFound();
      const isP1 = id === P1.id;
      return {
        project_license: st.license,
        usage_model: st.usage_model,
        findings: violations.filter((v) => v.project?.id === id && v.category === 'license').map(({ rule_name, severity, summary, component, details }) => ({ rule: rule_name, severity: severity!, summary, component, details: details ?? {} })),
        distribution: isP1
          ? [
              { license: 'MIT', count: 812, category: 'permissive', summary: 'Permissive: attribution only' },
              { license: 'ISC', count: 201, category: 'permissive', summary: 'Permissive: attribution only' },
              { license: 'Apache-2.0', count: 94, category: 'permissive', summary: 'Permissive: attribution only' },
              { license: 'BSD-3-Clause', count: 61, category: 'permissive', summary: 'Permissive: attribution only' },
              { license: 'BSD-2-Clause', count: 23, category: 'permissive', summary: 'Permissive: attribution only' },
              { license: 'MPL-2.0', count: 3, category: 'weak_copyleft', summary: 'Weak copyleft: changes to the library itself must be shared' },
              { license: 'GPL-3.0-or-later', count: 1, category: 'strong_copyleft', summary: 'Strong copyleft: derivative works must use the same license' },
              { license: 'GPL-2.0-only', count: 1, category: 'strong_copyleft', summary: 'Strong copyleft: derivative works must use the same license' },
              { license: 'UNKNOWN', count: 8, category: 'unknown', summary: 'No license detected: all rights reserved by default' },
            ]
          : [{ license: 'MIT', count: 40, category: 'permissive', summary: 'Permissive: attribution only' }, { license: 'Apache-2.0', count: 12, category: 'permissive', summary: 'Permissive: attribution only' }],
      } satisfies T.LicenseReport;
    }
    case 'GET /package-analyses':
      return paginate(analyses.filter((a) => has(a.project.name, q.get('project')) && (!q.get('project_id') || a.project.id === q.get('project_id')) && has(a.version, q.get('version')) && (!q.get('status') || a.status === q.get('status')) && (!q.get('verified') || String(a.verified) === q.get('verified')) && inRange(a.created_at, q)), q);
    case 'GET /package-analyses/:': {
      const a = analyses.find((x) => x.id === id);
      if (!a) throw new MockNotFound();
      return a;
    }
    case 'POST /package-analyses/:/verify': {
      const a = analyses.find((x) => x.id === id)!;
      Object.assign(a, { status: b.status, verified: true, verified_by: 'you', verified_at: new Date().toISOString() });
      return a;
    }
    case 'GET /vulnerabilities':
      return paginate(vulns.filter((v) => (!q.get('risk') || v.risk === q.get('risk')) && (q.get('overdue') !== '1' || v.overdue) && has(v.id, q.get('id')) && inRange(v.published, q)), q);
    case 'GET /fix-queue': {
      const all: T.FixQueueItem[] = pathItems
        .filter((p) => p.advisories.some((a) => a.fixed_in))
        .map((p, i) => {
          const a = p.advisories[0];
          const w = ({ CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1 } as Record<string, number>)[p.risk] * (i === 0 ? 2 : 1) * (a.kev ? 2 : 1);
          const days = ({ CRITICAL: 7, HIGH: 30, MEDIUM: 90 } as Record<string, number>)[p.risk] ?? 0;
          return { ecosystem: 'npm', name: p.target.name, version: p.target.version, fixed_in: a.fixed_in!, command: `npm install ${p.target.name}@${a.fixed_in}`, risk: p.risk, kev: a.kev, epss: a.epss, advisories: p.advisories.map((x) => ({ id: x.id, risk: x.risk, fixed_in: x.fixed_in ?? '', kev: x.kev })), projects: i === 0 ? [{ id: P1.id, name: P1.name, manifest_path: 'package-lock.json', direct: false }, { id: P2.id, name: P2.name, manifest_path: 'package-lock.json', direct: false }] : [{ id: P1.id, name: P1.name, manifest_path: 'package-lock.json', direct: p.depth === 1 }], first_seen: iso(12), due_at: days ? iso(12 - days) : null, overdue: days > 0 && days < 12, weight: w, share: 0 };
        })
        .filter((x) => !q.get('project_id') || x.projects.some((p) => p.id === q.get('project_id')))
        .sort((a, b) => b.weight - a.weight);
      const total = all.reduce((n, x) => n + x.weight, 0);
      let cum = 0;
      for (const x of all) x.share = Math.round(((cum += x.weight) / total) * 1000) / 10;
      return { items: all, total: all.length, total_weight: total, summary: { overdue: all.filter((x) => x.overdue).length, due_soon: 0, fixable: all.length }, sla } satisfies T.FixQueue;
    }
    case 'GET /audit-log':
      return paginate(auditLog.filter((e) => has(e.actor_email, q.get('actor')) && has(e.action, q.get('action'))), q);
    case 'POST /audit':
      return { status: 'recorded' };
    case 'GET /settings/notifications':
      return notif;
    case 'PUT /settings/notifications': {
      const x = b as { settings: T.NotificationSettings; slack_webhook_url?: string; jira_token?: string };
      if (x.slack_webhook_url !== undefined && x.slack_webhook_url !== '' && !x.slack_webhook_url.startsWith('https://hooks.slack.com/')) throw new Error('Slack webhook URL must start with https://hooks.slack.com/');
      notif = {
        ...notif,
        settings: x.settings,
        slack_configured: x.slack_webhook_url === undefined ? notif.slack_configured : x.slack_webhook_url !== '',
        slack_hint: x.slack_webhook_url ? '…' + x.slack_webhook_url.slice(-6) : x.slack_webhook_url === '' ? '' : notif.slack_hint,
        jira_token_set: x.jira_token === undefined ? notif.jira_token_set : x.jira_token !== '',
      };
      return notif;
    }
    case 'POST /settings/notifications/test': {
      const c = (b as { channel: string }).channel;
      if (c === 'slack' && !notif.slack_configured) throw new Error('add a Slack webhook URL first');
      return { status: 'sent' };
    }
    case 'GET /jira/links':
      return paginate(jiraLinks, q);
    case 'POST /jira/issues': {
      const x = b as { ref_kind: 'vuln' | 'package'; ref: string };
      const found = jiraLinks.find((l) => l.ref_kind === x.ref_kind && l.ref === x.ref);
      if (found) return { issue_key: found.issue_key, url: found.url, status: 'exists' };
      const link: T.JiraLink = { ...x, issue_key: `SEC-${42 + jiraLinks.length}`, url: `https://acme.atlassian.net/browse/SEC-${42 + jiraLinks.length}`, created_by: 'ada@acme.dev', created_at: new Date().toISOString() };
      jiraLinks.push(link);
      return { issue_key: link.issue_key, url: link.url, status: 'created' };
    }
    case 'GET /assistant/briefing':
      return {
        enabled: assistantEnabled,
        configured: true,
        items: [
          { tone: 'red', text: '1 pull request is blocked: acme/payments-api #482 (malware)', url: `/pull-requests/${P2.id}/482` },
          { tone: 'amber', text: 'minimist 1.2.5 is past its fix deadline', url: '/fix-queue' },
          { tone: 'green', text: '7 of 9 vulnerabilities fixed on time this month', url: '/dashboard' },
        ],
      } satisfies T.AssistantBriefing;
    case 'GET /assistant/conversations':
      return { items: assistantConvs.map(({ id, title, updated_at }) => ({ id, title, updated_at })) };
    case 'GET /assistant/conversations/:': {
      const c = assistantConvs.find((x) => x.id === seg[2]);
      if (!c) throw new MockNotFound();
      return { id: c.id, title: c.title, messages: c.messages };
    }
    case 'DELETE /assistant/conversations/:': {
      const i = assistantConvs.findIndex((x) => x.id === seg[2]);
      if (i >= 0) assistantConvs.splice(i, 1);
      return null;
    }
    case 'GET /settings/assistant':
    case 'PUT /settings/assistant':
      if (method === 'PUT') assistantEnabled = Boolean((body as { enabled: boolean }).enabled);
      return { enabled: assistantEnabled, configured: true, provider: 'gemini', model: 'gemini-flash-lite-latest', usage_30d: { questions: 42, input_tokens: 183000, output_tokens: 21000 } } satisfies T.AssistantSettings;
    case 'GET /vaults':
      return { items: projects.map((p) => { const v = vaultState(p.id); return { project_id: p.id, project: p.name, source: 'github', initialized: v.initialized, has_access: !!v.my_key, items: v.items.length, members: v.members.filter((m) => m.has_access).length, leaks: v.items.reduce((n, i) => n + i.leaks.length, 0), updated_at: v.items[0]?.updated_at ?? null }; }) };
    case 'GET /vault/me':
      return { member: vaultMe };
    case 'PUT /vault/me': {
      const x = b as { public_key: string; wrapped_private: T.VaultWrappedPrivate };
      vaultMe = { user_id: 'u_mock', public_key: x.public_key, wrapped_private: x.wrapped_private, created_at: new Date().toISOString() };
      return { member: vaultMe };
    }
    case 'GET /projects/:/vault':
      return vaultState(id);
    case 'POST /projects/:/vault/init':
      if (Object.keys(vaultKeys[id] ?? {}).length) throw new Error('this project\'s vault already exists');
      vaultKeys[id] = { u_mock: { key_version: 1, wrapped: (b as { wrapped: T.VaultWrappedKey }).wrapped, granted_by: 'ada@acme.dev', created_at: new Date().toISOString() } };
      return vaultState(id);
    case 'PUT /projects/:/vault/grants/:': {
      const x = b as { wrapped: T.VaultWrappedKey; key_version: number };
      vaultKeys[id][seg[4]] = { key_version: x.key_version, wrapped: x.wrapped, granted_by: 'ada@acme.dev', created_at: new Date().toISOString() };
      return vaultState(id);
    }
    case 'DELETE /projects/:/vault/grants/:':
      delete vaultKeys[id][seg[4]];
      return vaultState(id);
    case 'POST /projects/:/vault/rotate': {
      const x = b as { key_version: number; grants: { user_id: string; wrapped: T.VaultWrappedKey }[]; items: { id: string; iv: string; ciphertext: string }[] };
      vaultKeys[id] = Object.fromEntries(x.grants.map((g) => [g.user_id, { key_version: x.key_version, wrapped: g.wrapped, granted_by: 'ada@acme.dev', created_at: new Date().toISOString() }]));
      for (const it of x.items) Object.assign(vaultItems[id].find((i) => i.id === it.id)!, { iv: it.iv, ciphertext: it.ciphertext, key_version: x.key_version });
      return vaultState(id);
    }
    case 'PUT /projects/:/vault/items': {
      const x = b as { name: string; kind: 'env' | 'file'; iv: string; ciphertext: string; size: number; key_version: number; fingerprints: { name: string; sha256: string }[] };
      const list = (vaultItems[id] ??= []);
      const cur = list.find((i) => i.name === x.name);
      const row = { id: cur?.id ?? `vi-${list.length + 1}`, name: x.name, kind: x.kind, version: (cur?.version ?? 0) + 1, key_version: x.key_version, iv: x.iv, ciphertext: x.ciphertext, size: x.size, keys: x.fingerprints.map((f) => f.name), updated_by: 'ada@acme.dev', updated_at: new Date().toISOString(), fingerprints: x.fingerprints };
      if (cur) Object.assign(cur, row);
      else list.push(row);
      return vaultState(id);
    }
    case 'GET /projects/:/vault/items/:': {
      const it = (vaultItems[id] ?? []).find((i) => i.id === seg[4]);
      if (!it) throw new MockNotFound();
      return { id: it.id, name: it.name, kind: it.kind, version: it.version, key_version: it.key_version, iv: it.iv, ciphertext: it.ciphertext, size: it.size };
    }
    case 'DELETE /projects/:/vault/items/:':
      vaultItems[id] = (vaultItems[id] ?? []).filter((i) => i.id !== seg[4]);
      return vaultState(id);
    case 'GET /settings/sla':
      return sla;
    case 'PUT /settings/sla':
      sla = { ...sla, ...(body as T.SLA) };
      return sla;
    case 'GET /vulnerabilities/:': {
      const v = vulns.find((x) => x.id === id);
      if (!v) throw new MockNotFound();
      return { id: v.id, summary: v.summary, details: `${v.summary}.\n\nUpgrade to a fixed version. See the references for details.`, risk: v.risk, aliases: v.id.startsWith('GHSA') ? ['CVE-2026-' + (1000 + v.id.length * 37)] : [], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], published: v.published, modified: v.modified, references: [{ type: 'ADVISORY', url: `https://osv.dev/vulnerability/${v.id}` }], epss: 0.0123, kev: v.risk === 'CRITICAL' } satisfies T.VulnerabilityDetail;
    }
    case 'GET /vulnerabilities/:/paths': {
      const ps = pathItems.filter((p) => p.advisories.some((a) => a.id === id));
      return { items: ps.length ? [{ project: P1, version: 'main', paths: ps }, ...(id === 'GHSA-3xgq-45jj-v275' ? [{ project: P2, version: 'main', paths: [{ ...ps[0], chain: [{ name: 'minimist', version: '1.2.5', component_id: comp('minimist').id }], depth: 1, direct_head: 'minimist@1.2.5', score: 60, fix: 'Upgrade minimist to ≥1.2.6' }] }] : [])] : [] } satisfies T.VulnPaths;
    }
    case 'GET /vulnerabilities/:/components':
      return paginate([{ component: ref('minimist'), projects: [P1, P2] }], q);
    case 'GET /policy/violations':
      return paginate(violations.filter((v) => has(v.rule_name, q.get('rule')) && (!q.get('category') || v.category === q.get('category')) && (!q.get('severity') || v.severity === q.get('severity')) && (!q.get('project_id') || v.project?.id === q.get('project_id')) && has(v.version ?? '', q.get('version'))), q);
    case 'GET /policy':
      return policy;
    case 'PUT /policy':
      policy = b as T.Policy;
      return policy;
    case 'POST /policy/test': {
      const expr = String(b.expr ?? '');
      if (!expr.trim()) return { matched: false, error: 'expression is empty' };
      if ((expr.match(/\(/g) ?? []).length !== (expr.match(/\)/g) ?? []).length) return { matched: false, error: 'syntax error: unbalanced parentheses' };
      return { matched: expr.includes(String(b.name ?? '\u0000')) };
    }
    case 'GET /endpoints':
      return paginate(endpoints, q);
    case 'GET /endpoints/:': {
      const e = endpoints.find((x) => x.id === id);
      if (!e) throw new MockNotFound();
      return e;
    }
    case 'GET /endpoints/:/inventory':
      return paginate<T.InventoryItem>([
        { id: 'i1', kind: 'coding_agent', name: 'Claude Code', version: '2.1.0', scope: 'user', config_path: '~/.claude/settings.json', first_seen: iso(3), last_seen: iso(0) },
        { id: 'i2', kind: 'mcp_server', name: 'github', version: '0.9.1', scope: 'project', config_path: '~/code/app/.mcp.json', first_seen: iso(3), last_seen: iso(0) },
        { id: 'i3', kind: 'agent_skill', name: 'pdf', version: '1.0.0', scope: 'user', config_path: '~/.claude/skills/pdf', first_seen: iso(3), last_seen: iso(1) },
        { id: 'i4', kind: 'ide_extension', name: 'ms-python.python', version: '2026.8.0', scope: 'user', config_path: '~/.vscode/extensions', first_seen: iso(3), last_seen: iso(2) },
      ], q);
    case 'GET /endpoints/:/package-events':
      return paginate<T.PackageEvent>([
        { id: 3, ts: iso(0), event_type: 'guard.block', package_name: null, version: null, ecosystem: 'npm', message: 'npm install: block (1 package with findings of 1 checked)', details: { command: 'npm install lodash@4.17.15', dir: 'web', reason: '' } },
        { id: 4, ts: iso(0), event_type: 'guard.package.block', package_name: 'lodash', version: '4.17.15', ecosystem: 'npm', message: 'lodash 4.17.15 is outside the allowed versions >=4.17.21. Reason: security baseline', details: { rules: ['version-not-allowed', 'vulnerability-high-or-higher'] } },
        { id: 5, ts: iso(0), event_type: 'guard.override', package_name: null, version: null, ecosystem: 'pypi', message: 'pip install: override (1 package with findings of 12 checked)', details: { command: 'pip install django==3.2', reason: 'legacy app, upgrade tracked in JIRA-42' } },
        { id: 1, ts: iso(0), event_type: 'install_allowed', package_name: 'express', version: '5.1.0', ecosystem: 'npm' },
        { id: 2, ts: iso(0), event_type: 'malware_blocked', package_name: 'event-stream-lite', version: '1.0.2', ecosystem: 'npm' },
      ], q);
    case 'GET /endpoints/:/agent-events':
      return paginate<T.AgentEvent>([
        { id: 'ae1', session_id: 's1', ts: iso(0), agent_name: 'claude-code', action_type: 'command_exec', result_status: 'success', tool_name: 'Bash', is_sensitive: false },
        { id: 'ae2', session_id: 's1', ts: iso(0), agent_name: 'cursor', action_type: 'file_write', result_status: 'success', tool_name: 'edit_file', is_sensitive: false },
      ], q);
    case 'POST /query': {
      const sql = String(b.sql ?? '').replace(/^\s*(--[^\n]*\n\s*)*/, '').trim();
      if (!/^\s*(select|with)\b/i.test(sql)) throw new Error('only SELECT statements are allowed');
      return { columns: ['project_name', 'vuln_id', 'risk', 'created_at'], rows: vulns.slice(0, 6).map((v, i) => [projects[i % 3].name, v.id, v.risk, v.published]), truncated: false, elapsed_ms: 18 } satisfies T.QueryResult;
    }
    case 'GET /query/schema':
      return { tables: [
        { name: 'q_projects', columns: [{ name: 'id', type: 'text' }, { name: 'name', type: 'text' }, { name: 'source', type: 'text' }, { name: 'created_at', type: 'timestamptz' }] },
        { name: 'q_components', columns: [{ name: 'id', type: 'text' }, { name: 'name', type: 'text' }, { name: 'version', type: 'text' }, { name: 'ecosystem', type: 'text' }, { name: 'updated_at', type: 'timestamptz' }] },
        { name: 'q_findings', columns: [{ name: 'project_name', type: 'text' }, { name: 'vuln_id', type: 'text' }, { name: 'risk', type: 'text' }, { name: 'created_at', type: 'timestamptz' }] },
        { name: 'q_scans', columns: [{ name: 'id', type: 'text' }, { name: 'trigger', type: 'text' }, { name: 'status', type: 'text' }, { name: 'created_at', type: 'timestamptz' }] },
      ] } satisfies T.QuerySchema;
    case 'GET /queries':
      return { items: savedQueries, total: savedQueries.length };
    case 'POST /queries': {
      const sq = { id: `q-${Date.now()}`, name: String(b.name), sql: String(b.sql), created_at: new Date().toISOString() };
      savedQueries = [sq, ...savedQueries];
      return sq;
    }
    case 'DELETE /queries/:':
      savedQueries = savedQueries.filter((x) => x.id !== id);
      return {};
    case 'GET /settings':
      return settings;
    case 'PUT /settings':
      settings = { ...settings, ...(b as Partial<T.Settings>) };
      return settings;
    case 'GET /api-keys':
      return { items: apiKeys, total: apiKeys.length };
    case 'POST /api-keys': {
      const key = 'dg_' + Array.from({ length: 32 }, () => 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'[Math.floor(Math.random() * 56)]).join('');
      const k: T.ApiKey = { id: `k-${Date.now()}`, name: String(b.name), prefix: key.slice(0, 12), created_at: new Date().toISOString(), last_used_at: null, expires_at: (b.expires_at as string) ?? null };
      apiKeys = [k, ...apiKeys];
      return { ...k, key };
    }
    case 'DELETE /api-keys/:':
      apiKeys = apiKeys.filter((k) => k.id !== id);
      return {};
    case 'GET /exclusions':
      return paginate(exclusions.filter((e) => (!q.get('ecosystem') || e.ecosystem === q.get('ecosystem')) && has(e.name, q.get('name')) && has(e.version, q.get('version')) && (!q.get('status') || e.status === q.get('status')) && (!q.get('expiry_before') || (e.expires_at ?? '9') <= q.get('expiry_before')!)), q);
    case 'POST /exclusions': {
      const e = { id: `ex-${Date.now()}`, status: 'active', created_at: new Date().toISOString(), ...(b as object) } as T.Exclusion;
      exclusions = [e, ...exclusions];
      return e;
    }
    case 'PUT /exclusions/:':
      exclusions = exclusions.map((e) => (e.id === id ? { ...e, ...(b as object) } : e));
      return exclusions.find((e) => e.id === id);
    case 'DELETE /exclusions/:':
      exclusions = exclusions.filter((e) => e.id !== id);
      return {};
    case 'GET /integrations':
      return { api_url: 'http://localhost:8080', mcp_url: 'http://localhost:8080/mcp', github: { install_url: 'https://github.com/apps/depguard-dev/installations/new', installations: [{ id: '51234567', account_login: 'acme', status: 'active', repos: 12 }] } } satisfies T.Integrations;

    // ---- admin ----
    case 'GET /admin/tenants':
      return { items: tenants, total: tenants.length };
    case 'POST /admin/tenants': {
      tenants = [...tenants, { tenant_id: String(b.tenant_id), domain: String(b.domain), plan: 'free', disabled_at: null, projects: 0, installations: 0 }];
      return {};
    }
    case 'PATCH /admin/tenants/:':
      tenants = tenants.map((t) => (t.tenant_id === seg[2] ? { ...t, disabled_at: b.disabled ? new Date().toISOString() : null } : t));
      return {};
    case 'GET /admin/installations':
      return { items: installations.filter((i) => !q.get('status') || i.status === q.get('status')), total: installations.length };
    case 'POST /admin/installations/:/link':
      installations = installations.map((i) => (i.id === seg[2] ? { ...i, status: 'active', tenant_id: String(b.tenant_id) } : i));
      return {};
    case 'POST /admin/installations/:/unlink':
      installations = installations.map((i) => (i.id === seg[2] ? { ...i, status: 'pending', tenant_id: null } : i));
      return {};
    case 'GET /admin/feeds':
      return [
        { source: 'osv', last_ok: iso(0), last_error: null, cursor: '2026-10-01T11:45:00Z', updated_at: iso(0) },
        { source: 'kev', last_ok: iso(0), last_error: null, cursor: 'W/"5f3a"', updated_at: iso(0) },
        { source: 'epss', last_ok: iso(1), last_error: 'HTTP 503 from epss.cyentia.com', cursor: '2026-09-30', updated_at: iso(0) },
      ] satisfies T.FeedStatus[];
    case 'GET /admin/webhooks':
      return { items: [
        { delivery_id: '9a1f0c00-1111-11ef-8000-000000000001', event: 'pull_request', status: 'processed', error: null, received_at: iso(0) },
        { delivery_id: '9a1f0c00-1111-11ef-8000-000000000002', event: 'push', status: 'failed', error: 'installation 51239999 is pending', received_at: iso(0) },
      ] satisfies T.WebhookDelivery[], total: 2 };
    case 'POST /admin/webhooks/:/redeliver':
      return {};
    case 'GET /admin/jobs/failed':
      return { items: [{ id: 4412, kind: 'scan_pull_request', state: 'discarded', attempt: 5, errors: [{ error: 'github: 404 Not Found', at: iso(0), attempt: 5 }], finalized_at: iso(0) }] satisfies T.FailedJob[], total: 1 };
  }
  throw new MockNotFound(`mock: no route for ${route}`);
}

// Path segments that are literal words (not ids) at a given position.
function isStatic(root: string, i: number, s: string) {
  const words = ['versions', 'summary', 'components', 'vulnerabilities', 'violations', 'scans', 'verify', 'inventory', 'package-events', 'agent-events', 'schema', 'test', 'link', 'unlink', 'redeliver', 'tenants', 'installations', 'feeds', 'webhooks', 'jobs', 'failed', 'paths', 'licenses', 'settings', 'report', 'pull-requests', 'comment', 'review', 'rescan', 'ai-review', 'fixes', 'vault', 'init', 'grants', 'rotate', 'items'];
  if (root === 'admin' && i === 1) return true;
  if ((root === 'pull-requests' && s === 'summary') || (root === 'components' && s === 'health') || (root === 'assistant' && i === 1) || root === 'settings') return true;
  if (root === 'policy' || root === 'query' || root === 'jira' || root === 'vault') return true;
  return words.includes(s) && i !== 1;
}

const directOk = (c: T.DepInfo, q: URLSearchParams) => !q.get('direct') || String(c.direct) === q.get('direct');

const toFinding = (v: T.Violation): T.Finding => ({ rule: v.rule_name, category: v.category, severity: v.severity ?? 'high', blocking: v.blocking ?? true, summary: v.summary, component: v.component, details: v.details ?? {} });

function scanPackages(scanId: string): T.ScanPackage[] {
  const pkg = (name: string, manifest: string, change: string, extra: Partial<T.ScanPackage> = {}): T.ScanPackage => {
    const c = comp(name);
    const p = pathItems.find((x) => x.target.name === name);
    const via = p ? p.chain.map((l) => `${l.name}@${l.version}`) : [nv(name)];
    return {
      component: { ...ref(name), purl: `pkg:npm/${c.name}@${c.version}` },
      manifest_path: manifest,
      change,
      malware: false,
      vulnerable: false,
      risky_license: false,
      vulns: [],
      violations: violations.filter((v) => v.scan_id === scanId && v.component.name === name).map(({ rule_name, category, summary }) => ({ rule_name, category, summary })),
      direct: c.direct,
      depth: c.depth,
      dev: c.dev,
      via,
      paths: [via],
      imported: p ? p.imported : c.direct ? true : null,
      licenses: name === 'ffmpeg-static' ? ['GPL-3.0-or-later'] : ['MIT'],
      graph_source: 'lockfile',
      ...extra,
    };
  };
  return [
    pkg('event-stream-lite', 'package-lock.json', 'added', { malware: true, vulnerable: true, vulns: [{ id: 'MAL-2026-1337', summary: 'Malicious code in event-stream-lite', risk: 'CRITICAL' }] }),
    pkg('minimist', 'package-lock.json', 'updated', { vulnerable: true, vulns: [{ id: 'GHSA-3xgq-45jj-v275', summary: 'Prototype pollution in minimist', risk: 'CRITICAL' }] }),
    pkg('qs', 'package-lock.json', 'unchanged', { vulnerable: true, vulns: [{ id: 'GHSA-hrpp-h998-j3pp', summary: 'qs vulnerable to prototype pollution', risk: 'HIGH' }] }),
    pkg('lodahs', 'package-lock.json', 'added'),
    pkg('request', 'package-lock.json', 'unchanged'),
    pkg('ffmpeg-static', 'package-lock.json', 'added', { risky_license: true }),
    pkg('react', 'apps/web/package-lock.json', 'added'),
  ];
}

/** Combined report for GET /scans/{id}/report in mock mode (the real one is rendered by Go). */
export function mockReport(id: string, format: 'md' | 'json' | 'html'): string {
  const s = mockApi('GET', `/scans/${id}`, new URLSearchParams(), undefined) as T.ScanDetail;
  const { paths } = mockApi('GET', `/scans/${id}/paths`, new URLSearchParams(), undefined) as { paths: T.PathItem[] };
  if (format === 'json') return JSON.stringify({ scan: s, paths }, null, 2);
  const vulnPkgs = s.packages.filter((p) => p.vulns.length);
  const sections: [string, string[]][] = [
    ['1. Summary', [`Verdict: ${s.conclusion === 'failure' ? 'BLOCKED' : 'PASSED'}`, `${s.counts.components} components, ${s.counts.vulns} vulnerabilities, ${s.counts.malicious} malicious, ${s.findings.length} suspicious/license findings`]],
    ['2. Vulnerabilities by severity', vulnPkgs.flatMap((p) => p.vulns.map((v) => `${v.risk} ${v.id} in ${p.component.name}@${p.component.version} (${p.direct ? 'direct' : 'transitive'})`))],
    ['3. Transitive vulnerabilities', vulnPkgs.filter((p) => p.direct === false).map((p) => `${p.component.name}@${p.component.version} depth ${p.depth}: ${p.via.join(' → ')}`)],
    ['4. Suspicious packages', s.findings.filter((f) => f.category === 'suspicious').map((f) => `${f.rule}: ${f.component.name}@${f.component.version} — ${f.summary}`)],
    ['5. License issues', s.findings.filter((f) => f.category === 'license').map((f) => `${f.rule}: ${f.component.name}@${f.component.version} — ${f.summary}`)],
    ['6. Attack paths', paths.map((p) => `[${p.score}] ${p.chain.map((l) => `${l.name}@${l.version}`).join(' → ')} — ${p.fix}`)],
    ['7. Recommended next steps', paths.slice(0, 3).map((p) => p.fix)],
  ];
  const title = `depguard report: ${s.project.name}@${s.version}`;
  if (format === 'md') return `# ${title}\n\n` + sections.map(([h, l]) => `## ${h}\n\n${l.length ? l.map((x) => `- ${x}`).join('\n') : '_None._'}\n`).join('\n');
  const e = (x: string) => x.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  return `<!doctype html><html><head><meta charset="utf-8"><title>${e(title)}</title><style>body{font-family:system-ui;max-width:56rem;margin:2rem auto;padding:0 1rem}h2{color:#4f46e5}</style></head><body><h1>${e(title)}</h1>${sections.map(([h, l]) => `<h2>${e(h)}</h2>${l.length ? `<ul>${l.map((x) => `<li>${e(x)}</li>`).join('')}</ul>` : '<p><em>None.</em></p>'}`).join('')}</body></html>`;
}

/** A small CycloneDX/SPDX document for the SBOM download route. */
export function mockSbom(projectId: string, format: string) {
  const p = projects.find((x) => x.id === projectId);
  if (!p) throw new MockNotFound();
  if (format === 'spdx')
    return JSON.stringify({ spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT', name: `${p.name}@main`, packages: components.slice(0, 5).map((c, i) => ({ name: c.name, SPDXID: `SPDXRef-Package-${i + 1}`, versionInfo: c.version, downloadLocation: 'NOASSERTION' })) }, null, 2);
  return JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', metadata: { component: { type: 'application', name: p.name } }, components: components.slice(0, 5).map((c) => ({ type: 'library', name: c.name, version: c.version, purl: `pkg:npm/${c.name}@${c.version}` })) }, null, 2);
}

function mockHealth(name: string): T.HealthResult {
  const f = (key: string, label: string, weight: number, value: number | null, detail: string) => ({ key, label, weight, value, detail });
  if (name === 'event-stream-lite') return { score: 0, level: 'malicious', factors: [] };
  const score = name === 'request' ? 3.4 : name.length % 3 === 0 ? 5.6 : 8.4;
  return {
    score,
    level: score >= 7 ? 'good' : score >= 4 ? 'fair' : 'poor',
    factors: [
      f('scorecard', 'OpenSSF Scorecard', 40, 0.68, '6.8 / 10'),
      f('recency', 'Recent releases', 20, name === 'request' ? 0 : 1, name === 'request' ? 'Last release 6 years ago' : 'Last release 2 months ago'),
      f('popularity', 'Popularity', 15, 1, '12400 stars'),
      f('repo', 'Source repository', 10, 1, 'Linked to its source code'),
      f('deprecated', 'Not deprecated', 10, name === 'request' ? 0 : 1, name === 'request' ? 'Deprecated by its maintainers' : 'Not deprecated'),
      f('age', 'Established', 5, 1, 'First published 8 years ago'),
    ],
  };
}
