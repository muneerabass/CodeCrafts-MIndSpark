import { expect, test, type Page } from '@playwright/test';

const P1 = '01JB7Q3M1K8Z4XW2N5R6T9V0AA';

async function columns(page: Page, names: string[]) {
  for (const n of names) await expect(page.getByRole('columnheader', { name: n, exact: true }).first()).toBeVisible();
}

test('shell: sidebar groups, tenant switcher, user card, plan badge', async ({ page }) => {
  await page.goto('/dashboard');
  const nav = page.locator('[data-sidebar="sidebar"]').first();
  for (const l of ['Dashboard', 'Inventory', 'Projects', 'Components', 'Query', 'Scans', 'Threat & Compliance', 'Package Analysis', 'Vulnerabilities', 'Policy Violations', 'Endpoints', 'Settings', 'Setup']) {
    await expect(nav.getByText(l, { exact: true }).first()).toBeVisible();
  }
  await expect(nav.getByText('acme.depguard.dev')).toBeVisible();
  await expect(nav.getByText('ada@acme.dev')).toBeVisible();
  await expect(nav.getByText('Free plan')).toBeVisible();
  await expect(page.getByRole('link', { name: /Set up more integrations/ })).toBeVisible();
});

test('dashboard: greeting, KPIs, charts, range', async ({ page }) => {
  await page.goto('/dashboard');
  await expect(page.getByRole('heading', { name: /Welcome back, Ada/ })).toBeVisible();
  for (const k of ['Projects', 'Components', 'Suspicious Packages', 'Malicious Packages', 'Policy Violations', 'Total Vulnerabilities', 'Transitive Vulnerabilities', 'Attack Paths', 'Suspicious Findings', 'License Issues', 'Policy Violations Count', 'Policy Violation Checks', 'Vulnerabilities by Risk', 'Top Vulnerable Projects']) {
    await expect(page.locator('main, [data-slot="sidebar-inset"]').getByText(k, { exact: true }).first()).toBeVisible();
  }
  await page.getByRole('combobox', { name: 'Time range' }).click();
  await page.getByRole('option', { name: '7 days' }).click();
  await expect(page).toHaveURL(/range=7d/);
});

test('projects: filters, columns, toggles in URL, pagination', async ({ page }) => {
  await page.goto('/projects');
  await expect(page.getByRole('button', { name: 'Scan a repository' })).toBeVisible();
  await columns(page, ['Repository Name', 'No. of Versions', 'No. of Components', 'Policy Violations', 'Vulnerabilities', 'Created At']);
  await expect(page.getByRole('link', { name: 'acme/storefront' })).toBeVisible();
  await page.getByLabel('Has Vulnerabilities').click();
  await expect(page).toHaveURL(/has_vulns=true/);
  await expect(page.getByRole('link', { name: 'acme/infra-tools' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Previous/ })).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Rows per page' })).toBeVisible();
});

test('scan a repository dialog lists repositories', async ({ page }) => {
  await page.goto('/projects');
  await page.getByRole('button', { name: 'Scan a repository' }).click();
  await expect(page.getByRole('option', { name: /acme\/payments-api/ })).toBeVisible();
});

test('project detail tabs', async ({ page }) => {
  await page.goto(`/projects/${P1}`);
  await expect(page.getByRole('heading', { name: 'acme/storefront' })).toBeVisible();
  await expect(page.getByText('Versions Available')).toBeVisible();
  await columns(page, ['Name', 'Version', 'Classification', 'Dependency', 'Ecosystem', 'Policy Violations', 'Vulnerabilities', 'Created At', 'Updated At']);
  await expect(page.getByText('Transitive · depth 3').first()).toBeVisible();
  await page.getByRole('button', { name: 'Dependency' }).click();
  await page.getByRole('option', { name: 'Transitive' }).click();
  await expect(page).toHaveURL(/direct=false/);
  await expect(page.getByRole('cell', { name: 'Direct', exact: true })).toHaveCount(0);
  const tabs = page.getByRole('navigation', { name: 'Project sections' });
  await tabs.getByRole('link', { name: 'Vulnerabilities' }).click();
  await columns(page, ['ID', 'Summary', 'Risk', 'Published', 'Modified']);
  await expect(page.getByText('Critical').first()).toBeVisible();
  await tabs.getByRole('link', { name: 'Scans' }).click();
  await columns(page, ['Trigger', 'Policy Violations', 'Vulnerabilities', 'Scan Date', 'Status']);
  await tabs.getByRole('link', { name: 'Attack Paths' }).click();
  const graph = page.getByRole('figure', { name: 'Dependency attack path graph' });
  await expect(graph.getByText('Your app')).toBeVisible();
  await expect(graph.getByText('body-parser@1.19.0')).toBeVisible();
  expect(await graph.locator('.react-flow__node').count()).toBeGreaterThan(5);
  const ranked = page.getByRole('list', { name: 'Ranked attack paths' });
  await ranked.getByRole('button', { name: /qs@6\.7\.0/ }).click();
  const panel = page.getByLabel('Selected path');
  await expect(panel.getByText('Upgrade qs to ≥6.7.3 (via express ≥4.17.3)')).toBeVisible();
  await expect(panel.getByRole('link', { name: 'GHSA-hrpp-h998-j3pp' })).toBeVisible();
  await tabs.getByRole('link', { name: 'Licenses' }).click();
  await expect(page.getByText('License distribution')).toBeVisible();
  await expect(page.getByRole('img', { name: 'License distribution' })).toBeVisible();
  await columns(page, ['Rule', 'Severity', 'Package', 'License', 'Explanation']);
  await expect(page.getByText('license-incompatible').first()).toBeVisible();
  await expect(page.getByText(/Conflicts \(2\)/)).toBeVisible();
  await expect(page.getByLabel('Usage model')).toContainText('Distributed binary');
  await page.getByLabel('License override (SPDX)').fill('Apache-2.0');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Project license settings saved')).toBeVisible();
  await page.goto('/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AC?tab=violations');
  await expect(page.getByText('No policy violations found in this project')).toBeVisible();
});

const lists: [string, string[]][] = [
  ['/components', ['Name', 'Projects', 'Version', 'Ecosystem', 'Type', 'Dependency', 'Policy Violations', 'Vulnerabilities', 'Last Updated']],
  ['/scans', ['Scanned Project', 'Project Version', 'Trigger', 'Policy Violations', 'Vulnerabilities', 'Scan Date', 'Status']],
  ['/package-analysis', ['Component', 'Project Name', 'Project Version', 'Status', 'Component Version', 'Verification', 'Scan Date']],
  ['/vulnerabilities', ['ID', 'Summary', 'Risk', 'Affected Components', 'Affected Projects', 'Published', 'Modified']],
  ['/policy/violations', ['Rule', 'Category', 'Severity', 'Component', 'Summary', 'Project']],
  ['/package-analysis?view=suspicious', ['Package', 'Rule', 'Severity', 'Reason', 'Similar To', 'Project', 'Detected']],
  ['/endpoints', ['Endpoint', 'Type', 'Hostname', 'OS', 'Last Sync']],
  ['/settings/package-exclusions', ['Ecosystem', 'Package Name', 'Version', 'Reason', 'Status', 'Expires At', 'Actions']],
];
for (const [path, cols] of lists) {
  test(`list ${path}`, async ({ page }) => {
    await page.goto(path);
    await columns(page, cols);
  });
}

test('reports and detail pages', async ({ page }) => {
  await page.goto('/scans/S01JB8A0000000000000000001');
  await expect(page.getByText('Packages (7)')).toBeVisible();
  await expect(page.getByRole('cell', { name: /event-stream-lite/ }).first()).toBeVisible();
  for (const h of [/Transitive vulnerabilities \(3\)/, /Suspicious packages \(5\)/, /License issues \(2\)/, /Attack paths \(6\)/]) await expect(page.getByText(h)).toBeVisible();
  await expect(page.getByText('express@4.17.1 → body-parser@1.19.0 → qs@6.7.0')).toBeVisible();
  await page.getByRole('button', { name: /Download report/ }).click();
  for (const f of ['Markdown (.md)', 'JSON (.json)', 'HTML (.html)']) await expect(page.getByRole('menuitem', { name: f })).toBeVisible();
  await expect(page.getByRole('menuitem', { name: 'Markdown (.md)' })).toHaveAttribute('href', '/api/scans/S01JB8A0000000000000000001/report?format=md');
  for (const [f, type, text] of [['md', 'text/markdown', '## 6. Attack paths'], ['json', 'application/json', '"paths"'], ['html', 'text/html', '<h2>4. Suspicious packages</h2>']]) {
    const r = await page.request.get(`/api/scans/S01JB8A0000000000000000001/report?format=${f}`);
    expect(r.status()).toBe(200);
    expect(r.headers()['content-type']).toContain(type);
    expect(r.headers()['content-disposition']).toBe(`attachment; filename="depguard-report-S01JB8A0000000000000000001.${f}"`);
    expect(await r.text()).toContain(text);
  }
  await page.goto('/package-analysis/pa-5');
  await expect(page.getByRole('button', { name: /Mark malicious/ })).toBeVisible();
  await expect(page.getByText('npm-install-script')).toBeVisible();
  await page.goto('/vulnerabilities/GHSA-3xgq-45jj-v275');
  await expect(page.getByText('Affected components')).toBeVisible();
  await expect(page.getByText('Known exploited')).toBeVisible();
  await expect(page.getByText('How it reaches your app')).toBeVisible();
  await expect(page.getByRole('link', { name: 'acme/payments-api' }).first()).toBeVisible();
  await expect(page.getByText('mkdirp@0.5.5').first()).toBeVisible();
  await page.goto('/endpoints/ep-1');
  await columns(page, ['Kind', 'Name', 'Version', 'Scope', 'Config Path']);
  await page.getByRole('link', { name: 'Agent Activity' }).click();
  await columns(page, ['Agent', 'Action', 'Tool', 'Result']);
});

test('query page runs SQL', async ({ page }) => {
  await page.goto('/query');
  await expect(page.getByText('q_components')).toBeVisible();
  await page.getByRole('button', { name: 'Run' }).click();
  await expect(page.getByText(/rows? in \d+ ms/)).toBeVisible();
});

test('policy editor', async ({ page }) => {
  await page.goto('/policy');
  for (const c of ['Vulnerability', 'Malware', 'License', 'Popularity', 'Maintenance']) await expect(page.getByText(c, { exact: true }).first()).toBeVisible();
  await expect(page.getByText('No licenses denied.')).toBeVisible();
  for (const t of ['Suspicious', 'Typosquats', 'Unusual behaviour', 'License compliance checks', 'Block at severity']) await expect(page.getByText(t, { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('switch', { name: 'Typosquats' })).toBeChecked();
  await expect(page.getByRole('switch', { name: 'No source repository' })).not.toBeChecked();
});

test('suspicious findings and violation filters', async ({ page }) => {
  await page.goto('/package-analysis?view=suspicious');
  await expect(page.getByRole('cell', { name: 'lodash', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Rule' }).click();
  await page.getByRole('option', { name: 'deprecated' }).click();
  await expect(page).toHaveURL(/rule=deprecated/);
  await expect(page.getByText('request has been deprecated').first()).toBeVisible();
  await expect(page.getByRole('cell', { name: 'lodash', exact: true })).toHaveCount(0);
  await page.goto('/policy/violations');
  await page.getByRole('button', { name: 'Severity' }).click();
  await page.getByRole('option', { name: 'Low' }).click();
  await expect(page).toHaveURL(/severity=low/);
  await expect(page.getByText('new-package')).toBeVisible();
  await page.goto('/policy/violations?category=license');
  await expect(page.getByText('Conflicts With')).toBeVisible();
});

test('setup integrations and guides', async ({ page }) => {
  await page.goto('/setup/integrations');
  for (const t of ['Source Control', 'GitHub App', 'Bitbucket App', 'CI/CD Pipelines', 'GitHub Actions', 'GitLab CI', 'Bitbucket Pipes', 'Developer Tools', 'PMG', 'MCP Server', 'AI Governance & Endpoints', 'AI Tools Discovery']) {
    await expect(page.getByText(t).first()).toBeVisible();
  }
  await expect(page.getByText('Connected').first()).toBeVisible();
  await page.goto('/setup/guides/mcp');
  await expect(page.getByText('/mcp').first()).toBeVisible();
  await page.goto('/setup/guides/github-actions');
  await expect(page.getByText(/--fail-on-violation/).first()).toBeVisible();
});

test('settings pages', async ({ page }) => {
  const pages: [string, string][] = [
    ['/settings/general', 'Tenant Details'],
    ['/settings/api-keys', 'API Keys'],
    ['/settings/teams', 'Team Members'],
    ['/settings/invitations', 'Team Invitations'],
    ['/settings/billing', 'Billing'],
    ['/settings/preferences', 'Tenant Preferences'],
    ['/settings/profile', 'Your Profile'],
  ];
  for (const [path, heading] of pages) {
    await page.goto(path);
    await expect(page.getByRole('heading', { name: heading }).first()).toBeVisible();
  }
  await page.goto('/settings/preferences');
  for (const t of ['Scan Draft Pull Requests', 'Suppress Comments on Clean Scans']) await expect(page.getByText(t).first()).toBeVisible();
  await page.goto('/settings/general');
  await expect(page.getByLabel('Tenant', { exact: true })).toHaveValue('acme.depguard.dev');
});

test('admin panel (super-admin)', async ({ page }) => {
  await page.goto('/admin');
  await expect(page.getByRole('button', { name: /Create tenant/ })).toBeVisible();
  await page.goto('/admin/installations');
  await expect(page.getByText('initech')).toBeVisible();
  await page.goto('/admin/health');
  for (const t of ['Feed sync', 'Failed jobs', 'Webhook deliveries']) await expect(page.getByText(t).first()).toBeVisible();
});

test('public pages', async ({ page }) => {
  await page.goto('/sign-in');
  await expect(page.getByRole('heading', { name: 'Sign in to depguard' })).toBeVisible();
  await page.goto('/attributions');
  await expect(page.getByText('OSV').first()).toBeVisible();
  for (const t of ['OSADL Open Source License Checklists', 'DataDog/guarddog', 'npm-rank']) await expect(page.getByText(t).first()).toBeVisible();
});

test.describe('RBAC', () => {
  test('members are read-only', async ({ page, context, baseURL }) => {
    await context.addCookies([{ name: 'e2e_role', value: 'member', url: baseURL! }]);
    await page.goto('/projects');
    await expect(page.getByRole('button', { name: 'Scan a repository' })).toBeDisabled();
    await page.goto('/settings/api-keys');
    await expect(page.getByRole('button', { name: /Create API Key/ }).first()).toBeDisabled();
    await page.goto('/package-analysis/pa-5');
    await expect(page.getByRole('button', { name: /Mark malicious/ })).toHaveCount(0);
    await page.goto(`/projects/${P1}?tab=licenses`);
    await expect(page.getByLabel('License override (SPDX)')).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
  });

  test('non super-admins cannot open /admin', async ({ page, context, baseURL }) => {
    await context.addCookies([{ name: 'e2e_sa', value: '0', url: baseURL! }]);
    await page.goto('/admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});
