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
  for (const k of ['Projects', 'Components', 'Suspicious Packages', 'Malicious Packages', 'Policy Violations', 'Total Vulnerabilities', 'Policy Violations Count', 'Policy Violation Checks', 'Vulnerabilities by Risk', 'Top Vulnerable Projects']) {
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
  await columns(page, ['Name', 'Version', 'Classification', 'Ecosystem', 'Policy Violations', 'Vulnerabilities', 'Created At', 'Updated At']);
  const tabs = page.getByRole('navigation', { name: 'Project sections' });
  await tabs.getByRole('link', { name: 'Vulnerabilities' }).click();
  await columns(page, ['ID', 'Summary', 'Risk', 'Published', 'Modified']);
  await expect(page.getByText('Critical').first()).toBeVisible();
  await tabs.getByRole('link', { name: 'Scans' }).click();
  await columns(page, ['Trigger', 'Policy Violations', 'Vulnerabilities', 'Scan Date', 'Status']);
  await page.goto('/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AC?tab=violations');
  await expect(page.getByText('No policy violations found in this project')).toBeVisible();
});

const lists: [string, string[]][] = [
  ['/components', ['Name', 'Projects', 'Version', 'Ecosystem', 'Type', 'Policy Violations', 'Vulnerabilities', 'Last Updated']],
  ['/scans', ['Scanned Project', 'Project Version', 'Trigger', 'Policy Violations', 'Vulnerabilities', 'Scan Date', 'Status']],
  ['/package-analysis', ['Component', 'Project Name', 'Project Version', 'Status', 'Component Version', 'Verification', 'Scan Date']],
  ['/vulnerabilities', ['ID', 'Summary', 'Risk', 'Affected Components', 'Affected Projects', 'Published', 'Modified']],
  ['/policy/violations', ['Rule', 'Category', 'Component', 'Summary', 'Project']],
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
  await expect(page.getByText('Packages (3)')).toBeVisible();
  await expect(page.getByRole('cell', { name: /event-stream-lite/ }).first()).toBeVisible();
  await page.goto('/package-analysis/pa-5');
  await expect(page.getByRole('button', { name: /Mark malicious/ })).toBeVisible();
  await expect(page.getByText('npm-install-script')).toBeVisible();
  await page.goto('/vulnerabilities/GHSA-3xgq-45jj-v275');
  await expect(page.getByText('Affected components')).toBeVisible();
  await expect(page.getByText('Known exploited')).toBeVisible();
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
  await expect(page.getByText('GPL-3.0').first()).toBeVisible();
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
});

test.describe('RBAC', () => {
  test('members are read-only', async ({ page, context }) => {
    await context.addCookies([{ name: 'e2e_role', value: 'member', url: 'http://localhost:3100' }]);
    await page.goto('/projects');
    await expect(page.getByRole('button', { name: 'Scan a repository' })).toBeDisabled();
    await page.goto('/settings/api-keys');
    await expect(page.getByRole('button', { name: /Create API Key/ }).first()).toBeDisabled();
    await page.goto('/package-analysis/pa-5');
    await expect(page.getByRole('button', { name: /Mark malicious/ })).toHaveCount(0);
  });

  test('non super-admins cannot open /admin', async ({ page, context }) => {
    await context.addCookies([{ name: 'e2e_sa', value: '0', url: 'http://localhost:3100' }]);
    await page.goto('/admin');
    await expect(page).toHaveURL(/\/dashboard$/);
  });
});
