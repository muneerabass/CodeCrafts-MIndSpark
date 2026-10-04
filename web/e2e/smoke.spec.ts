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
  // Grid (default): one card per project with health and numbers.
  const card = page.getByRole('article').filter({ hasText: 'storefront' });
  await expect(card.getByText('At risk')).toBeVisible();
  await expect(card.getByText('Vulnerabilities')).toBeVisible();
  await expect(page.getByRole('article').filter({ hasText: 'infra-tools' }).getByText('Healthy')).toBeVisible();
  await page.getByRole('button', { name: 'Table view' }).click();
  await expect(page).toHaveURL(/view=table/);
  await columns(page, ['Repository Name', 'Health', 'No. of Versions', 'No. of Components', 'Policy Violations', 'Vulnerabilities', 'Created At']);
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
  ['/components', ['Component', 'Status', 'Dependency', 'Projects', 'Policy Violations', 'Vulnerabilities', 'Last Updated']],
  ['/scans', ['Scanned Project', 'Trigger', 'Status', 'Policy Violations', 'Vulnerabilities', 'Scan Date']],
  ['/package-analysis', ['Package', 'Verdict', 'Project', 'Scanned']],
  ['/vulnerabilities', ['Vulnerability', 'Risk', 'Affected', 'Published']],
  ['/policy/violations', ['Violation', 'Severity', 'Component', 'Project', 'Detected']],
  ['/package-analysis?view=suspicious', ['Package', 'Finding', 'Severity', 'Project', 'Detected']],
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
  const title = (t: string) => page.locator('[data-slot=card-title]', { hasText: t });
  for (const t of ['Vulnerabilities by severity', 'Policy findings', 'Where vulnerabilities sit', 'Fix these first']) await expect(title(t)).toBeVisible();
  await page.getByRole('tab', { name: /Vulnerabilities/ }).click();
  await expect(title('Vulnerable packages')).toBeVisible();
  await expect(page.getByText('6 attack paths')).toBeVisible();
  await expect(page.getByText('How it reaches your app').first()).toBeVisible();
  await expect(page.getByText('via express@4.17.1 → body-parser@1.19.0').first()).toBeVisible();
  await page.getByRole('tab', { name: /Suspicious & licenses/ }).click();
  for (const [t, n] of [['Suspicious packages', '5'], ['License issues', '2']]) await expect(title(t)).toContainText(n);
  await page.getByRole('tab', { name: /All packages/ }).click();
  await expect(page.getByText('All packages (7)')).toBeVisible();
  await expect(page.getByRole('cell', { name: /event-stream-lite/ }).first()).toBeVisible();
  await page.getByRole('button', { name: /With issues/ }).click();
  await expect(page.getByRole('cell', { name: /react/ })).toHaveCount(0);
  await page.getByLabel('Search packages').fill('qs');
  await expect(page.getByRole('cell', { name: /event-stream-lite/ })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Save as PDF' })).toBeVisible();
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
  // install guard decisions from the depguard CLI
  await page.getByRole('link', { name: 'Package Events' }).click();
  await columns(page, ['Time', 'Event', 'Package', 'Ecosystem', 'Details']);
  for (const t of ['Install blocked', 'Package blocked', 'Install forced (override)', 'npm install lodash@4.17.15', 'Reason: legacy app, upgrade tracked in JIRA-42']) await expect(page.getByText(t).first()).toBeVisible();
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
  // package & version rules
  const rules = page.getByRole('table', { name: 'Package rules' });
  await expect(rules.getByLabel('Rule 1 package')).toHaveValue('lodash');
  await expect(rules.getByLabel('Rule 1 versions')).toHaveValue('>=4.17.21');
  await expect(rules.getByLabel('Rule 2 package')).toHaveValue('request');
  await expect(rules.getByText('every version')).toBeVisible();
  await page.getByRole('button', { name: 'Add package rule' }).click();
  await rules.getByLabel('Rule 3 package').fill('moment');
  await rules.getByLabel('Rule 3 versions').fill('>=');
  await expect(rules.getByText(/Use e\.g\./)).toBeVisible();
  await rules.getByLabel('Rule 3 versions').fill('<3 || >=3.1');
  await expect(rules.getByText(/Use e\.g\./)).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove rule 3' }).click();
  await expect(rules.getByLabel('Rule 3 package')).toHaveCount(0);
});

test('policy: fresh releases preset', async ({ page }) => {
  await page.goto('/policy');
  const tile = page.getByRole('link', { name: /Fresh releases/ });
  await expect(tile).toContainText('48h cooldown');
  await expect(page.getByRole('switch', { name: 'New install scripts' })).toBeChecked();
  await page.getByLabel('Wait before allowing a new release').click();
  await page.getByRole('option', { name: '72 hours' }).click();
  await page.getByRole('switch', { name: 'Fail the check (otherwise these only warn)' }).click();
  await expect(tile).toContainText('72h cooldown · warn');
  await page.getByRole('button', { name: /Save/ }).first().click();
  await expect(page.getByText(/saved/i).first()).toBeVisible();
  await page.reload();
  await expect(page.getByRole('link', { name: /Fresh releases/ })).toContainText('72h cooldown · warn');
});

test('suspicious findings and violation filters', async ({ page }) => {
  await page.goto('/package-analysis?view=suspicious');
  await expect(page.getByText('Looks like lodash').first()).toBeVisible();
  await page.getByRole('button', { name: 'Rule' }).click();
  await page.getByRole('option', { name: 'deprecated' }).click();
  await expect(page).toHaveURL(/rule=deprecated/);
  await expect(page.getByText('request has been deprecated').first()).toBeVisible();
  await expect(page.getByText('Looks like lodash')).toHaveCount(0);
  await page.goto('/policy/violations');
  await page.getByRole('button', { name: 'Severity' }).click();
  await page.getByRole('option', { name: 'Low' }).click();
  await expect(page).toHaveURL(/severity=low/);
  await expect(page.getByText('new-package')).toBeVisible();
  await page.goto('/policy/violations?category=license');
  await page.getByText('Details', { exact: true }).last().click();
  await expect(page.getByText('Conflicts With')).toBeVisible();
});

test('setup integrations and guides', async ({ page }) => {
  await page.goto('/setup/integrations');
  for (const t of ['Source Control', 'GitHub App', 'Bitbucket App', 'CI/CD Pipelines', 'GitHub Actions', 'GitLab CI', 'Bitbucket Pipes', 'Developer Tools', 'PMG', 'AI agents: MCP server + skill', 'AI Governance & Endpoints', 'AI Tools Discovery']) {
    await expect(page.getByText(t).first()).toBeVisible();
  }
  await expect(page.getByText('Connected').first()).toBeVisible();
  await page.goto('/setup/guides/mcp');
  await expect(page.getByText('/mcp').first()).toBeVisible();
  await expect(page.getByText(/depguard setup agents/).first()).toBeVisible();
  for (const t of ['Cursor', 'VS Code (Copilot agent mode)', 'Windsurf', 'Gemini CLI', 'Codex']) await expect(page.getByText(t, { exact: true })).toBeVisible();
  await expect(page.getByText(/\/agent\/SKILL\.md/).first()).toBeVisible();
  await page.goto('/setup/guides/github-actions');
  await expect(page.getByText(/--fail-on-violation/).first()).toBeVisible();
  await page.goto('/setup/integrations');
  await expect(page.getByText('Install Guard').first()).toBeVisible();
  await page.goto('/setup/guides/install-guard');
  for (const t of [/install\.sh \| sh/, /npm install --save-dev .*depguard-cli\.tgz/, /pip install --find-links .*pypi\/ depguard-cli/, /depguard init/, /depguard check/]) await expect(page.getByText(t).first()).toBeVisible();
  // GitLab and Bitbucket apps are announced; the CI guides cover them meanwhile.
  await page.goto('/setup/integrations');
  for (const c of ['GitLab App', 'Bitbucket App']) {
    const card = page.getByLabel(c);
    await expect(card.getByText('Coming soon')).toBeVisible();
    await expect(card.getByRole('button', { name: `Install ${c}` })).toBeDisabled();
  }
  await page.getByLabel('GitLab App').getByRole('link', { name: 'View setup guide' }).click();
  await expect(page).toHaveURL(/\/setup\/guides\/gitlab-ci$/);
  await page.goto('/setup/guides/container');
  for (const t of [/depguard scan --image ghcr\.io\/acme\/api:1\.4/, /depguard scan --sbom image\.cdx\.json/, /OS packages \(apk, deb\)/]) await expect(page.getByText(t).first()).toBeVisible();
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

test('pull requests: inbox, detail, actions, settings', async ({ page }) => {
  await page.goto('/pull-requests');
  const rows = page.getByRole('list', { name: 'Pull requests' }).getByRole('listitem');
  await expect(rows.first()).toContainText('Add Stripe webhooks and the payments SDK');
  await expect(rows.first()).toContainText('Critical');
  await expect(rows.first()).toContainText('1 malware');
  await expect(page.getByText('Bump next to 16.1')).toBeVisible();
  await expect(page.getByText('Docs: payment flow diagram')).toHaveCount(0); // merged PRs are not in the default (open) view
  await page.getByRole('link', { name: /Medium pull requests/ }).click();
  await expect(page).toHaveURL(/level=medium/);
  await expect(page.getByText('Add Stripe webhooks and the payments SDK')).toHaveCount(0);
  await page.goto('/pull-requests?state=merged');
  await expect(page.getByText('Docs: payment flow diagram')).toBeVisible();

  // detail
  await page.goto('/pull-requests');
  await page.getByRole('link', { name: 'Add Stripe webhooks and the payments SDK' }).click();
  await expect(page.getByRole('heading', { name: /Add Stripe webhooks/ })).toBeVisible();
  await expect(page.getByLabel('Urgency').getByText('Critical · Fix before merging')).toBeVisible();
  await expect(page.getByLabel('Checks').getByText('Failed').first()).toBeVisible();
  await expect(page.getByText('npm uninstall event-stream-lite')).toBeVisible();
  await page.getByRole('tab', { name: /Code review/ }).click();
  await expect(page.getByText('SQL injection in /refunds', { exact: true })).toBeVisible();
  await page.getByText('SQL injection in /refunds', { exact: true }).click(); // the committed token sorts first and is open
  await expect(page.getByRole('link', { name: 'api/refunds.ts:42' })).toHaveAttribute('href', /github\.com\/acme\/payments-api\/blob\/a1b2c3d4e5f60718\/api\/refunds\.ts#L42/);
  await expect(page.getByRole('link', { name: 'Open on GitHub' })).toHaveAttribute('href', 'https://github.com/acme/payments-api/pull/482');

  // comment editor: preview, templates, post
  const editor = page.getByLabel('Comment', { exact: true });
  await page.getByRole('button', { name: 'Ask to upgrade' }).click();
  await expect(editor).toHaveValue(/upgrade the vulnerable dependencies/);
  await editor.fill('**Please** upgrade minimist.');
  await page.getByRole('tab', { name: 'preview' }).click();
  await expect(page.locator('strong', { hasText: 'Please' })).toBeVisible();
  await page.getByRole('tab', { name: 'write' }).click();
  await page.getByRole('button', { name: 'Post comment' }).click();
  await expect(page.getByText('Comment queued for GitHub')).toBeVisible();
  await expect(page.getByLabel('Activity').getByText('**Please** upgrade minimist.')).toBeVisible();
  await page.getByRole('button', { name: 'Re-run AI review' }).click();
  await expect(page.getByText('AI security review queued')).toBeVisible();

  // project tab and dashboard card
  await page.goto('/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AA?tab=pull-requests');
  await expect(page.getByText('Add Stripe webhooks and the payments SDK')).toBeVisible();
  await expect(page.getByText('Bump next to 16.1')).toHaveCount(0); // another project
  await page.goto('/dashboard');
  await expect(page.getByLabel('Pull requests needing attention').getByText('Add Stripe webhooks and the payments SDK')).toBeVisible();

  // settings
  await page.goto('/settings/pull-requests');
  await expect(page.getByText('AI model configured: eu-west-1/qwen.qwen3-coder-30b-a3b-v1:0.')).toBeVisible();
  await page.getByLabel('Request changes on blocking issues').click();
  await page.getByLabel('Header (Markdown)').fill('Security questions? Ask in **#appsec**.');
  await expect(page.locator('strong', { hasText: '#appsec' })).toBeVisible(); // live preview
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Pull request settings saved')).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Header (Markdown)')).toHaveValue('Security questions? Ask in **#appsec**.');
  await expect(page.getByLabel('Request changes on blocking issues')).toBeChecked();
});

test('auto-fix: create fix PR from a scan report, settings', async ({ page }) => {
  await page.goto('/scans/S01JB8A0000000000000000002');
  await page.getByRole('tab', { name: /Vulnerabilities/ }).click();
  const vulns = page.getByRole('tabpanel', { name: /Vulnerabilities/ });
  await expect(vulns.getByRole('link', { name: 'Fix PR #512 open' })).toBeVisible(); // minimist: existing auto fix
  await vulns.getByRole('button', { name: 'Create fix PR' }).first().click();
  await expect(page.getByText(/Opening a PR to upgrade qs to 6\.7\.3/)).toBeVisible();
  await expect(vulns.getByText('Opening fix PR…')).toBeVisible();

  await page.goto('/settings/auto-fix');
  await expect(page.getByText('minimist').first()).toBeVisible();
  await page.getByLabel('Open fix PRs automatically').click();
  await page.getByRole('button', { name: 'high' }).click();
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('Auto-fix settings saved')).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Open fix PRs automatically')).toBeChecked();
  await expect(page.getByRole('button', { name: 'high' })).toHaveAttribute('aria-pressed', 'true');
});

test('fix first queue, deadlines on vulnerabilities and dashboard, deadline settings', async ({ page }) => {
  await page.goto('/fix-queue');
  await expect(page.getByRole('heading', { name: 'Fix first' })).toBeVisible();
  await expect(page.getByText(/(Fix the top \d+ packages to remove [\d.]+%|removes all) of your known vulnerability risk/)).toBeVisible();
  const first = page.getByRole('listitem').filter({ hasText: 'minimist' }).first();
  await expect(first.getByText('Actively exploited')).toBeVisible();
  await expect(first.getByText(/Overdue \d+d/)).toBeVisible();
  await expect(first.getByRole('link', { name: 'Fix PR #512 open' })).toBeVisible();
  await expect(page.getByRole('list', { name: 'Projects using minimist' }).getByRole('link', { name: 'acme/payments-api' })).toBeVisible();

  await page.goto('/vulnerabilities');
  await expect(page.getByRole('columnheader', { name: 'Fix by' })).toBeVisible();
  await page.getByRole('link', { name: /Past fix deadline/ }).click();
  await expect(page).toHaveURL(/overdue=1/);
  await expect(page.getByRole('link', { name: 'GHSA-3xgq-45jj-v275' }).first()).toBeVisible();
  await expect(page.getByRole('link', { name: 'GHSA-wf5p-g6vw-rhxx' })).toHaveCount(0);

  await page.goto('/dashboard');
  await expect(page.getByRole('link', { name: 'What to fix first' })).toBeVisible();
  await expect(page.getByText('78%')).toBeVisible(); // 7 of 9 fixed on time

  await page.goto('/settings/preferences');
  await page.getByLabel('Critical').fill('14');
  await page.getByRole('button', { name: 'Save deadlines' }).click();
  await expect(page.getByText('Fix deadlines saved')).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Critical')).toHaveValue('14');
});

test('notifications: slack, email, events, digest, jira tickets', async ({ page }) => {
  await page.goto('/settings/notifications');
  await expect(page.getByLabel('Email recipients')).toHaveValue('security@acme.dev');
  await page.getByLabel('Slack webhook URL').fill('https://evil.example/hook');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Slack webhook URL must start with https://hooks.slack.com/')).toBeVisible();
  await page.getByLabel('Slack webhook URL').fill('https://hooks.slack.com/services/T0/B0/abc123');
  await page.getByLabel('Pull request blocked').click();
  await page.getByLabel('Jira site').fill('https://acme.atlassian.net');
  await page.getByLabel('Account email').fill('bot@acme.dev');
  await page.getByLabel('Project key').fill('sec');
  await page.getByLabel('API token').fill('token-1');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Notification settings saved')).toBeVisible();
  await expect(page.getByLabel('Slack webhook URL')).toHaveAttribute('placeholder', /Connected \(…abc123\)/);
  await expect(page.getByLabel('Slack webhook URL')).toHaveValue('');
  await page.getByRole('button', { name: 'Send test' }).first().click();
  await expect(page.getByText('Test message sent')).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Pull request blocked')).not.toBeChecked();
  await expect(page.getByLabel('Project key')).toHaveValue('SEC');

  // Jira tickets from a vulnerability and the fix queue.
  await page.goto('/vulnerabilities/GHSA-9wv6-86v2-598j');
  await expect(page.getByRole('link', { name: 'SEC-41' })).toBeVisible(); // existing ticket
  await page.goto('/vulnerabilities/GHSA-3xgq-45jj-v275');
  await page.getByRole('button', { name: 'Create Jira ticket' }).click();
  await expect(page.getByRole('link', { name: /SEC-4\d/ })).toBeVisible();
  await page.goto('/fix-queue');
  await expect(page.getByRole('button', { name: 'Create Jira ticket' }).first()).toBeVisible();
});

test('project export: SBOM downloads and compliance report', async ({ page }) => {
  await page.goto('/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AA');
  await page.getByRole('button', { name: 'Export' }).click();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('menuitem', { name: 'CycloneDX 1.6 (.json)' }).click()]);
  expect(dl.suggestedFilename()).toMatch(/\.cdx\.json$/);
  const bom = JSON.parse(await (await import('node:fs/promises')).readFile((await dl.path())!, 'utf8'));
  expect(bom.bomFormat).toBe('CycloneDX');
  const spdx = await page.request.get('/api/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AA/sbom?format=spdx');
  expect((await spdx.json()).spdxVersion).toBe('SPDX-2.3');
  expect((await page.request.get('/api/projects/01JB7Q3M1K8Z4XW2N5R6T9V0AA/sbom?format=xml')).status()).toBe(400);

  await page.getByRole('button', { name: 'Export' }).click();
  await page.getByRole('menuitem', { name: 'Compliance report (PDF)' }).click();
  await expect(page.getByRole('heading', { name: 'acme/storefront', level: 1 })).toBeVisible();
  await expect(page.getByText('Action required before this release meets policy.')).toBeVisible();
  for (const h of ['Open vulnerabilities', 'Licenses', 'Policy violations', 'Software bill of materials']) await expect(page.getByRole('heading', { name: h })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save as PDF' })).toBeVisible();
});

test('secrets: PR check tile and policy switch', async ({ page }) => {
  await page.goto('/pull-requests');
  await page.getByRole('link', { name: /Add Stripe webhooks|Add payments/ }).first().click();
  const checks = page.getByLabel('Checks');
  await expect(checks.getByText('Secrets')).toBeVisible();
  await page.getByRole('tab', { name: /Code review/ }).click();
  await expect(page.getByRole('link', { name: 'acme/payments-api › .env.production' })).toBeVisible(); // leaked key → vault entry
  await page.goto('/policy');
  await expect(page.getByRole('link', { name: /Secrets in PRs/ })).toContainText('Blocks keys & tokens');
  await page.getByLabel('Also fail on hard-coded passwords (otherwise a warning)').click();
  await expect(page.getByRole('link', { name: /Secrets in PRs/ })).toContainText('Blocks keys & passwords');
});

test('components: health column and package detail page', async ({ page }) => {
  await page.goto('/components?name=request');
  await expect(page.getByRole('columnheader', { name: 'Health' })).toBeVisible();
  await expect(page.getByRole('row').filter({ hasText: '2.88.2' }).getByText('3.4')).toBeVisible();
  await page.getByRole('link', { name: 'request', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'request', level: 1 })).toBeVisible();
  const health = page.getByLabel('Package health');
  await expect(health.getByText('poor', { exact: true })).toBeVisible();
  await expect(health.getByText('Deprecated by its maintainers')).toBeVisible();
  await expect(page.getByLabel('Scorecard checks').getByText('Signed Releases')).toBeVisible();
  await expect(page.getByRole('link', { name: 'acme/storefront' })).toBeVisible();
});

test('audit log: entries, filter, CSV export', async ({ page }) => {
  await page.goto('/settings/audit-log');
  await expect(page.getByText('Changed the policy')).toBeVisible();
  await expect(page.getByText('Changed a member’s role')).toBeVisible();
  await expect(page.getByText('Uploaded a scan (CLI/CI)')).toBeVisible();
  await expect(page.getByText('203.0.113.7', { exact: false })).toBeVisible();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()]);
  expect(dl.suggestedFilename()).toMatch(/^depguard-audit-log-.*\.csv$/);
  await page.goto('/settings/audit-log?action=policy');
  await expect(page.getByText('Changed the policy')).toBeVisible();
  await expect(page.getByText('Uploaded a scan (CLI/CI)')).toHaveCount(0);
});

test('vault: passphrase, create, encrypt and view a .env, unlock again, approve a teammate, rotate on removal', async ({ page }) => {
  test.setTimeout(120_000); // PBKDF2 with 600k iterations runs a few times
  await page.goto('/dashboard');
  await page.getByRole('link', { name: 'Secrets', exact: true }).click();
  await page.getByRole('listitem').filter({ hasText: 'acme/storefront' }).getByRole('link', { name: /Create vault|Open vault/ }).click();
  await expect(page.getByRole('heading', { name: 'Project secrets' })).toBeVisible();
  await page.getByLabel('Passphrase (12+ characters)').fill('correct horse battery');
  await page.getByLabel('Repeat it').fill('correct horse battery');
  await page.getByRole('button', { name: 'Create my vault key' }).click();
  await page.getByRole('button', { name: 'Create vault' }).click();
  await expect(page.getByText('Vault created')).toBeVisible();

  await page.getByLabel('File name').fill('.env.production');
  await page.getByLabel('File contents').fill('STRIPE_SECRET_KEY=sk_live_0123456789abcdef\nDATABASE_URL="postgres://app:pw@db/app"\n');
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByText('.env.production saved, encrypted')).toBeVisible();
  const items = page.getByLabel('Vault items');
  await expect(items.getByText('2 keys: STRIPE_SECRET_KEY, DATABASE_URL', { exact: false })).toBeVisible();
  await expect(items.getByText(/STRIPE_SECRET_KEY leaked in/)).toBeVisible();

  await items.getByRole('button', { name: 'View' }).click();
  const contents = page.getByLabel('Contents of .env.production');
  await expect(contents.getByText('sk_live_0123456789abcdef')).toHaveCount(0); // masked
  await contents.getByRole('button', { name: 'Show STRIPE_SECRET_KEY' }).click();
  await expect(contents.getByText('sk_live_0123456789abcdef')).toBeVisible();

  // A reload locks it; the passphrase unlocks it again and decrypts.
  await page.reload();
  await page.getByLabel('Vault passphrase').fill('wrong passphrase');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText('Wrong vault passphrase')).toBeVisible();
  await page.getByLabel('Vault passphrase').fill('correct horse battery');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await page.getByLabel('Vault items').getByRole('button', { name: 'View' }).click();
  await page.getByLabel('Contents of .env.production').getByRole('button', { name: 'Show DATABASE_URL' }).click();
  await expect(page.getByText('postgres://app:pw@db/app')).toBeVisible();

  // Approve Grace (her key wraps the vault key), then remove her: the key rotates.
  const members = page.getByLabel('Vault members');
  await members.getByRole('listitem').filter({ hasText: 'grace@acme.dev' }).getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByText('Access granted')).toBeVisible();
  page.once('dialog', (d) => d.accept());
  await members.getByRole('listitem').filter({ hasText: 'grace@acme.dev' }).getByRole('button', { name: 'Remove' }).click();
  await expect(page.getByText('grace@acme.dev removed; vault key rotated')).toBeVisible();
  await page.getByLabel('Vault items').getByRole('button', { name: 'View' }).click(); // still decrypts with the new key
  await expect(page.getByLabel('Contents of .env.production').getByText('STRIPE_SECRET_KEY')).toBeVisible();
  await page.goto('/secrets');
  await expect(page.getByRole('listitem').filter({ hasText: 'acme/storefront' }).getByText(/1 file · .*1 with access/)).toBeVisible();
});
