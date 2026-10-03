// Real-stack E2E: web + Go api + worker + Postgres + Mailpit, synced feeds.
// See docs/TESTING.md. Env: E2E_WEB_URL, E2E_API_URL, E2E_MAILPIT_URL, DEPGUARD_BIN,
// E2E_WORKDIR (screenshots), E2E_EXTRA_PROJECT (optional extra dir to scan).
// The web must run with SUPERADMIN_EMAILS=admin@example.com and SMTP pointed at Mailpit.
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
const ROOT = new URL('../../', import.meta.url).pathname;
const require = createRequire(`${ROOT}web/package.json`);
const { chromium } = require('@playwright/test');

const WEB = process.env.E2E_WEB_URL ?? 'http://localhost:13000';
const API = process.env.E2E_API_URL ?? 'http://127.0.0.1:18080';
const CLI = process.env.DEPGUARD_BIN ?? 'depguard';
const MAIL = process.env.E2E_MAILPIT_URL ?? 'http://127.0.0.1:8025/api/v1';
const S = process.env.E2E_WORKDIR ?? '/tmp/depguard-e2e';
const SHOTS = `${S}/shots`;
fs.mkdirSync(SHOTS, { recursive: true });
const results = [];
const ok = (name, detail = '') => { results.push(['PASS', name, detail]); console.log('PASS', name, detail); };
const fail = (name, detail) => { results.push(['FAIL', name, detail]); console.log('FAIL', name, detail); };

async function latestMail(to, subjectHas, since) {
  for (let i = 0; i < 40; i++) {
    const list = await (await fetch(`${MAIL}/messages?limit=50`)).json();
    const m = list.messages.find((x) => x.To.some((t) => t.Address === to) && new Date(x.Created) >= since && (!subjectHas || x.Subject.toLowerCase().includes(subjectHas)));
    if (m) return (await (await fetch(`${MAIL}/message/${m.ID}`)).json());
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`no mail for ${to} (${subjectHas})`);
}
const linkIn = (msg, re) => {
  const m = (msg.Text + ' ' + msg.HTML).match(re);
  if (!m) throw new Error('link not found in mail: ' + msg.Subject);
  return m[0].replace(/&amp;/g, '&');
};

async function magicSignIn(page, email) {
  const since = new Date(Date.now() - 1000);
  await page.goto(`${WEB}/sign-in`);
  await page.fill('#email', email);
  await page.locator('form button[type=submit]').click();
  const mail = await latestMail(email, '', since);
  await page.goto(linkIn(mail, new RegExp(WEB.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&') + '/api/auth/magic-link/verify[^\\s"\'<>]+')));
  await page.waitForLoadState('networkidle');
}

async function checkPage(page, path, expectText, shot) {
  const errors = [];
  const onErr = (m) => { if (m.type() === 'error') errors.push(m.text()); };
  page.on('console', onErr);
  const res = await page.goto(`${WEB}${path}`);
  await page.waitForLoadState('networkidle');
  page.off('console', onErr);
  await page.waitForTimeout(1500); // let charts finish animating
  const body = await page.locator('body').innerText();
  if (shot) await page.screenshot({ path: `${SHOTS}/${shot}.png`, fullPage: true });
  if (!res || res.status() >= 400) return fail(path, `HTTP ${res?.status()}`);
  if (/couldn.t load this page|Application error|Internal Server Error/i.test(body)) return fail(path, 'error card shown');
  for (const t of [].concat(expectText || [])) if (!body.toLowerCase().includes(t.toLowerCase())) return fail(path, `missing text "${t}"`);
  ok(path, errors.length ? `(console errors: ${errors.length})` : '');
}

const RUN = Date.now().toString(36);
const OWNER = `owner+${RUN}@example.com`;
const browser = await chromium.launch();
try {
  // 1. Super-admin signs in and creates a tenant.
  const adminCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const admin = await adminCtx.newPage();
  await magicSignIn(admin, 'admin@example.com');
  await checkPage(admin, '/admin', 'Create tenant', 'admin-tenants');
  await admin.getByRole('button', { name: /Create tenant/ }).first().click();
  await admin.fill('#t-name', `Acme ${RUN}`);
  await admin.fill('#t-email', OWNER);
  const inviteSince = new Date(Date.now() - 1000);
  await admin.getByRole('dialog').locator('button[type=submit]').click();
  await admin.waitForTimeout(2500);
  const tenantsBody = await admin.locator('body').innerText();
  tenantsBody.toLowerCase().includes(RUN) ? ok('tenant created', 'listed in admin') : fail('tenant created', tenantsBody.slice(0, 300));
  await checkPage(admin, '/admin/installations', null, 'admin-installations');
  await checkPage(admin, '/admin/health', ['osv'], 'admin-health');

  // 2. Owner accepts the invitation.
  const invite = await latestMail(OWNER, '', inviteSince);
  const inviteUrl = linkIn(invite, new RegExp(WEB.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&') + '/accept-invitation/[^\\s"\'<>]+'));
  ok('invitation email', invite.Subject);
  const ownerCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const owner = await ownerCtx.newPage();
  await magicSignIn(owner, OWNER);
  await owner.goto(inviteUrl);
  await owner.getByRole('button', { name: /Accept invitation/ }).click();
  await owner.waitForURL(/dashboard/, { timeout: 15000 });
  ok('invitation accepted', owner.url());

  // 3. Owner creates an API key in the UI.
  await owner.goto(`${WEB}/settings/api-keys`);
  await owner.getByRole('button', { name: /Create API Key/i }).first().click();
  await owner.getByRole('dialog').locator('input').first().fill('ci');
  await owner.getByRole('dialog').locator('button[type=submit], button:has-text("Create")').last().click();
  let keyText = '', key;
  for (let i = 0; i < 30 && !key; i++) {
    await owner.waitForTimeout(500);
    keyText = await owner.getByRole('dialog').innerText().catch(() => '');
    key = (keyText.match(/dg_[A-Za-z0-9]{32}/) || [])[0];
    if (!key) key = await owner.getByRole('dialog').locator('input[readonly], code').first().inputValue().catch(() => owner.getByRole('dialog').locator('code').first().innerText().catch(() => undefined));
    if (key && !/^dg_[A-Za-z0-9]{32}$/.test(key)) key = undefined;
  }
  if (!key) throw new Error('API key not shown: ' + keyText);
  ok('API key created in UI', key.slice(0, 12) + '…');
  await owner.keyboard.press('Escape');

  // 4. Real scans through the CLI with that key.
  const env = { ...process.env, DEPGUARD_API_URL: API, DEPGUARD_API_KEY: key };
  const scanDirs = [[`${ROOT}test/e2e/fixtures/e2e-app`, 'acme/e2e-app']];
  if (process.env.E2E_EXTRA_PROJECT) scanDirs.push([process.env.E2E_EXTRA_PROJECT, 'extra/project']);
  for (const [dir, name] of scanDirs) {
    try { execSync(`${CLI} scan --project ${name} --version main --source github`, { cwd: dir, env, stdio: 'pipe' }); }
    catch (e) { /* exit 1 = policy failure, expected */ if (e.status !== 1) throw e; }
  }
  ok('CLI scans uploaded');
  // Endpoint agent: one check-in with inventory discovery.
  execSync(`${CLI} agent --once`, { env, stdio: 'pipe' });
  ok('endpoint agent check-in');

  // 5. Visit every tenant page.
  const pages = [
    ['/dashboard', ['Projects', 'Components', 'Malicious Packages', 'Total Vulnerabilities'], 'dashboard'],
    ['/projects', ['acme/e2e-app'], 'projects'],
    ['/components?name=lodash', ['lodash'], 'components'],
    ['/scans', ['acme/e2e-app'], 'scans'],
    ['/package-analysis', ['react-dropzone-truffle'], 'package-analysis'],
    ['/vulnerabilities', ['GHSA-'], 'vulnerabilities'],
    ['/policy/violations?category=malware', ['malicious-package'], 'policy-violations'],
    ['/policy', null, 'policy'],
    ['/endpoints', null, 'endpoints'],
    ['/query', null, 'query'],
    ['/setup/integrations', ['GitHub App'], 'integrations'],
    ['/setup/guides/cli', ['depguard scan'], 'guide-cli'],
    ['/settings/general', ['Tenant'], 'settings-general'],
    ['/settings/api-keys', ['ci'], 'settings-api-keys'],
    ['/settings/package-exclusions', null, 'settings-exclusions'],
    ['/settings/teams', [OWNER], 'settings-teams'],
    ['/settings/invitations', null, 'settings-invitations'],
    ['/settings/billing', null, 'settings-billing'],
    ['/settings/preferences', ['Scan Draft Pull Requests'], 'settings-preferences'],
    ['/settings/profile', null, 'settings-profile'],
    ['/attributions', null, null],
  ];
  for (const [p, t, s] of pages) await checkPage(owner, p, t, s);

  // Project detail tabs.
  await owner.goto(`${WEB}/projects`);
  await owner.getByText('acme/e2e-app').first().click();
  await owner.waitForURL(/\/projects\/[^/?]+/);
  const proj = new URL(owner.url()).pathname;
  for (const tab of ['components', 'vulnerabilities', 'violations', 'scans']) await checkPage(owner, `${proj}?tab=${tab}`, null, `project-${tab}`);
  // Scan report + endpoint detail.
  await owner.goto(`${WEB}/scans`);
  await owner.getByRole('row', { name: /acme\/e2e-app/ }).getByText(/Open Report/i).first().click();
  await owner.waitForURL(/\/scans\/[^/?]+/);
  await checkPage(owner, new URL(owner.url()).pathname, ['react-dropzone-truffle'], 'scan-report');
  await owner.goto(`${WEB}/endpoints`);
  const ep = owner.locator('a[href^="/endpoints/"]').first();
  if (await ep.count()) {
    const href = await ep.getAttribute('href');
    for (const tab of ['inventory', 'package-events', 'agent-events']) await checkPage(owner, `${href}?tab=${tab}`, null, `endpoint-${tab}`);
  } else fail('/endpoints/[id]', 'no endpoint row link');

  // Query page: run a real SQL query.
  await owner.goto(`${WEB}/query`);
  const runBtn = owner.getByRole('button', { name: /^Run/ }).first();
  await runBtn.click();
  await owner.waitForTimeout(2500);
  await owner.screenshot({ path: `${SHOTS}/query-run.png`, fullPage: true });
  const qb = await owner.locator('body').innerText();
  /error|denied/i.test(qb.slice(0, 50)) ? fail('query run', qb.slice(0, 200)) : ok('query run');

  // Preferences toggle round-trip.
  await owner.goto(`${WEB}/settings/preferences`);
  const sw = owner.getByRole('switch').first();
  const before = await sw.getAttribute('aria-checked');
  await sw.click();
  await owner.waitForTimeout(1500);
  await owner.reload();
  const after = await owner.getByRole('switch').first().getAttribute('aria-checked');
  before !== after ? ok('preferences persisted') : fail('preferences persisted', `${before} -> ${after}`);
  await owner.getByRole('switch').first().click(); // restore
} catch (e) {
  fail('flow', e.stack || String(e));
} finally {
  await browser.close();
  const f = results.filter((r) => r[0] === 'FAIL');
  console.log(`\n${results.length - f.length} passed, ${f.length} failed`);
  process.exit(f.length ? 1 : 0);
}
