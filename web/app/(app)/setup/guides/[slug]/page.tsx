import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ExternalLink, KeyRound } from 'lucide-react';
import { api } from '@/lib/api';
import { publicUrl } from '@/lib/auth';
import { requireOrg } from '@/lib/session';
import type { Integrations, Settings } from '@/lib/types';
import { PageHeader } from '@/components/page';
import { CopyButton } from '@/components/client';
import { Button } from '@/components/ui/button';
import { guides, IconTile } from '../../catalog';

type Step = { title: string; body?: React.ReactNode; code?: string; file?: string };

// The CLI is served by this deployment (packaging/build.sh); install.sh picks the binary for the OS.
const installCmd = (appUrl: string) => `curl -fsSL ${appUrl}/install.sh | sh`;

function Code({ code, file }: { code: string; file?: string }) {
  return (
    <div className="mt-3 overflow-hidden rounded-lg border bg-muted/50">
      <div className="flex items-center justify-between border-b bg-muted px-3 py-1 text-xs text-muted-foreground">
        <span className="font-mono">{file ?? 'shell'}</span>
        <CopyButton value={code} />
      </div>
      <pre className="overflow-x-auto p-3 text-[13px] leading-5">
        <code className="font-mono">{code}</code>
      </pre>
    </div>
  );
}

const keyNote = (
  <>
    Create a key under{' '}
    <Link href="/settings/api-keys" className="text-primary underline">
      Settings → API Keys
    </Link>
    . It is shown once — store it as a secret, never commit it.
  </>
);

function stepsFor(slug: string, apiUrl: string, mcpUrl: string, s: Settings, installUrl: string, appUrl: string): Step[] {
  const install = installCmd(appUrl);
  switch (slug) {
    case 'github-app':
      return [
        { title: 'Install the app on your GitHub organization', body: <>Open the install page, pick the organization and choose all repositories or a selection. <a className="text-primary underline" href={installUrl} target="_blank" rel="noreferrer">Open the GitHub App install page</a>.</> },
        { title: 'Wait for the link to your tenant', body: <>If this organization is not yet linked to <b>{s.domain}</b>, the installation stays <i>pending</i> and nothing is scanned. Ask your platform administrator to link it (they will see it under Admin → GitHub installations).</> },
        { title: 'Open a pull request', body: 'Every pull request that changes a lockfile gets a "depguard: Supply Chain Security" check run and one summary comment that is updated on each push. Pushes to the default branch refresh the project inventory.' },
        { title: 'Scan existing repositories', body: <>Use <b>Scan repositories</b> on the Integrations page (or <b>Scan a repository</b> on Projects) to run a full scan right away.</> },
        { title: 'Tune behaviour', body: <>Choose block or warn mode, draft PR scanning and clean-scan comments in <Link className="text-primary underline" href="/settings/preferences">Preferences</Link>, and edit rules in <Link className="text-primary underline" href="/policy">Policy</Link>.</> },
      ];
    case 'github-actions':
      return [
        { title: 'Create an API key', body: keyNote },
        { title: 'Add it as a repository secret', body: 'In GitHub: Settings → Secrets and variables → Actions → New repository secret, named DEPGUARD_API_KEY.' },
        {
          title: 'Add the workflow',
          file: '.github/workflows/depguard.yml',
          code: `name: depguard
on:
  pull_request:
  push:
    branches: [main]

jobs:
  depguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install depguard
        run: |
          ${install}
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Scan dependencies
        env:
          DEPGUARD_API_URL: ${apiUrl}
          DEPGUARD_API_KEY: \${{ secrets.DEPGUARD_API_KEY }}
        run: |
          depguard scan --source github \\
            --project "\${{ github.repository }}" \\
            --version "\${{ github.head_ref || github.ref_name }}" \\
            --fail-on-violation`,
        },
        { title: 'Check the results', body: 'The job fails when a dependency breaks your policy, and the scan appears under Scans and Projects.' },
      ];
    case 'gitlab-ci':
      return [
        { title: 'Create an API key', body: keyNote },
        { title: 'Store it as a CI/CD variable', body: 'Settings → CI/CD → Variables: add DEPGUARD_API_KEY, masked and protected.' },
        {
          title: 'Add a job to your pipeline',
          file: '.gitlab-ci.yml',
          code: `depguard:
  stage: test
  image: alpine:3.20
  variables:
    DEPGUARD_API_URL: "${apiUrl}"
  script:
    - apk add --no-cache curl
    - ${install}
    - depguard scan --source gitlab --project "$CI_PROJECT_PATH" --version "$CI_COMMIT_REF_NAME" --fail-on-violation
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`,
        },
      ];
    case 'bitbucket-pipes':
      return [
        { title: 'Create an API key', body: keyNote },
        { title: 'Add a secured repository variable', body: 'Repository settings → Pipelines → Repository variables: DEPGUARD_API_KEY (secured).' },
        {
          title: 'Add a step to your pipeline',
          file: 'bitbucket-pipelines.yml',
          code: `definitions:
  steps:
    - step: &depguard
        name: depguard scan
        image: alpine:3.20
        script:
          - export DEPGUARD_API_URL="${apiUrl}"
          - apk add --no-cache curl
          - ${install}
          - depguard scan --source bitbucket --project "$BITBUCKET_REPO_FULL_NAME" --version "$BITBUCKET_BRANCH" --fail-on-violation

pipelines:
  pull-requests:
    '**':
      - step: *depguard
  branches:
    main:
      - step: *depguard`,
        },
      ];
    case 'install-guard': {
      const dl = `${appUrl}/downloads`;
      return [
        {
          title: 'Install the depguard CLI',
          body: 'One small binary for Linux, macOS and Windows. Pick whichever fits the project; all install the same CLI.',
          code: `# any machine\ncurl -fsSL ${appUrl}/install.sh | sh\n\n# as a dev dependency of a JavaScript project\nnpm install --save-dev ${dl}/depguard-cli.tgz\n\n# Python projects\npip install --find-links ${dl}/pypi/ depguard-cli`,
        },
        { title: 'Log in', body: <>Connects this machine to <b>{s.domain}</b>. {keyNote}</>, code: `depguard login --api-url ${apiUrl} --api-key dg_your_key_here` },
        {
          title: 'Link the project and guard installs',
          body: 'Run in the repository root. It writes .depguard.yml (commit it) and puts small shims for npm, pnpm, yarn, pip, uv, poetry, go and cargo first on your PATH, so every install is checked: typed commands, IDE terminals, scripts and Makefiles.',
          code: 'depguard init\n# open a new terminal, then check the setup\ndepguard doctor',
        },
        {
          title: 'Install as usual',
          body: 'depguard works out what the install would bring in (direct and transitive) without running install scripts, checks it against your policy and then runs the real command. Blocking findings stop the install; warnings are shown and the install continues. Malware always blocks.',
          code: 'npm install express\npip install requests\ngo get golang.org/x/net\ncargo add serde\n\n# install anyway (logged on the dashboard with the reason)\ndepguard --force --reason "fix tracked in JIRA-42" npm install lodash@4.17.15',
        },
        {
          title: 'Add project rules (optional)',
          body: <>Team rules live on the <Link className="text-primary underline" href="/policy">Policy</Link> page (Package &amp; version rules). A repository can add stricter rules in .depguard.yml; it can never loosen team policy.</>,
          file: '.depguard.yml',
          code: 'project: my-org/my-app\nfail_closed: false   # true = block installs when depguard is unreachable\nrules:\n  - { ecosystem: npm, name: lodash, versions: ">=4.17.21", reason: "prototype pollution fixes" }\n  - { name: request, deny: true, reason: "deprecated, use undici" }\n  - { ecosystem: pypi, name: django, versions: ">=4.2 <6", severity: medium }',
        },
        { title: 'In CI', body: 'Check the committed lockfiles on every build; the job fails when a dependency is blocked.', code: `export DEPGUARD_API_URL=${apiUrl}\nexport DEPGUARD_API_KEY=\${{ secrets.DEPGUARD_API_KEY }}\ndepguard check` },
        { title: 'See every decision', body: <>Allowed, warned, blocked and forced installs appear per machine under <Link className="text-primary underline" href="/endpoints">Endpoints</Link> → Package Events.</> },
      ];
    }
    case 'cli':
      return [
        { title: 'Install the CLI', code: install },
        { title: 'Point it at your tenant', body: <>Results go to <b>{s.domain}</b>. {keyNote}</>, code: `export DEPGUARD_API_URL=${apiUrl}\nexport DEPGUARD_API_KEY=dg_your_key_here` },
        { title: 'Scan a project', body: 'Run it from the repository root. Supported lockfiles are found automatically; the exit code is non-zero when the policy fails.', code: 'depguard scan --project my-org/my-app --version main --fail-on-violation .' },
        { title: 'Open the report', body: 'The command prints a link to the scan report. You can also find it under Scans.' },
      ];
    case 'pmg':
      return [
        { title: 'Install Package Manager Guard (PMG)', body: 'PMG is an open-source (Apache-2.0) wrapper that checks packages before your package manager installs them.', code: 'brew install safedep/tap/pmg\n# or\ngo install github.com/safedep/pmg@latest' },
        { title: 'Install through PMG', code: 'pmg npm install express\npmg pip install requests\n\n# optional: always route installs through PMG\nalias npm="pmg npm"\nalias pip="pmg pip"' },
        { title: 'Ship PMG events to depguard', body: <>The depguard agent tails PMG&apos;s daily event log and reports allowed and blocked installs under Endpoints → Package Events. {keyNote}</>, code: `${install}\nexport DEPGUARD_API_URL=${apiUrl}\nexport DEPGUARD_API_KEY=dg_your_key_here\ndepguard agent` },
        { title: 'In CI', body: 'Use the same commands on CI runners; prefix install steps with pmg and run the agent once at the end of the job with --once.', code: 'pmg npm ci\ndepguard agent --once' },
      ];
    case 'mcp':
      return [
        { title: 'Create an API key', body: keyNote },
        {
          title: 'Add the server to your MCP client',
          body: 'Most clients (Claude Desktop, Cursor, VS Code) accept this JSON. Tools: get_package_vulnerabilities, get_malware_verdict, get_license_info, get_package_scorecard.',
          file: 'mcp.json',
          code: JSON.stringify({ mcpServers: { depguard: { type: 'http', url: `${mcpUrl}`, headers: { Authorization: 'Bearer dg_your_key_here' } } } }, null, 2),
        },
        { title: 'Claude Code', code: `claude mcp add --transport http depguard ${mcpUrl} \\\n  --header "Authorization: Bearer dg_your_key_here"` },
        { title: 'Ask your agent to check packages', body: 'For example: "Before adding a dependency, check it with depguard for malware and known vulnerabilities."' },
      ];
    case 'ai-tools':
      return [
        { title: 'Install the depguard agent on each machine', code: install },
        { title: 'Configure and start it', body: <>The agent checks in every few minutes and reports coding agents, MCP servers, agent skills and IDE extensions it finds. {keyNote}</>, code: `export DEPGUARD_API_URL=${apiUrl}\nexport DEPGUARD_API_KEY=dg_your_key_here\ndepguard agent` },
        {
          title: 'Run it as a service (Linux, systemd user unit)',
          file: '~/.config/systemd/user/depguard-agent.service',
          code: `[Unit]
Description=depguard endpoint agent

[Service]
Environment=DEPGUARD_API_URL=${apiUrl}
Environment=DEPGUARD_API_KEY=dg_your_key_here
ExecStart=%h/.local/bin/depguard agent
Restart=on-failure

[Install]
WantedBy=default.target`,
        },
        { title: 'Enable the service', code: 'systemctl --user daemon-reload\nsystemctl --user enable --now depguard-agent' },
        { title: 'See it under Endpoints', body: <>The machine appears on the <Link className="text-primary underline" href="/endpoints">Endpoints</Link> page with its inventory and activity.</> },
      ];
  }
  return [];
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }) {
  const g = guides[(await params).slug];
  return { title: g ? `${g.title} setup` : 'Setup guide' };
}

export default async function GuidePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const g = guides[slug];
  if (!g) notFound();
  await requireOrg();
  const [settings, integrations] = await Promise.all([
    api<Settings>('/settings'),
    api<Integrations>('/integrations'),
  ]);
  const apiUrl = (integrations.api_url || process.env.PUBLIC_API_URL || 'http://localhost:8080').replace(/\/$/, '');
  const mcpUrl = integrations.mcp_url || `${apiUrl}/mcp`;
  const steps = stepsFor(slug, apiUrl, mcpUrl, settings, integrations.github.install_url || '#', publicUrl.replace(/\/$/, ''));

  return (
    <>
      <PageHeader crumbs={[{ label: 'Setup', href: '/setup' }, { label: 'Integrations', href: '/setup/integrations' }, { label: g.title }]} actions={null} />
      <div className="mx-auto w-full max-w-3xl px-4 py-8">
        <div className="flex items-start gap-4">
          <IconTile Icon={g.Icon} />
          <div>
            <h1 className="text-2xl font-semibold">{g.title}</h1>
            <p className="mt-1 text-sm text-muted-foreground">{g.desc}</p>
          </div>
        </div>
        <ol className="mt-8 flex flex-col gap-6">
          {steps.map((st, i) => (
            <li key={i} className="flex gap-4">
              <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-accent text-sm font-semibold text-primary" aria-hidden>
                {i + 1}
              </span>
              <div className="min-w-0 flex-1">
                <h2 className="font-medium">{st.title}</h2>
                {st.body && <p className="mt-1 text-sm text-muted-foreground">{st.body}</p>}
                {st.code && <Code code={st.code} file={st.file} />}
              </div>
            </li>
          ))}
        </ol>
        <div className="mt-10 flex flex-wrap gap-2 border-t pt-6">
          {slug === 'github-app' && integrations && (
            <Button asChild>
              <a href={integrations.github.install_url} target="_blank" rel="noreferrer">
                Install GitHub App <ExternalLink aria-hidden />
              </a>
            </Button>
          )}
          {slug !== 'github-app' && (
            <Button asChild variant="outline">
              <Link href="/settings/api-keys">
                <KeyRound /> Manage API keys
              </Link>
            </Button>
          )}
          <Button asChild variant="ghost">
            <Link href="/setup/integrations">All integrations</Link>
          </Button>
        </div>
      </div>
    </>
  );
}
