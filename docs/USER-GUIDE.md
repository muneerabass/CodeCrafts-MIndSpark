# depguard user guide

depguard checks the open-source dependencies of your projects for known vulnerabilities, malware, suspicious
packages and license problems, shows how each risk reaches your code (attack paths), and stops risky packages
in pull requests and before they are installed.

Live deployment: **https://app.16-4-42-122.sslip.io** (dashboard) · **https://api.16-4-42-122.sslip.io** (API for the CLI, CI, MCP, GitHub)

| Tool | What it is for | Section |
|---|---|---|
| Dashboard (web app) | see projects, scans, reports, attack paths, policy, team | [2](#2-the-dashboard) |
| GitHub App | scan every pull request and push automatically, comment on PRs | [3](#3-github-app-automatic-pr-and-push-scans) |
| Policy | decide what blocks and what only warns | [4](#4-policy-what-blocks-and-what-warns) |
| `depguard` CLI | install guard, project check, full scans from a laptop or CI | [5](#5-the-depguard-cli) |
| CI integrations | GitHub Actions, GitLab CI, Bitbucket Pipelines | [6](#6-ci-pipelines) |
| AI agents (MCP + skill) | Claude Code, Cursor, VS Code, Windsurf, Gemini, Codex check packages before adding them | [7](#7-ai-coding-agents-mcp-server--skill) |
| Endpoint agent | inventory of AI tools on developer machines + install events | [8](#8-endpoint-agent) |
| Admin panel | platform administration (super-admins) | [9](#9-admin-panel-super-admins) |

---

## 1. Getting access

1. Open the dashboard and click **Continue with GitHub**.
2. depguard is invite-only. A team owner invites you under **Settings → Teams → Invite Team** (pending invites are under Settings → Invitations). You get an email,
   or the owner sends you the sign-in link. Sign in with GitHub **using the invited email address** and you land
   on the team's dashboard with the invited role.
3. Roles:
   | Role | Can |
   |---|---|
   | Member | read everything |
   | Admin | + API keys, policy, exclusions, scans, settings |
   | Owner | + members and invitations |
   | Super-admin (platform) | the Admin panel: all teams, GitHub installations, feeds, jobs |

---

## 2. The dashboard

| Page | What you see / do |
|---|---|
| **Dashboard** | KPIs (projects, components, vulnerabilities, transitive vulnerabilities, attack paths, suspicious, license issues), charts over time, top vulnerable projects |
| **Projects** | one row per repository/project; open one for tabs: **Components**, **Vulnerabilities**, **Violations**, **Scans**, **Attack Paths**, **Licenses** |
| **Attack Paths** tab | how each vulnerable package reaches your app: summary cards, severity filters, search, a graph of the riskiest chains (click a node or row to highlight it), every package with its paths and the fix |
| **Licenses** tab | project license and usage model (internal / SaaS / distributed binary / source), license distribution, conflicts and copyleft findings; you can override the project license |
| **Components** | every package across all projects; filter by direct/transitive, ecosystem |
| **Query** | read-only SQL over your data (`q_*` views), saved queries |
| **Scans** | every scan (PR, push, manual, CLI); **Scan a repository** starts one; **Open Report** shows the full report |
| **Scan report** | verdict banner, KPIs, charts, *Fix these first*, vulnerable packages with fixes, attack paths, suspicious packages, license issues, all packages; **Save as PDF** and **Download report** (Markdown, JSON, HTML) |
| **Package Analysis** | suspicious/malware analysis results (guarddog, typosquats); mark packages as verified malicious/safe |
| **Vulnerabilities** | every advisory affecting your projects; detail page shows EPSS/KEV, affected projects and how it reaches each app |
| **Policy Violations** | everything the policy flagged, filter by category/severity |
| **Endpoints** | developer machines: AI tools inventory, **Package Events** (install guard and PMG decisions), coding-agent activity |
| **Setup → Integrations** | step-by-step guides for every integration with your API URL filled in |
| **Settings** | General (team name), Teams (members, roles, **Invite Team**), Invitations (pending), **API Keys**, **Package Exclusions** (accepted risks), Preferences (**block mode**, draft PRs, quiet comments), Profile |

Theme: switch between *Cyber* (dark) and *Classic* in the sidebar footer. PDFs always print in the light theme.

---

## 3. GitHub App: automatic PR and push scans

1. **Setup → Integrations → GitHub App → Install**, or open
   `https://github.com/apps/depguard-coep/installations/new`. Choose the account/organization and
   *All repositories* or a selection.
2. The first time an account installs, a **super-admin links the installation to a team**:
   Admin panel → **Installations** → *Link* → choose the team. Later installs from the same account link automatically.
3. Repositories then appear on the dashboard. From then on:
   - every **pull request** that changes a lockfile gets a *depguard: Supply Chain Security* check run and one
     summary comment (updated on each push) listing new vulnerabilities, malware, suspicious and license issues,
     with "introduced via" chains and fixes; the check fails when the policy blocks;
   - every **push to the default branch** rescans the repository and refreshes the project;
   - **Scans → Scan a repository** scans any branch on demand.
4. Add or remove repositories later in GitHub: Settings → Applications → depguard-coep → Configure.

Supported lockfiles: npm (`package-lock.json`, `npm-shrinkwrap.json`), `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`,
Python (`requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock`), `go.mod`, Maven `pom.xml`,
Gradle lockfiles, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `pubspec.lock`, `mix.lock`, NuGet
`packages.lock.json`, GitHub Actions workflows.

### Pull Requests (review, urgency, labels, actions)

Every pull request of a connected repository is recorded and reviewed on each push:

- **Dependency review**: new or changed packages are checked for known vulnerabilities, malware (OSV feed, SafeDep
  malware analysis, guarddog behaviour analysis), license problems, suspicious packages and your package rules.
- **Code security review**: a rule-based review of the changed lines always runs (leaked secrets, SQL/command
  injection, eval, unsafe deserialization, disabled TLS checks, unverified JWTs, raw HTML, CORS `*`, weak hashing,
  risky GitHub Actions, `curl | sh`). When an AI model is configured, an **AI security review** of the diff adds
  findings with file and line (it runs on Amazon Bedrock; the default model is Qwen3 Coder 30B).
- **Urgency** (0–100, Critical/High/Medium/Low/Clean) ranks which PRs to fix first, with the top reasons.
- **Labels** on GitHub: `depguard:blocked`, `depguard:urgent`, `depguard:malware`, `depguard:vulnerable`,
  `depguard:security`, `depguard:secrets`, plus change type (`frontend`, `backend`, `ci`, `docs`, `tests`,
  `dependencies`, `infra`, `database`, `config`, `size/XS…XL`, AI labels such as `feature`, `bug-fix`). Labels
  without the prefix are never touched.
- **The PR comment**: status badges (Malware · Vulnerability · License · Suspicious · Code review), urgency, a
  *Review in depguard* button, *Fix before merging* with exact commands (`npm install lodash@4.17.21`, …), the code
  review, collapsible details, and a **Re-run depguard review** checkbox. It is edited on every push and says
  "All issues fixed" when the PR becomes clean.

Where to see them:

| Page | What it shows |
|---|---|
| **Pull Requests** (sidebar) | every open PR of the team, most urgent first; filter by urgency, state (open/merged/closed), project, author; search |
| **Project → Pull Requests** tab | the same for one repository |
| **PR page** | urgency and reasons, dependency checks, *Fix before merging* (copy commands), code review with links to the exact lines on GitHub, review history, activity |
| **Dashboard** | *Pull requests needing attention* (top 5) |

From the PR page, admins and owners can **post a comment** (Markdown with preview and templates), **request
changes**, **rescan**, or **re-run the AI review**; actions are posted to GitHub by the depguard app with your name.
To accept a risk, add a package exclusion (Settings → Package Exclusions) and rescan.

**Settings → Pull Requests**: when to comment (every PR / only with findings / never), which sections to include,
mention the author on blocking issues, request changes automatically on blocking issues (dismissed once fixed),
header/footer text, labels on/off and prefix, AI review on/off and the largest diff to review.

Existing open PRs are imported when a repository is connected, and everything is re-synced every 6 hours, so a
missed webhook never leaves a PR stale.

---

## 4. Policy: what blocks and what warns

**Policy** page (admins and owners edit, members read):

| Section | Controls |
|---|---|
| Vulnerability | minimum severity that is a violation (Critical / High+ / Medium+ / Any / Off) |
| Malware | block packages known as malicious (OSV `MAL-`, SafeDep analysis, your verified analyses) — always blocks |
| **Package & version rules** | per package: **Allowed versions** (e.g. `>=4.17.21 <5`, `<2 \|\| >=3.1`), **Banned**, or **Trusted** (skips suspicious/license checks, never vulnerability/malware). Severity high/critical blocks, medium/low warns |
| License | usage-aware license compliance, the severity that blocks, denied SPDX licenses |
| Suspicious | typosquats, unmaintained, deprecated, brand-new versions, no source repo, unusual behaviour; choose which ones block |
| Popularity / Maintenance | minimum stars, minimum OpenSSF Scorecard |
| Advanced | custom CEL rules (`pkg.name`, `vulns.critical`, `licenses`, `scorecard.score`, …) |

**Settings → Preferences → block mode**: on = blocking findings fail PR checks and stop installs; off = everything only
warns (malware still blocks installs). **Settings → Package Exclusions**: accept a known risk for a package
(optionally one version, optionally until a date); exclusions never hide malware.

The same policy applies everywhere: PR checks, repository scans, CLI scans and the install guard.

---

## 5. The `depguard` CLI

One small binary for Linux, macOS and Windows.

### 5.1 Install (pick one)

```sh
# any machine (puts depguard in /usr/local/bin or ~/.local/bin)
curl -fsSL https://app.16-4-42-122.sslip.io/install.sh | sh

# JavaScript project, as a dev dependency  →  run it with: npx depguard …
npm install --save-dev https://app.16-4-42-122.sslip.io/downloads/depguard-cli.tgz

# Python project / virtualenv
pip install --find-links https://app.16-4-42-122.sslip.io/downloads/pypi/ depguard-cli
```

If you installed it into a JavaScript project, prefix every command below with `npx` (`npx depguard check`).
Update: run the same install command again; `depguard version` prints the version.

### 5.2 Log in (once per machine)

1. Dashboard → **Settings → API Keys** → *Create API key* → copy the `dg_…` key (shown once).
2. `depguard login --api-key dg_…` (or just `depguard login` and paste it).
3. `depguard doctor` should show *logged in* and *API reachable*.

The key is stored only on your machine (`~/.config/depguard/credentials.json`, mode 600). Never commit it or paste
it into chats; if it leaks, delete it under API Keys and create a new one.

### 5.3 Check a project (nothing is installed or uploaded)

```sh
depguard check                 # every lockfile in the project, exit 1 if the policy blocks
depguard check --fail-on warn  # also fail on warnings
depguard check --json          # machine-readable
```

### 5.4 Full scan (saved to the dashboard with the full report)

```sh
depguard scan --project my-org/my-app --version main
depguard scan --project my-org/my-app --version main --format report          # full report in the terminal
depguard scan --project my-org/my-app --version main --report-out report.html  # also save .md/.json/.html
depguard scan --project my-org/my-app --version main --fail-on-violation       # exit 1 when blocked (CI)
```

Options: `--dir` (default `.`), `--project-license MIT`, `--usage-model internal|saas|distributed_binary|distributed_source`.
The scan appears under **Projects** and **Scans**, with attack paths, licenses and the PDF report.

Container images and SBOMs:

```sh
depguard scan --image ghcr.io/acme/api:1.4 --fail-on-violation   # needs syft on PATH
depguard scan --sbom image.cdx.json --project acme/api --version 1.4   # CycloneDX or SPDX JSON from any tool
```

`--image` reads the image with [syft](https://github.com/anchore/syft) (registry, local Docker or archive; the image
is never run). The project is the image name and the version its tag (source `container`). Language packages are
checked against advisories, malware and policy; OS packages (apk, deb) are listed but not checked.

### 5.5 Install guard: check every install before it happens

```sh
cd my-project
depguard init        # writes .depguard.yml (commit it) and installs the guard for this user
# open a new terminal
depguard doctor      # confirms the guard is active
```

From now on the normal commands are checked first:

```sh
npm install express          pnpm add vitest        yarn add react
pip install requests         uv add httpx           poetry add fastapi
go get golang.org/x/net      cargo add serde
```

What happens on each install:

1. depguard works out what the command **would** install, including transitive dependencies, in a temporary copy
   of the project with install scripts disabled (`npm --package-lock-only --ignore-scripts`, `pip --dry-run --report`,
   `go get` in a copy, `cargo metadata`, …).
2. It checks those packages against your team's policy and the repository rules.
3. It prints the verdict:
   - **✔ clean** → the install runs;
   - **▲ WARNING** → findings are shown, the install runs;
   - **✖ BLOCKED** → nothing is installed, exit code 1, with the fix (e.g. *upgrade to 4.17.21*) and how each
     package is pulled in (*via express*). Malware always blocks.
4. The decision is logged under **Endpoints → your machine → Package Events**.

Useful flags (put them before the tool name):

```sh
depguard --dry-run npm install lodash@4.17.15                      # check only, never installs
depguard --force --reason "fix tracked in JIRA-42" npm install x   # install despite a block (logged with the reason)
depguard --json npm install x                                      # print the verdict as JSON
```

`DEPGUARD_DISABLE=1 npm install` skips the guard for one command; `depguard setup shell --remove` uninstalls it.
How it works: `init` / `depguard setup shell` puts small `npm`, `pnpm`, `yarn`, `pip`, `pip3`, `uv`, `poetry`,
`go` and `cargo` wrappers in `~/.depguard/bin` at the front of your PATH, so installs from any terminal, IDE,
script or Makefile go through depguard, which then runs the real tool.

### 5.6 Repository rules: `.depguard.yml`

```yaml
project: my-org/my-app
fail_closed: false        # true = block installs when depguard cannot be reached
rules:                    # can only add to the team policy, never loosen it
  - { ecosystem: npm, name: lodash, versions: ">=4.17.21", reason: "prototype pollution fixes" }
  - { ecosystem: npm, name: moment, versions: "<3", severity: medium }   # medium/low = warn
  - { name: request, deny: true, reason: "deprecated, use undici" }
  - { ecosystem: pypi, name: django, versions: ">=4.2 <6" }
```

### 5.7 Command reference

| Command | Purpose |
|---|---|
| `depguard login` / `logout` | save / remove the API key on this machine |
| `depguard init [--project name] [--force] [--shell=false]` | link the project and install the guard |
| `depguard setup shell [--remove]` | install / remove the install guard for this user |
| `depguard doctor` | show login, API, project config and guard status |
| `depguard <tool> <args>` | guarded install (what the wrappers run) |
| `depguard check` | check the project's lockfiles |
| `depguard scan` | full scan saved to the dashboard |
| `depguard agent [--once]` | endpoint agent (section 8) |
| `depguard version` / `help` | version / help |

Environment: `DEPGUARD_API_URL`, `DEPGUARD_API_KEY` (override the saved login, e.g. in CI), `DEPGUARD_DISABLE=1`, `NO_COLOR=1`.

---

## 6. CI pipelines

Create an API key, store it as a secret named `DEPGUARD_API_KEY`, then add one step. **Setup → Integrations** shows
the exact snippet for GitHub Actions, GitLab CI and Bitbucket Pipelines. GitHub Actions:

```yaml
# .github/workflows/depguard.yml
name: depguard
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
          curl -fsSL https://app.16-4-42-122.sslip.io/install.sh | sh
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - name: Scan dependencies
        env:
          DEPGUARD_API_URL: https://api.16-4-42-122.sslip.io
          DEPGUARD_API_KEY: ${{ secrets.DEPGUARD_API_KEY }}
        run: depguard scan --source github --project "${{ github.repository }}" --version "${{ github.head_ref || github.ref_name }}" --fail-on-violation
```

Use `depguard check` instead of `scan` for a faster check that is not stored on the dashboard. Repositories that have
the GitHub App installed are already scanned on every PR without any CI step.

---

## 7. AI coding agents: MCP server + skill

One command connects every AI coding agent on the machine (Claude Code, Cursor, VS Code Copilot, Windsurf, Gemini CLI,
Codex) to depguard, so agents check each package before installing it:

```sh
curl -fsSL https://app.16-4-42-122.sslip.io/install.sh | sh
depguard login --api-key dg_your_key
depguard setup agents          # --print shows the config for other clients, --remove undoes it
```

It adds the depguard MCP server (`https://api.16-4-42-122.sslip.io/mcp`, header `Authorization: Bearer dg_…`) to each
agent's config and installs the depguard skill (`~/.claude/skills/depguard`, `~/.codex/skills/depguard`). Config files
with comments are never rewritten; the command tells you to add the server by hand instead.

Tools:
- `check_packages`: allow / warn / block per package from your team policy, the reasons and a safer version. Omit the
  version to check the latest release; names that do not exist in the registry (typos, hallucinated packages) are blocked.
- `get_package_vulnerabilities`, `get_malware_verdict`, `get_license_info`, `get_package_scorecard`.

The server's instructions tell every agent to call `check_packages` before installing; the skill
(`https://api.16-4-42-122.sslip.io/agent/SKILL.md`) makes skill-aware agents do it reliably and falls back to
`depguard --dry-run npm install x` when MCP is not connected. Per-client JSON is in **Setup → AI agents**.

---

## 8. Endpoint agent

Reports the AI coding tools, MCP servers, agent skills and IDE extensions on a machine, ships PMG install events and
gryph coding-agent activity. Results: **Endpoints**.

```sh
depguard login --api-key dg_…   # once
depguard agent                  # runs every 5 minutes; --once for a single sync (e.g. at the end of a CI job)
```

Setup → AI Tools Discovery has a systemd user unit to run it in the background. Install-guard decisions are reported
by the CLI itself; the agent is not needed for them.

---

## 9. Admin panel (super-admins)

`/admin` (visible to platform super-admins only):

| Page | Use it to |
|---|---|
| Tenants (`/admin`) | create teams, change plan, disable/enable a team |
| Installations | **link GitHub App installations to teams** (needed once per new GitHub account), unlink |
| Health | feed sync (OSV, KEV, EPSS; stale after 24 h), failed jobs, GitHub webhook deliveries (redeliver) |
| River | background job queue UI |

---

## 10. Typical end-to-end flows

**New team member**
1. Owner: Settings → Teams → Invite Team → email + role. 2. Member: sign in with GitHub using that email.
3. Member: install the CLI, `depguard login`, `depguard init` in each project.

**New repository**
1. Install the GitHub App on it (or it is already covered by *All repositories*).
2. First time for that GitHub account: super-admin links the installation.
3. Open a PR → depguard check + comment; merge → project refreshed; Projects → Attack Paths / Licenses.

**Fixing what a scan found**
1. Scans → Open Report → *Fix these first* (or the project's Attack Paths tab).
2. Upgrade the package named in the fix (or the direct dependency it comes through).
3. Push → automatic rescan; accepted risks go to Settings → Package Exclusions with a reason and expiry.

**Locking down a dependency**
Policy → Package & version rules → e.g. `lodash` allowed versions `>=4.17.21` → enforced on the next PR scan and on
every install on every machine with the guard.

---

## 11. Troubleshooting

| Symptom | Fix |
|---|---|
| `depguard: command not found` after `npm i -D …` | use `npx depguard …`, or install globally with the `install.sh` line |
| `not logged in` | `depguard login --api-key dg_…` (create the key under Settings → API Keys) |
| installs are not checked | open a new terminal after `depguard init`; run `depguard doctor` |
| `nothing new to install` | the package is already in your lockfile; `depguard check` reviews the whole project |
| a harmless old package is blocked | your policy blocks that rule (e.g. *unmaintained*); change it on the Policy page or add an exclusion |
| repositories missing after installing the GitHub App | the installation is *pending*: a super-admin links it under Admin → Installations |
| attack paths marked *approximate* | the lockfile has no dependency graph; chains come from deps.dev. Rescan after updating the lockfile |
| GitHub login loops back to sign-in | Supabase → Authentication → URL Configuration must list `<dashboard URL>/auth/callback` |
| AI review shows "delayed" | the Bedrock account hit its daily token quota; it retries automatically, the rule-based review is complete. Ask AWS for a higher Bedrock quota |
| "Request changes" or label actions fail | grant the GitHub App **Pull requests: Read and write** and accept the new permissions on each installation |
| invitation email not received | send the sign-in link shown in the invite dialog; the invitee signs in with the invited email |

---

## 12. Operating the deployment

- Server: AWS EC2 (Amazon Linux 2023), native systemd services `depguard-api`, `depguard-worker`, `depguard-web`,
  `caddy` (HTTPS), PostgreSQL 17 on the `/data` disk; nightly database backup timer.
- Configuration: `/etc/depguard/deploy.conf` (hosts, GitHub App, Supabase, SMTP) → rendered into
  `/etc/depguard/{depguard,web,caddy}.env`. Never commit these files.
- Deploy / update: copy the repository to `/data/src/depguard` and run `sudo bash deploy/native/install.sh`
  (idempotent: builds Go, the web app and the CLI downloads, runs migrations, restarts services). See
  `docs/DEPLOY.md`.
- Logs: `journalctl -u depguard-api -u depguard-worker -u depguard-web -f`.
- Local development: `docs/TESTING.md`, `scripts/run-dev.sh`. CLI internals: `docs/CLI.md`. Risk model and
  scoring: `docs/RISK-MODEL.md`. API contracts: `docs/CONTRACTS.md`.
