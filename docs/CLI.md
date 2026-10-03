# depguard CLI and install guard

One pure-Go binary (`cmd/depguard`, no cgo) for Linux, macOS and Windows.

## Install

| Where | Command |
|---|---|
| Any machine | `curl -fsSL https://<app host>/install.sh \| sh` |
| JavaScript project (dev dependency) | `npm install --save-dev https://<app host>/downloads/depguard-cli.tgz` then `npx depguard …` |
| Python project | `pip install --find-links https://<app host>/downloads/pypi/ depguard-cli` |
| From source | `go build -o depguard ./cmd/depguard` in this repository |

`packaging/build.sh` builds all of them into `dist/downloads/` (6 platform binaries, the npm tarball with a
small launcher, one wheel per platform plus an `index.html` for `--find-links`, and `install.sh`).
The native deploy runs it on every install and Caddy serves `/install.sh` and `/downloads/*` from the app host.
`DEPGUARD_API_URL` is baked in as the default API, so `depguard login` only needs the key.

## Commands

| Command | What it does |
|---|---|
| `depguard login [--api-url] [--api-key]` | verifies the key (`GET /v1/me`), stores it in `<config dir>/depguard/credentials.json` (0600) |
| `depguard init` | writes `.depguard.yml` (project, ecosystems, repo rules) and runs `setup shell` |
| `depguard setup shell [--remove]` | PATH shims for npm, pnpm, yarn, pip, pip3, uv, poetry, go, cargo in `~/.depguard/bin` + a marked block in `.bashrc`/`.zshrc`/`.profile`/fish/PowerShell |
| `depguard doctor` | login, API reachability, project config, shims on PATH, real tool locations |
| `depguard [--force --reason r] [--dry-run] [--json] <tool> <args…>` | guarded install (what the shims run) |
| `depguard check [--fail-on block\|warn\|never]` | checks the committed lockfiles (CI, git hooks) |
| `depguard scan`, `depguard agent` | full scan upload; endpoint agent (unchanged) |

Credentials: flags > `DEPGUARD_API_URL`/`DEPGUARD_API_KEY` > `.depguard.yml` `api_url` > saved login > build default.
`DEPGUARD_DISABLE=1` skips checks; `NO_COLOR` disables colour.

## How an install is checked

1. **Classify** the command (`commands.go`); only commands that add or change dependencies are checked, everything
   else runs untouched. Nested calls (lifecycle scripts) carry `DEPGUARD_ACTIVE=1` and are not checked twice.
2. **Resolve** what would be installed in a temporary copy of the manifest/lockfile, with install scripts disabled:

   | Tool | Resolution | Sent to the API |
   |---|---|---|
   | npm | `npm install … --package-lock-only --ignore-scripts` | before/after `package-lock.json` + `package.json` |
   | pnpm | `pnpm … --lockfile-only --ignore-scripts` | before/after `pnpm-lock.yaml` |
   | yarn | `yarn install` with a lockfile: the lockfile as is; `yarn add`: resolved with npm (approximate) | lockfile |
   | pip | `pip install --dry-run --ignore-installed --report` (pip ≥ 22.2) | package list (`requested` = direct) |
   | uv | `uv add … --no-sync` / `uv lock` in the copy; `uv pip install … --dry-run` | `uv.lock` or package list |
   | poetry | `poetry add … --lock` / `poetry lock`; `poetry install` with a lock: the lock as is | `poetry.lock` |
   | go | `go get …` in a copy of go.mod/go.sum (Go runs no code while fetching), then `go list -m -json all` | new modules (direct = not `// indirect`) |
   | cargo | `cargo add …` + `cargo metadata` in the copy (no build scripts); `cargo install <crate>`: the crate from crates.io | `Cargo.lock` or the crate |

   Commands that name packages check only what is new compared with the current lockfile; plain installs
   (`npm install`, `npm ci`, `uv sync`, `go build`, …) check the whole tree. A clean result for an unchanged
   resolution is cached for 24 hours. When the package manager says the package or version does not exist the
   install stops with its error; any other resolution failure falls back to checking the exact versions named
   on the command line ("partial check").
3. **Check** with `POST /v1/packages/check` (below), adding the repo rules from `.depguard.yml`.
4. **Decide**: `block` → exit 1 (nothing installed); `warn`/`allow` → the real tool runs with the terminal attached.
   `--force` installs anyway and is logged as an override with its reason. If the API is unreachable the install
   proceeds with a warning, unless `fail_closed: true` in `.depguard.yml`.
5. **Log** the decision as package-guard events (`guard.allow|warn|block|override`, plus `guard.package.*` per
   flagged package) on the machine's endpoint; they appear under Endpoints → Package Events.

## API

`POST /v1/packages/check` (API key):

```json
{ "packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.15", "direct": true}],
  "before": [{"path": "package-lock.json", "content": "…"}],
  "after":  [{"path": "package-lock.json", "content": "…"}],
  "manifests": [{"path": "package.json", "content": "…"}],
  "repo_rules": [{"ecosystem": "npm", "name": "left-pad", "deny": true, "severity": "medium"}] }
```

Lockfiles are parsed with vet; with `after`, only packages added or changed relative to `before` are checked,
`manifests` mark direct dependencies and the project's own package is skipped. The pipeline is the scan pipeline
without persistence: OSV vulnerabilities and `MAL-` malware from the local mirror, CEL policy, suspicious and
license checkers, package rules (team + repo), exclusions (never for malware), plus SafeDep's community malware
analysis (`internal/malysis`, cached 24 h in `malysis_verdict`; verified → block, unverified → high).
Advisories below the policy threshold are returned as non-blocking `known-vulnerability` findings.
Per package: `block` if malware, or a blocking finding while block mode is on; `warn` for any other finding.

```json
{ "decision": "block", "block_mode": true, "checked": 69,
  "packages": [{ "ecosystem": "npm", "name": "path-to-regexp", "version": "0.1.12", "direct": false,
                 "via": ["express@4.21.2", "path-to-regexp@0.1.12"], "decision": "block",
                 "findings": [{ "rule": "vulnerability-high-or-higher", "category": "vulnerability", "severity": "high",
                                "blocking": true, "summary": "…", "fixed_in": "0.1.13" }] }] }
```

`GET /v1/me` → `{tenant_id, domain, block_mode, api_key_id, policy: {vulnerability_min_risk, malware, package_rules, custom_rules}}`.

## Package & version rules

Team rules: `presets.packages` in the policy (Policy page → Package & version rules). Repo rules: `rules` in
`.depguard.yml`, same shape; they only add findings.

```yaml
rules:
  - { ecosystem: npm, name: lodash, versions: ">=4.17.21", reason: "prototype pollution fixes" }
  - { ecosystem: npm, name: "@types/*", allow: true }          # trusted: no suspicious/license findings
  - { name: request, deny: true, reason: "deprecated" }        # banned in every version and ecosystem
  - { ecosystem: pypi, name: django, versions: ">=4.2 <6", severity: medium }   # medium/low warn, high/critical block
```

`versions` is an allowed range: comparisons `>= > <= < = !=` joined by spaces or commas, alternatives with `||`,
compared in the ecosystem's own version scheme (npm semver, PEP 440, Go with or without `v`, crates.io). Names
compare case-insensitively (PyPI also treats `-_.` alike) and `*` is a wildcard. Rules are enforced by
`internal/pkgrules` as a scan checker on PR, repository and upload scans too (category `policy`, rules
`package-denied` and `version-not-allowed`).
