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
| `depguard init` | writes `.depguard.yml` (project, ecosystems, repo rules; never the API URL) and runs `setup shell` |
| `depguard setup shell [--remove]` | PATH shims in `~/.depguard/bin` for each of npm, npx, pnpm, yarn, pip, pip3, uv, uvx, poetry, go, cargo found on PATH (run it again after installing a tool; shims of tools no longer present are removed) + a marked block in `.bashrc`/`.zshrc`/`.profile`/fish/PowerShell |
| `depguard doctor` | login, API reachability, project config, shims on PATH, real tool locations, tools whose PATH lookup bypasses the shim |
| `depguard [--force --reason r] [--dry-run] [--json] <tool> <args…>` | guarded install (what the shims run) |
| `depguard check [--fail-on block\|warn\|never]` | checks the committed lockfiles (CI, git hooks) |
| `depguard scan`, `depguard agent` | full scan upload; endpoint agent (unchanged) |

Credentials: flags > `DEPGUARD_API_URL`/`DEPGUARD_API_KEY` > saved login > build default. An `api_url` in a
repository's `.depguard.yml` is never used to send the key anywhere: it is ignored (with a warning) unless it equals the
saved or env URL. `.depguard.yml` is looked up from the current directory upwards, stopping at the git root or `$HOME`.
`DEPGUARD_DISABLE=1` skips checks; `NO_COLOR` disables colour.

The shims export `DEPGUARD_SHIM_DEPTH` (incremented per shim); depguard refuses to run at depth 3 so a wrapper that
calls the shim again cannot loop. When looking for the real tool, depguard skips the shim directory (compared with
`os.SameFile`, so symlinked paths are caught too), its own binary and any file starting with the shim marker.

## How an install is checked

1. **Classify** the command (`commands.go`); only commands that add or change dependencies are checked, everything
   else runs untouched. The subcommand is the first positional argument that is a known subcommand (so
   `pip --proxy http://p install x` and `npm --loglevel silent install x` are installs); values of known flags
   (`--with dev`, `--cache dir`, `-j 4`, cargo `+nightly`, …) are never package specs. `--help`/`-h`/`--version` (and
   `-v` for npm/pnpm/yarn, `-V` for the others) mean "not an install". Checked: npm/pnpm/yarn install/add/update/ci,
   bare `yarn`; `pip install`; `uv add|sync|lock`, `uv pip install|sync`; `poetry add|install|update|lock`;
   `go get`, `go install pkg@version`, `go mod tidy|download`; `cargo add|install|update|fetch|generate-lockfile`.
   `go build/test/run/vet/generate` and `cargo build/run/test/check/clippy/bench/doc` are not installs.
   Fetch-and-run commands are checked too: `npx <pkg>`, `npm exec <pkg>`, `pnpm dlx <pkg>`, `yarn dlx <pkg>`,
   `uvx <pkg>` (and `uv tool run|install`): the named package (`--package`/`--from`/`--with` included) at the exact
   version given, else the registry's latest (`registry.npmjs.org/<name>/latest`, `pypi.org/pypi/<name>/json`);
   `npx` of a binary already in the project's `node_modules/.bin` is not checked again.
   Only checked installs run with `DEPGUARD_ACTIVE=1`, so their lifecycle scripts are not checked twice; `npm run`,
   `npx` and other pass-through commands do not get it.
2. **Resolve** what would be installed in a temporary copy of the manifest/lockfile, with install scripts disabled:

   | Tool | Resolution | Sent to the API |
   |---|---|---|
   | npm | `npm install … --package-lock-only --ignore-scripts` | before/after `package-lock.json` + `package.json` |
   | pnpm | `pnpm … --lockfile-only --ignore-scripts` | before/after `pnpm-lock.yaml` |
   | yarn 2+ | `yarn add … --mode update-lockfile` (scripts off) in a copy with `.yarnrc.yml` and `.yarn/releases` | before/after `yarn.lock` |
   | yarn 1 | `yarn install` with a lockfile: the lockfile as is; `yarn add`: resolved with npm (approximate) | packages not already in `yarn.lock` |
   | pip | `pip install --dry-run --ignore-installed --only-binary=:all: --report` (pip ≥ 22.2) | package list (`requested` = direct) |
   | uv | `uv add … --no-sync --no-build` / `uv lock --no-build [-U/--upgrade-package]`; `uv sync --frozen/--locked`: `uv.lock` as is; `uv pip install … --dry-run --no-build` | `uv.lock` or package list |
   | poetry | `poetry add … --lock` / `poetry update … --lock` / `poetry lock`; `poetry install` with a lock: the lock as is | `poetry.lock` |
   | go | copy of go.mod (relative `replace` paths made absolute) + go.sum; `go get …` there (Go runs no code while fetching), then `go list -m -json all`; `go mod tidy/download`: the module graph of the copy | new modules (direct = not `// indirect`) |
   | cargo | `cargo add/update/generate-lockfile …` + `cargo metadata` in the copy (no build scripts); `cargo install <crate> [--version X]`: the crate from crates.io | `Cargo.lock` or the crate |

   Resolution never runs package code and never touches the real project: npm/pnpm/yarn workspaces are copied as the
   root manifests plus every member `package.json` matching `workspaces`/`pnpm-workspace.yaml` (run in the member's
   copy), Cargo workspaces as the root `Cargo.toml`/`Cargo.lock` plus member manifests with empty targets, and
   absolute `--prefix`, `-C`, `--dir`, `--cwd`, `--manifest-path`, `--directory`, `--project`, `-modfile` values are
   dropped from the resolution run. Python packages that exist only as source distributions would have to be built
   (their code run) to resolve: depguard reports "cannot resolve without building packages" and checks the exact
   versions named on the command line instead (poetry cannot be told not to build; a build failure in the copy is
   handled the same way).

   Commands that name packages check only what is new compared with the current lockfile; plain installs
   (`npm install`, `npm ci`, `uv sync`, `go mod tidy`, …) check the whole tree. A clean result is cached for 12 hours
   in `<config dir>/depguard/guard-state.json`, keyed by the API URL, the API key (hash), the repo rules (hash) and the
   resolution, and reused only while `policy_version` from `GET /v1/me` is unchanged (fetched once per run, 5 s
   timeout, only when an entry exists or a clean result is stored; any error is a cache miss). `depguard login`
   clears the cache. When the package manager says the package or version does not exist the install stops with its
   error; any other resolution failure falls back to checking the exact versions named on the command line
   ("partial check") — or stops the install when `fail_closed: true`.
3. **Check** with `POST /v1/packages/check` (below), adding the repo rules from `.depguard.yml`.
4. **Decide**: `block` → exit 1 (nothing installed); `warn`/`allow` → the real tool runs: on Linux/macOS depguard
   `exec`s it (exact exit code, signals and terminal), on Windows it runs it as a child and ignores Ctrl-C itself.
   `--force` installs anyway and is logged as an override with its reason. If the API is unreachable (30 s timeout)
   or the install cannot be resolved, it proceeds with a warning, unless `fail_closed: true` in `.depguard.yml`.
5. **Log** the decision as package-guard events (`guard.allow|warn|block|override`, plus `guard.package.*` per
   flagged package) on the machine's endpoint before the tool runs (at most 5 s); they appear under
   Endpoints → Package Events.

### Limits

- Shims work through PATH order. Version managers (nvm, pyenv, mise, volta, asdf) that put their own directories
  first can bypass them; run `depguard doctor` after installing or switching one (it flags each tool whose PATH
  lookup does not reach the shim) and `depguard setup shell` after installing a new package manager.
- `python -m pip`, `pipx`, `npm init <pkg>`/`npm create`, `uv run --with` and package managers called by absolute
  path are not intercepted.

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

`GET /v1/me` → `{tenant_id, domain, block_mode, api_key_id, policy_version, policy: {vulnerability_min_risk, malware, package_rules, custom_rules}}`
(`policy_version` changes whenever the team policy or block mode changes; the CLI cache depends on it).

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
