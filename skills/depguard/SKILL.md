---
name: depguard
description: Checks open source packages with depguard before they are installed, added or upgraded (npm, pnpm, yarn, bun, pip, uv, poetry, go get, cargo, gem, composer, maven, nuget), answers "is this package safe?", and runs commands that need the project's secrets without exposing them. Use whenever you are about to run an install command, add a dependency to a manifest (package.json, requirements.txt, pyproject.toml, go.mod, Cargo.toml, Gemfile, pom.xml), bump a version, when the user asks about a package's vulnerabilities, malware, license or health, or when a command needs API keys, database URLs or .env files.
---

# depguard: check dependencies before you add them

depguard knows your team's security policy and checks packages for malware, known vulnerabilities, typosquats, banned packages, licenses and package health. A package you add runs on the user's machine and in production, so check it first.

## Before adding or upgrading any dependency

1. Collect every package you are about to add or change, with the exact version if you know it.
2. Call the `check_packages` tool of the depguard MCP server once with all of them:
   `{"packages": [{"ecosystem": "npm", "name": "express", "version": "4.21.2"}, {"ecosystem": "PyPI", "name": "requests"}]}`
   Omit `version` to check the latest release. Ecosystems: npm, PyPI, Go, Maven, Cargo, RubyGems, Packagist, NuGet.
3. Follow the `decision` for each package:
   - `block`: do not install it and do not write it into a manifest. Tell the user in one or two sentences what depguard found. If `safer_version` is present, offer that version; otherwise suggest a well-known alternative and check it too.
   - `warn`: go ahead, and mention the warning to the user in one line.
   - `allow`: go ahead. No need to mention depguard.
4. Then install with the normal command.

If the MCP server is not connected but the depguard CLI is installed, check with a dry run instead (nothing is installed):

```sh
depguard --dry-run npm install express@4.21.2
depguard --dry-run pip install requests
```

Exit code 1 or "blocked" in the output means the same as `block`.

## Rules

- A name that is "not found in the registry" may be a typo or a hallucinated package. Never install it; ask the user what they meant.
- Never work around a block: no other registry, no vendoring or copying the code, no `--force`. Only the user can override a block, in depguard.
- Check transitive surprises too: after installing, if the lockfile gained packages you did not expect, run `depguard check` in the project.
- When the user asks whether a package is safe, use `check_packages`, and for details `get_package_vulnerabilities`, `get_malware_verdict`, `get_license_info` and `get_package_scorecard`.
- Keep reports short: which package, what was found, what you did instead.

## Project secrets (API keys, .env files)

The team keeps the project's private files in depguard's end-to-end encrypted vault. When a command needs them
(start the app, run migrations, call an API, run integration tests):

- Use the `run_with_secrets` tool of the local `depguard-secrets` MCP server with the command. Secrets arrive as
  environment variables (files in `$DEPGUARD_SECRETS_DIR`), and the output comes back with every value replaced by
  `«KEY_NAME»`. `list_secrets` shows which files and key names exist.
- Without MCP, run `depguard secrets run -- <command>` in the terminal.
- Never read, print, copy, encode or commit secret values, never ask the user to paste a key, and never create a `.env`
  with real values. If the vault is locked, ask the user to run `depguard secrets unlock` in a terminal.
