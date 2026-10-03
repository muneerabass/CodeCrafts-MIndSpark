# depguard CLI

Checks every `npm`, `pnpm`, `yarn`, `pip`, `uv`, `poetry`, `go` and `cargo` install against your team's
depguard policy before anything is installed: known vulnerabilities, malware, banned packages,
allowed version ranges, licenses and suspicious packages.

```sh
npm install --save-dev <your depguard>/downloads/depguard-cli.tgz
npx depguard login --api-key dg_...   # API key from Settings → API Keys
npx depguard init                     # writes .depguard.yml and guards installs on this machine
npm install express                   # checked first, then installed
npx depguard check                    # CI: check the lockfiles, exit 1 when blocked
```
