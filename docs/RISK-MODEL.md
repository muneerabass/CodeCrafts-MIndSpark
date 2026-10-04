# depguard risk model

How depguard decides what is risky in your dependencies and how it ranks it. This is the plain-English
companion to `docs/CONTRACTS.md` ("Risk analysis").

## Direct and transitive dependencies

- A **direct** dependency is one your project lists itself (`package.json`, `go.mod`, `pyproject.toml`, …).
- A **transitive** dependency is pulled in by another dependency. `app → express → body-parser → qs`
  makes `qs` transitive at **depth 3** (`express` is depth 1).
- Depth and the "introduced via" chain are the **shortest** route from your app to the package. depguard
  keeps up to three distinct chains per package (shortest first).
- **Dev** dependencies (test/build only, e.g. npm `devDependencies`) are labelled and weigh less.
- "Unknown" means the scan had no dependency graph for that package (see Limitations).

Where the graph comes from:
1. **The lockfile** when it records parent → child edges (npm `package-lock.json` v2+, `uv.lock`, CycloneDX).
2. **deps.dev** for other ecosystems: depguard reads your direct dependencies from the manifest and asks
   deps.dev for each one's resolved dependency graph. Those paths are marked **approximate** because
   deps.dev may resolve different versions than your lockfile.
3. **None**: only direct/transitive labels from the manifest, no chains.

## Attack paths

An attack path is a chain from your app to a **target**: a package with a known vulnerability, known
malware (OSV `MAL-` advisory) or a suspicious-package finding. Each path is scored 0–100 so the most
urgent fixes come first:

```
base     = CRITICAL 40 · HIGH 30 · MEDIUM 15 · LOW 5      (highest advisory on the target)
         + 20 if any advisory is in CISA KEV (known exploited)
         + 20 × EPSS (probability of exploitation in the next 30 days, 0–1)
score    = base
         × 1.0 if your code imports the chain's direct dependency, 0.6 if unknown, 0.3 if not imported
         × 0.5 if the target is a dev-only dependency
         × max(0.5, 1 − 0.05 × (depth − 1))               (deeper = slightly less reachable)
clamped to 0–100; a known-malware target is always 100.
```

Suspicious targets without advisories use the finding's severity as the base (high = 30, …).
The score is computed when you read it, so it follows the latest EPSS and KEV data.

Example: `app → express → qs`, qs has a HIGH advisory in KEV with EPSS 0.42, express is imported:
(30 + 20 + 8.4) × 1.0 × 0.95 = **55**.

**Fix advice** names the lowest fixed version above the installed one from the OSV advisory ("Upgrade qs
to ≥6.7.3"). For a transitive target it adds the direct dependency that pulls it in, since that is
usually what you update ("via express: update express or pin qs with an override/resolution").
Malware advice is always "remove and rotate credentials".

## Suspicious packages

| Rule | Severity | Fires when |
|---|---|---|
| `typosquat` | high | The name is one edit, swap, separator reorder or confusable (`py`/`python`, `go`/`golang`) away from a popular package (top-package lists from guarddog) and is not popular itself. Names under 4 characters are skipped. `details.similar_to` names the lookalike. |
| `deprecated` | medium | The registry marks the version (or package) deprecated (deps.dev). |
| `unmaintained` | medium | No release for longer than the policy limit (default 24 months) **and** no sign of maintenance (OpenSSF Scorecard "Maintained" ≤ 1 or no repository). |
| `new-package` | low | The installed version was published less than 30 days ago. |
| `no-source-repo` | low | No source repository is linked (off by default). |
| `unusual-behaviour` | per rule | guarddog's source heuristics fire: install scripts, obfuscation, exfiltration, downloading executables, … (`details.rules`). |

Each rule can be switched off on the Policy page, and you choose which rules **block** (fail the check).
Default: only `typosquat` and `unusual-behaviour` block; the rest are reported.

### Fresh releases

Hijacked releases (event-stream, ua-parser-js, chalk/debug, Shai-Hulud) are usually caught and pulled within hours,
before any advisory exists. These rules read release metadata straight from the npm and PyPI registries (cached: 1 hour
while a package's newest release is under a week old, else 24 hours) and are configured by the **Fresh releases**
policy preset. They block by default; turn off "Fail the check" to only warn.

| Rule | Severity | Fires when |
|---|---|---|
| `release-age` | high | The version was published less than the cooldown ago (default 48 hours; npm and PyPI). A release that is the `fixed` version of an OSV advisory skips the cooldown, so security fixes are never held back. |
| `install-script-added` | high | (npm) The release has a `preinstall`/`install`/`postinstall`/`prepare` script and the previous release had none. A changed script is a medium warning. |
| `provenance-dropped` | high | (npm) The previous release had signed build provenance and this one does not: it was probably not published by the project's CI. |
| `publisher-changed` | medium | (npm) Published by an account that never published the package before. High and blocking together with `install-script-added` or `provenance-dropped`. |
| `new-behaviour` | high | An upgrade in a pull request: guarddog rules that fire on the new version but not on the version the project had. Only releases under 30 days old are compared; each version is analysed once and cached. |

The previous-release rules only look at releases younger than 90 days. Registry failures disable the rules for that
package; they never fail a scan. Trusted packages (package rules) skip them.

## License compliance

depguard needs two facts about your project:

- **Project license**: your override (Project → Licenses, or CLI `--project-license`), else the manifest
  (`package.json`, `pyproject.toml`, `Cargo.toml`), else the root `LICENSE` text, else GitHub, else unknown.
- **Usage model** (default *distributed binary*): `internal`, `saas`, `distributed_binary`, `distributed_source`.
  Copyleft obligations depend on whether you distribute the software or run it as a network service.

| Rule | When it fires |
|---|---|
| `license-unknown` | The dependency has no license or `NOASSERTION` (high when you distribute). |
| `license-network-copyleft` | AGPL/SSPL-style licenses in a SaaS or distributed project: providing the service counts as distribution. |
| `license-copyleft-distributed` | GPL-style strong copyleft in software you distribute: your combined work may have to be GPL. |
| `license-weak-copyleft` | LGPL/MPL/EPL/CDDL when distributed (LGPL notes static linking for Go/Rust). |
| `license-noncommercial` | Non-commercial licenses (e.g. CC-BY-NC): high regardless of usage. |
| `license-incompatible` | Project ↔ dependency: the OSADL compatibility matrix says your project license cannot include this dependency ("No" = high; "Check dependency"/"Unknown" = warning). |
| `license-conflict` | Dependency ↔ dependency: two dependencies can't be combined (e.g. `GPL-2.0-only` with `Apache-2.0`). |
| `license-denied` | The license matches the Policy deny list. |

`internal` use triggers almost nothing: obligations mostly start at distribution. SPDX expressions are
honoured: `MIT OR GPL-3.0` takes the least restrictive option, `AND` means all apply.
The Policy page sets whether license checks run and which severity blocks (default high).

## Data sources

| Data | Source |
|---|---|
| Vulnerabilities, malware, fixed versions | OSV (local mirror, synced every 15 min) |
| Exploitation | CISA KEV (hourly), FIRST EPSS (daily) |
| Licenses, repository, publish dates, deprecation, dependency graphs | deps.dev |
| Maintenance signal | OpenSSF Scorecard |
| Lookalike names, unusual behaviour | guarddog lists and heuristics (Apache-2.0) |
| License compatibility | OSADL matrix (CC BY 4.0) |

## Limitations

- **deps.dev paths are approximate** when its resolved versions differ from your lockfile; they are
  labelled "approximate" in the UI and reports.
- **Import-level reachability is a heuristic.** "Imported" means your source imports the chain's direct
  dependency, not that the vulnerable function is called. Uploads without source (CLI) show "unknown".
- Fixed-version advice comes from OSV ranges; upgrading the direct dependency may still be needed when
  it pins an old version.
- OSADL covers about 120 licenses; others fall back to category rules and should be reviewed manually.
- Typosquat detection only knows the bundled top-package lists; a lookalike of a less popular package is
  not flagged.
