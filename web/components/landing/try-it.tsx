'use client';

import { useState } from 'react';
import { ShieldAlert, ShieldCheck, ShieldX, TriangleAlert } from 'lucide-react';

// Instant, in-browser preview of depguard's checks. Small built-in lists only:
// the real product checks the full OSV / malware feeds after sign-in.
// ponytail: static lists, swap for a public rate-limited API if the preview should be exhaustive.

type Eco = 'npm' | 'PyPI';

const POPULAR: Record<Eco, string[]> = {
  npm: ['react', 'lodash', 'express', 'axios', 'chalk', 'debug', 'request', 'commander', 'moment', 'webpack', 'typescript', 'vue', 'next', 'jquery', 'dotenv', 'uuid', 'yargs', 'async', 'body-parser', 'cross-env', 'mongoose', 'socket.io', 'eslint', 'prettier', 'jest', 'underscore', 'bluebird', 'minimist', 'colors', 'rimraf', 'glob', 'semver', 'classnames', 'nodemon', 'babel-cli', 'electron'],
  PyPI: ['requests', 'numpy', 'pandas', 'django', 'flask', 'urllib3', 'boto3', 'setuptools', 'pyyaml', 'matplotlib', 'scipy', 'pillow', 'cryptography', 'beautifulsoup4', 'selenium', 'pytest', 'sqlalchemy', 'tensorflow', 'torch', 'scikit-learn', 'jinja2', 'click', 'colorama', 'python-dateutil', 'fastapi', 'pydantic'],
};

// Versions known to be malicious (public incident reports).
const MALWARE: Record<Eco, Record<string, { versions: string[]; why: string }>> = {
  npm: {
    'flatmap-stream': { versions: ['*'], why: 'Stole bitcoin wallets via event-stream (2018)' },
    'event-stream': { versions: ['3.3.6'], why: 'Pulled in the malicious flatmap-stream (2018)' },
    'ua-parser-js': { versions: ['0.7.29', '0.8.0', '1.0.0'], why: 'Hijacked release with a cryptominer and password stealer (2021)' },
    colors: { versions: ['1.4.44-liberty-2'], why: 'Sabotaged by its maintainer: infinite loop (2022)' },
    faker: { versions: ['6.6.6'], why: 'Sabotaged by its maintainer (2022)' },
    'node-ipc': { versions: ['10.1.1', '10.1.2'], why: 'Wiped files on some machines (2022)' },
  },
  PyPI: {
    ctx: { versions: ['0.2.2', '0.2.6'], why: 'Hijacked release that sent environment variables to a remote host (2022)' },
  },
};

// A few well-known advisories: affected below `fixed`.
const VULNS: Record<Eco, Record<string, { id: string; risk: 'Critical' | 'High' | 'Medium'; fixed: string; what: string }>> = {
  npm: {
    lodash: { id: 'CVE-2021-23337', risk: 'High', fixed: '4.17.21', what: 'Command injection in template()' },
    minimist: { id: 'CVE-2021-44906', risk: 'Critical', fixed: '1.2.6', what: 'Prototype pollution' },
    axios: { id: 'CVE-2023-45857', risk: 'Medium', fixed: '1.6.0', what: 'XSRF token leaked to third-party hosts' },
    express: { id: 'CVE-2024-29041', risk: 'Medium', fixed: '4.19.2', what: 'Open redirect in malformed URLs' },
  },
  PyPI: {
    requests: { id: 'CVE-2023-32681', risk: 'Medium', fixed: '2.31.0', what: 'Proxy-Authorization header leaked on redirect' },
    pyyaml: { id: 'CVE-2020-14343', risk: 'Critical', fixed: '5.4', what: 'Arbitrary code execution in full_load()' },
    jinja2: { id: 'CVE-2024-22195', risk: 'Medium', fixed: '3.1.3', what: 'Cross-site scripting in xmlattr filter' },
  },
};

const EXAMPLES: Record<Eco, string[]> = {
  npm: ['lodash@4.17.15', 'ua-parser-js@0.7.29', 'expres', 'crossenv', 'lodash@4.17.21'],
  PyPI: ['requets', 'pyyaml==5.3', 'ctx==0.2.6', 'reqeusts', 'requests==2.32.3'],
};

/** Optimal string alignment distance (Levenshtein + adjacent swaps). */
export function distance(a: string, b: string): number {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  return d[a.length][b.length];
}

const lessThan = (a: string, b: string) => {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0);
  return false;
};

type Verdict = { tone: 'red' | 'orange' | 'amber' | 'green'; title: string; lines: string[]; fix?: string };

export function check(eco: Eco, input: string): Verdict | null {
  const raw = input.trim().toLowerCase();
  if (!raw) return null;
  const m = eco === 'npm' ? raw.match(/^(@?[^@\s]+)(?:@(\S+))?$/) : raw.match(/^([^=<>!~\s\[]+)(?:\[[^\]]*\])?\s*(?:==\s*(\S+))?/);
  if (!m) return null;
  const [, name, version] = m;
  const install = (v: string) => (eco === 'npm' ? `npm install ${name}@${v}` : `pip install "${name}>=${v}"`);

  const mal = MALWARE[eco][name];
  if (mal && (mal.versions.includes('*') || (version && mal.versions.includes(version))))
    return { tone: 'red', title: 'Blocked · known malware', lines: [mal.why, 'The install never runs: depguard stops it before any script executes.'] };

  const v = VULNS[eco][name];
  if (v && version && lessThan(version, v.fixed))
    return { tone: v.risk === 'Critical' ? 'red' : 'orange', title: `${v.risk} vulnerability · ${v.id}`, lines: [v.what], fix: install(v.fixed) };

  const norm = (s: string) => s.replace(/[-_.]/g, '');
  const pop = POPULAR[eco];
  if (!pop.includes(name)) {
    const twin = pop.find((p) => norm(p) === norm(name) || (name.length >= 4 && distance(name, p) <= (p.length >= 8 ? 2 : 1)));
    if (twin) return { tone: 'amber', title: `Looks like "${twin}" · possible typosquat`, lines: ['Name is one or two keystrokes away from a popular package.', 'Flagged on the pull request and stopped by the CLI guard.'], fix: eco === 'npm' ? `npm install ${twin}` : `pip install ${twin}` };
  }

  if (mal || v)
    return { tone: 'green', title: 'Clean in the instant check', lines: [version ? `${name} ${version} is past the known bad versions.` : `Add a version (e.g. ${name}${eco === 'npm' ? '@' : '=='}${v?.fixed ?? '1.0.0'}) to check advisories.`] };
  return { tone: 'green', title: 'Nothing found in the instant check', lines: ['Sign in for the full scan: every OSV advisory, malware analysis, install scripts and licenses.'] };
}

const TONE = {
  red: { box: 'border-red-500/40 bg-red-500/[0.07]', text: 'text-red-300', Icon: ShieldX },
  orange: { box: 'border-orange-500/40 bg-orange-500/[0.07]', text: 'text-orange-300', Icon: ShieldAlert },
  amber: { box: 'border-amber-400/40 bg-amber-400/[0.07]', text: 'text-amber-200', Icon: TriangleAlert },
  green: { box: 'border-emerald-400/40 bg-emerald-400/[0.06]', text: 'text-emerald-300', Icon: ShieldCheck },
};

export function TryIt() {
  const [eco, setEco] = useState<Eco>('npm');
  const [q, setQ] = useState('lodash@4.17.15');
  const v = check(eco, q);
  const t = v ? TONE[v.tone] : null;

  return (
    <div className="rounded-2xl border border-[var(--lp-line-2)] bg-[#07070b] p-5 shadow-2xl shadow-violet-950/30 md:p-7">
      <div className="flex flex-wrap items-center gap-2">
        <div role="tablist" aria-label="Registry" className="inline-flex rounded-lg border border-[var(--lp-line-2)] p-0.5">
          {(['npm', 'PyPI'] as Eco[]).map((e) => (
            <button
              key={e}
              role="tab"
              aria-selected={eco === e}
              onClick={() => {
                setEco(e);
                setQ(EXAMPLES[e][0]);
              }}
              className={`lp-mono rounded-md px-3 py-1 text-[13px] ${eco === e ? 'bg-[var(--lp-teal-btn)] text-white' : 'text-[var(--lp-muted)] hover:text-white'}`}
            >
              {e}
            </button>
          ))}
        </div>
        <span className="lp-mono text-[12px] text-[var(--lp-dim)]">runs in your browser · nothing is sent</span>
      </div>

      <label className="mt-4 flex items-center gap-3 rounded-xl border border-[var(--lp-line-2)] bg-black px-4 py-3 focus-within:border-[var(--lp-teal)]">
        <span className="lp-mono shrink-0 text-[15px] text-[var(--lp-dim)]">{eco === 'npm' ? '$ npm install' : '$ pip install'}</span>
        <input
          aria-label="Package to check"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          placeholder={eco === 'npm' ? 'name@version' : 'name==version'}
          className="lp-mono min-w-0 flex-1 bg-transparent text-[15px] text-white outline-none placeholder:text-[var(--lp-dim)]"
        />
      </label>

      <div className="mt-3 flex flex-wrap gap-1.5">
        <span className="text-[12px] text-[var(--lp-dim)]">Try:</span>
        {EXAMPLES[eco].map((x) => (
          <button key={x} onClick={() => setQ(x)} className="lp-mono rounded-md border border-[var(--lp-line-2)] px-2 py-0.5 text-[12px] text-[var(--lp-muted)] hover:border-[var(--lp-teal)] hover:text-white">
            {x}
          </button>
        ))}
      </div>

      <div aria-live="polite" className="mt-5 min-h-[132px]">
        {v && t && (
          <div key={v.title + q} className={`lp-verdict rounded-xl border p-4 ${t.box}`}>
            <p className={`flex items-center gap-2 text-[16px] font-medium ${t.text}`}>
              <t.Icon className="size-5 shrink-0" /> {v.title}
            </p>
            {v.lines.map((l) => (
              <p key={l} className="mt-1.5 text-[14px] text-[var(--lp-muted)]">
                {l}
              </p>
            ))}
            {v.fix && (
              <p className="lp-mono mt-3 rounded-md bg-black/60 px-3 py-2 text-[13px] text-white">
                <span className="text-[var(--lp-dim)]">fix › </span>
                {v.fix}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
