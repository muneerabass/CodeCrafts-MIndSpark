'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';

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


type Line = { c: string; t: string };

// Scripted demo (auto-plays until the visitor clicks a scenario or types).
const SCN: { label: string; dot: string; tag: string; cmd: string; out: Line[] }[] = [
  { label: 'Typosquat · one keystroke from a popular name', dot: '#f87171', tag: 'blocked', cmd: 'npm install lodahs', out: [{ c: '#6b7280', t: 'depguard ▸ checking lodahs …' }, { c: '#f87171', t: '✖ BLOCKED  typosquat of lodash (two letters swapped)' }, { c: '#9ca3af', t: '  lookalike of a package with millions of installs' }, { c: '#c4b5fd', t: '→ did you mean: npm install lodash' }] },
  { label: 'Malware · steals environment variables', dot: '#f87171', tag: 'blocked', cmd: 'pip install ctx==0.2.6', out: [{ c: '#6b7280', t: 'depguard ▸ checking ctx@0.2.6 …' }, { c: '#f87171', t: '✖ BLOCKED  malicious: sends environment variables' }, { c: '#9ca3af', t: '  (AWS keys) to a remote host, hijacked in 2022' }, { c: '#c4b5fd', t: '→ nothing was installed. No script ran.' }] },
  { label: 'Known CVE · with the exact fix command', dot: '#fbbf24', tag: 'warned', cmd: 'npm install minimist@1.2.5', out: [{ c: '#6b7280', t: 'depguard ▸ checking minimist@1.2.5 …' }, { c: '#fbbf24', t: '⚠ WARN  CVE-2021-44906 · CRITICAL · prototype pollution' }, { c: '#9ca3af', t: '  fixed in 1.2.6' }, { c: '#c4b5fd', t: '→ npm install minimist@1.2.6' }] },
  { label: 'Clean · installs as usual', dot: '#34d399', tag: 'allowed', cmd: 'npm install express', out: [{ c: '#6b7280', t: 'depguard ▸ checking express …' }, { c: '#34d399', t: '✔ ALLOWED  no known issues · MIT' }, { c: '#9ca3af', t: '  added 64 packages in 2.1s' }] },
];

const TONE: Record<string, [string, string]> = { red: ['#f87171', '✖ BLOCKED'], orange: ['#fbbf24', '⚠ WARN'], amber: ['#fbbf24', '⚠ WARN'], green: ['#34d399', '✔ ALLOWED'] };

/** Turns "npm i x@1", "pip install x==1" or "x@1" into the in-browser check's answer. */
function answer(cmd: string): Line[] {
  const words = cmd.trim().split(/\s+/);
  const pip = /^(pip3?|uv|poetry)$/.test(words[0] ?? '');
  const spec = words.filter((w) => !/^(npm|pnpm|yarn|pip3?|uv|poetry|install|i|add)$/.test(w) && !w.startsWith('-'))[0] ?? '';
  const eco: Eco = pip ? 'PyPI' : 'npm';
  const v = check(eco, spec);
  if (!v) return [{ c: '#9ca3af', t: 'try: npm install lodahs · pip install ctx==0.2.6 · npm i minimist@1.2.5' }];
  const [col, word] = TONE[v.tone];
  return [
    { c: '#6b7280', t: `depguard ▸ checking ${spec} (${eco}) …` },
    { c: col, t: `${word}  ${v.title.replace(/^Blocked · /, '')}` },
    ...v.lines.map((t) => ({ c: '#9ca3af', t: '  ' + t })),
    ...(v.fix ? [{ c: '#c4b5fd', t: '→ ' + v.fix }] : []),
  ];
}

const Prompt = ({ children }: { children: ReactNode }) => (
  <div>
    <span style={{ color: '#a78bfa' }}>$</span> {children}
  </div>
);
const Caret = () => <span style={{ display: 'inline-block', width: 8, height: 16, verticalAlign: -3, background: '#a78bfa', marginLeft: 2, animation: 'lpBlink 1s steps(1) infinite' }} />;

/** "Try it now": scenario list + typing terminal; the visitor can run their own package. */
export function TryDemo({ intro }: { intro: ReactNode }) {
  const [active, setActive] = useState(0);
  const [typed, setTyped] = useState('');
  const [out, setOut] = useState<Line[]>([]);
  const [busy, setBusy] = useState(true);
  const [input, setInput] = useState('');
  const auto = useRef(true);
  const run = useRef(0);

  const play = async (cmd: string, lines: Line[], fast = false) => {
    const id = ++run.current;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, reduce ? 0 : ms));
    setBusy(true);
    setOut([]);
    for (let c = 0; c <= cmd.length; c++) {
      if (run.current !== id) return false;
      setTyped(cmd.slice(0, c));
      if (!fast) await sleep(45 + Math.random() * 40);
    }
    await sleep(fast ? 120 : 350);
    for (let i = 0; i < lines.length; i++) {
      if (run.current !== id) return false;
      setOut(lines.slice(0, i + 1));
      await sleep(fast ? 120 : 320);
    }
    setBusy(false);
    return run.current === id;
  };

  useEffect(() => {
    let i = 0;
    let stop = false;
    (async () => {
      await new Promise((r) => setTimeout(r, 900));
      while (!stop && auto.current) {
        const s = SCN[i % SCN.length];
        setActive(i % SCN.length);
        if (!(await play(s.cmd, s.out))) return;
        await new Promise((r) => setTimeout(r, 2600));
        i++;
      }
    })();
    const r = run;
    return () => {
      stop = true;
      r.current++;
    };
  }, []);

  const pick = (i: number) => {
    auto.current = false;
    setActive(i);
    play(SCN[i].cmd, SCN[i].out, true);
  };
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd) return;
    auto.current = false;
    setActive(-1);
    setInput('');
    play(cmd.includes(' ') ? cmd : `npm install ${cmd}`, answer(cmd.includes(' ') ? cmd : `npm install ${cmd}`), true);
  };

  return (
    <>
      <div>
        {intro}
        <div data-r="up" data-d="240" style={{ marginTop: 28, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {SCN.map((s, i) => (
            <button
              key={s.cmd}
              type="button"
              onClick={() => pick(i)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, padding: '12px 14px', borderRadius: 10, textAlign: 'left', cursor: 'pointer', font: 'inherit', color: 'inherit', transition: 'all .3s',
                border: `1px solid ${active === i ? 'rgb(167 139 250 / 55%)' : 'rgb(255 255 255 / 10%)'}`,
                background: active === i ? 'rgb(167 139 250 / 8%)' : 'transparent',
                transform: active === i ? 'translateX(6px)' : 'none',
              }}
            >
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.dot, flex: 'none' }} />
              <span style={{ flex: 1, fontSize: 15 }}>{s.label}</span>
              <span style={{ font: '12px var(--home-mono),ui-monospace,monospace', color: s.dot }}>{s.tag}</span>
            </button>
          ))}
        </div>
      </div>
      <div data-r="right" data-d="120" style={{ position: 'relative', minWidth: 0 }}>
        <div style={{ position: 'absolute', inset: -40, background: 'radial-gradient(50% 50% at 50% 50%,rgb(124 58 237 / 25%),transparent 70%)', pointerEvents: 'none' }} />
        <div data-tilt="6" style={{ position: 'relative', borderRadius: 14, border: '1px solid rgb(255 255 255 / 12%)', background: '#07060c', boxShadow: '0 40px 80px -30px rgb(124 58 237 / 45%),0 0 0 1px rgb(255 255 255 / 3%) inset', overflow: 'hidden', transition: 'transform .25s ease-out' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 14px', borderBottom: '1px solid rgb(255 255 255 / 8%)' }}>
            {[0, 1, 2].map((k) => <span key={k} style={{ width: 11, height: 11, borderRadius: '50%', background: '#3f3f46' }} />)}
            <span style={{ marginLeft: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', font: '12px var(--home-mono),ui-monospace,monospace', color: '#6b7280' }}>~/acme/storefront · install guard</span>
          </div>
          <div aria-live="polite" style={{ padding: '20px 20px 18px', minHeight: 300, font: '14px/1.75 var(--home-mono),ui-monospace,monospace', color: '#e5e7eb', overflowWrap: 'anywhere' }}>
            <Prompt>depguard setup shell</Prompt>
            <div style={{ color: '#6b7280' }}>guard on · every install is checked first</div>
            <div style={{ height: 14 }} />
            <Prompt>
              {typed}
              {busy && !out.length && <Caret />}
            </Prompt>
            {out.map((l, i) => (
              <div key={i} style={{ color: l.c, whiteSpace: 'pre-wrap' }}>{l.t}</div>
            ))}
          </div>
          <form onSubmit={submit} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 20px', borderTop: '1px solid rgb(255 255 255 / 8%)', background: 'rgb(255 255 255 / 2%)', font: '14px var(--home-mono),ui-monospace,monospace' }}>
            <span style={{ color: '#a78bfa' }}>$</span>
            <label htmlFor="try-cmd" style={{ position: 'absolute', width: 1, height: 1, overflow: 'hidden', clip: 'rect(0 0 0 0)' }}>Package to check</label>
            <input
              id="try-cmd"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onFocus={() => (auto.current = false)}
              placeholder="npm install reqeusts"
              autoComplete="off"
              spellCheck={false}
              style={{ flex: 1, minWidth: 0, background: 'transparent', border: 0, outline: 'none', color: '#fff', font: 'inherit' }}
            />
            <button type="submit" style={{ padding: '5px 12px', borderRadius: 7, border: 0, background: '#7c3aed', color: '#fff', font: '500 13px var(--home-sans),system-ui,sans-serif', cursor: 'pointer' }}>Check</button>
          </form>
        </div>
      </div>
    </>
  );
}
