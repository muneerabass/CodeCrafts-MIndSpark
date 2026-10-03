'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowRight, Check } from 'lucide-react';

type Row = string[];
type Layer = {
  id: string;
  tab: string;
  title: string;
  body: string;
  points: string[];
  path: string;
  cols: string[];
  rows: Row[];
  href: string;
  cta: string;
};

const LAYERS: Layer[] = [
  {
    id: 'repos',
    tab: 'Repositories',
    title: 'A full dependency graph for every repo',
    body: 'Connect GitHub once and depguard resolves every manifest and lockfile into a graph of direct and transitive components, with versions, ecosystems and licenses. Each project gets a risk score you can sort on.',
    points: ['Direct and transitive, across ecosystems', 'Risk score per project', 'Re-scanned as code changes'],
    path: 'projects',
    cols: ['Project', 'Components', 'Critical', 'High', 'Last scan'],
    rows: [
      ['acme/payments-api', '1,204', '2', '7', '4 min ago'],
      ['acme/web-console', '2,318', '0', '3', '12 min ago'],
      ['acme/ingest-worker', '486', '1', '0', '1 hr ago'],
      ['acme/ml-pipeline', '911', '0', '5', '3 hr ago'],
      ['acme/cli', '143', '0', '0', '1 day ago'],
    ],
    href: '/sign-in',
    cta: 'Scan your repositories',
  },
  {
    id: 'malware',
    tab: 'Malicious packages',
    title: 'Look at what a package does, not just its CVEs',
    body: 'Install hooks that read credentials, obfuscated payloads, network calls at import time. depguard inspects package contents with static heuristics and flags behaviour that no advisory database has caught yet.',
    points: ['Install-script and obfuscation checks', 'Credential and exfiltration patterns', 'Exclusions for known-good packages'],
    path: 'package-analysis',
    cols: ['Package', 'Ecosystem', 'Verdict', 'Signals'],
    rows: [
      ['colors-utils@3.4.1', 'npm', 'Malicious', 'postinstall, env read, http'],
      ['reqeusts@2.31.0', 'PyPI', 'Suspicious', 'typosquat, new author'],
      ['left-pad-ng@1.0.2', 'npm', 'Suspicious', 'obfuscated, base64 eval'],
      ['fastjsonx@0.9.1', 'Maven', 'Clean', '—'],
      ['serde@1.0.203', 'crates.io', 'Clean', '—'],
    ],
    href: '/sign-in',
    cta: 'Inspect your packages',
  },
  {
    id: 'paths',
    tab: 'Attack paths',
    title: 'See exactly how risk reaches your code',
    body: 'A vulnerable package four levels deep is only useful if you know which direct dependency pulls it in. Attack paths trace the chain from your project to the risky component, so the fix is obvious.',
    points: ['Shortest path to every finding', 'Which direct dependency to bump', 'Fixed versions from OSV'],
    path: 'projects / acme/payments-api / attack paths',
    cols: ['Finding', 'Depth', 'Path', 'Fix'],
    rows: [
      ['GHSA prototype pollution', '3', 'express › body-parser › qs', 'qs ≥ 6.11.0'],
      ['ReDoS in semver', '4', 'eslint › … › semver', 'semver ≥ 7.5.2'],
      ['Path traversal', '2', 'archiver › tar-stream', 'tar-stream ≥ 3.1.7'],
      ['SSRF in follow-redirects', '3', 'axios › follow-redirects', '≥ 1.15.6'],
    ],
    href: '/sign-in',
    cta: 'Trace your attack paths',
  },
  {
    id: 'endpoints',
    tab: 'Endpoints',
    title: 'Laptops, runners and servers in one view',
    body: 'The depguard agent runs on developer machines and CI runners, inventories what is installed and streams events back. You see every endpoint, what it monitors and what it flagged, in one fleet view.',
    points: ['Lightweight CLI agent', 'Per-endpoint event feed', 'Same policy as your repos'],
    path: 'endpoints',
    cols: ['Endpoint', 'Platform', 'Events', 'Flagged', 'Last active'],
    rows: [
      ['dev-laptop-ana', 'macOS · arm64', '1,248', '3', '2 min ago'],
      ['ci-runner-01', 'Linux · amd64', '431', '5', '2 hr ago'],
      ['build-agent-eu', 'Linux · amd64', '89', '0', '2 hr ago'],
      ['dev-laptop-raj', 'Windows · x64', '164', '1', '1 hr ago'],
    ],
    href: '/sign-in',
    cta: 'Protect your machines',
  },
  {
    id: 'policy',
    tab: 'Policy',
    title: 'One policy, enforced on every pull request',
    body: 'Write the rules once: severity thresholds, banned licenses, blocked packages. depguard checks every new dependency against them and reports violations on the PR and in the console.',
    points: ['Severity and license rules', 'GitHub checks on pull requests', 'Violations tracked over time'],
    path: 'policy / violations',
    cols: ['Rule', 'Project', 'Component', 'Status'],
    rows: [
      ['no-critical-vulns', 'acme/payments-api', 'qs@6.5.2', 'Open'],
      ['no-copyleft', 'acme/web-console', 'xmldom@0.6.0', 'Open'],
      ['block-malicious', 'acme/cli', 'colors-utils@3.4.1', 'Blocked'],
      ['max-age-30d', 'acme/ml-pipeline', 'torch@2.0.1', 'Waived'],
    ],
    href: '/sign-in',
    cta: 'Set your policy',
  },
];

const COUNT_COLS = new Set(['Critical', 'High', 'Flagged']);
const tone = (col: string, v: string) => {
  if (COUNT_COLS.has(col)) return v === '0' ? 'text-[var(--lp-dim)]' : 'text-[var(--lp-red)]';
  if (/^(Malicious|Open)$/.test(v)) return 'text-[var(--lp-red)]';
  if (/^(Suspicious|Waived)$/.test(v)) return 'text-amber-300';
  if (/^(Clean|Blocked)$/.test(v)) return 'text-[var(--lp-teal)]';
  return '';
};

export function Layers() {
  const [active, setActive] = useState(LAYERS[0].id);
  const l = LAYERS.find((x) => x.id === active)!;
  return (
    <div>
      <div role="tablist" aria-label="Product layers" className="inline-flex max-w-full flex-wrap gap-1 border border-[var(--lp-line-2)] p-1">
        {LAYERS.map((x) => (
          <button
            key={x.id}
            role="tab"
            aria-selected={x.id === active}
            onClick={() => setActive(x.id)}
            className={`px-4 py-2.5 text-[15px] transition-colors ${
              x.id === active ? 'border border-[var(--lp-line-2)] bg-white/[0.06] text-white' : 'border border-transparent text-[var(--lp-muted)] hover:text-white'
            }`}
          >
            {x.tab}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="mt-12">
        <div className="grid gap-8 md:grid-cols-2">
          <h3 className="lp-display text-[28px] leading-tight">{l.title}</h3>
          <p className="text-[17px] leading-relaxed text-[var(--lp-muted)]">{l.body}</p>
        </div>
        <ul className="mt-10 grid gap-6 border-t border-[var(--lp-line)] pt-8 sm:grid-cols-3">
          {l.points.map((p) => (
            <li key={p} className="flex gap-3 text-[17px] text-white">
              <Check className="mt-1 size-4 shrink-0 text-[var(--lp-teal)]" /> {p}
            </li>
          ))}
        </ul>

        <div className="mt-10 overflow-hidden border border-[var(--lp-line-2)] bg-[#05080a]">
          <div className="flex items-center gap-3 border-b border-[var(--lp-line)] bg-white/[0.03] px-4 py-3">
            <span className="flex gap-1.5">
              <span className="size-2.5 rounded-full bg-white/20" />
              <span className="size-2.5 rounded-full bg-white/20" />
              <span className="size-2.5 rounded-full bg-white/20" />
            </span>
            <span className="lp-mono truncate text-sm text-[var(--lp-muted)]">depguard / {l.path}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead>
                <tr className="text-[var(--lp-muted)]">
                  {l.cols.map((c) => (
                    <th key={c} className="px-5 py-4 font-medium">{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {l.rows.map((r) => (
                  <tr key={r[0]} className="lp-row">
                    {r.map((v, i) => (
                      <td key={i} className={`px-5 py-4 ${i === 0 ? 'text-white' : `lp-mono ${tone(l.cols[i], v) || 'text-[var(--lp-fg)]'}`}`}>
                        {v}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="lp-mono border-t border-[var(--lp-line)] px-5 py-3 text-xs text-[var(--lp-dim)]">Sample data</p>
        </div>

        <Link href={l.href} className="mt-8 inline-flex items-center gap-2 text-[17px] text-[var(--lp-teal)] hover:text-white">
          {l.cta} <ArrowRight className="size-4" />
        </Link>
      </div>
    </div>
  );
}
