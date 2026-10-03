// Real supply-chain attacks and the depguard check that answers each one.
const INCIDENTS = [
  {
    when: 'Nov 2018',
    name: 'event-stream',
    eco: 'npm',
    what: 'A new maintainer added flatmap-stream, which quietly stole bitcoin wallets from a downstream app.',
    caught: 'New transitive dependency flagged on the PR · malware feed blocks flatmap-stream',
    tone: 'red',
  },
  {
    when: 'Oct 2021',
    name: 'ua-parser-js',
    eco: 'npm',
    what: 'A hijacked account published 3 versions with a preinstall script that dropped a cryptominer and password stealer.',
    caught: 'Install-script analysis + CLI guard stops the install before the script runs',
    tone: 'red',
  },
  {
    when: 'Jan 2022',
    name: 'colors & faker',
    eco: 'npm',
    what: 'The maintainer sabotaged their own packages: an infinite loop that broke thousands of apps.',
    caught: 'Malware feed marks the sabotaged versions · PR check blocks the upgrade',
    tone: 'amber',
  },
  {
    when: 'May 2022',
    name: 'ctx',
    eco: 'PyPI',
    what: 'An expired maintainer domain was taken over; new releases sent environment variables (AWS keys) to a remote host.',
    caught: 'Unusual-behaviour check flags env-var exfiltration · release blocked by policy',
    tone: 'red',
  },
  {
    when: 'Mar 2024',
    name: 'xz-utils',
    eco: 'Linux',
    what: 'A multi-year social-engineering campaign slipped a backdoor into release tarballs targeting sshd.',
    caught: 'Hard for any scanner before disclosure · after CVE-2024-3094, every affected repo is flagged on the next scan',
    tone: 'dim',
  },
  {
    when: 'Sep 2025',
    name: 'chalk, debug & Shai-Hulud',
    eco: 'npm',
    what: 'Phished maintainer tokens pushed trojanized versions of hugely popular packages; a self-replicating worm followed.',
    caught: 'Malware feed + new-version policy: risky updates wait for review instead of auto-merging',
    tone: 'red',
  },
] as const;

const DOT = { red: 'bg-red-400 shadow-[0_0_14px_rgb(248_113_113/0.7)]', amber: 'bg-amber-300 shadow-[0_0_14px_rgb(252_211_77/0.6)]', dim: 'bg-[var(--lp-dim)]' };

export function Incidents() {
  return (
    <ol className="relative mt-16 space-y-6 md:space-y-0 before:absolute before:inset-y-2 before:left-[7px] before:w-px before:bg-gradient-to-b before:from-[var(--lp-teal)] before:via-[var(--lp-line-2)] before:to-transparent md:before:left-1/2">
      {INCIDENTS.map((x, i) => (
        <li key={x.name} className={`lp-incident relative pl-8 md:w-1/2 md:pl-0 ${i % 2 ? 'md:ml-auto md:pl-10' : 'md:pr-10'} ${i ? 'md:-mt-20' : ''}`} style={{ animationDelay: `${i * 0.08}s` }}>
          <span className={`absolute top-6 left-0 size-[15px] rounded-full border-4 border-black ${DOT[x.tone]} ${i % 2 ? 'md:-left-[7.5px]' : 'md:left-auto md:-right-[7.5px]'}`} />
          <div className="rounded-xl border border-[var(--lp-line-2)] bg-[var(--lp-panel)] p-5 transition-colors hover:border-[var(--lp-teal)]/60">
            <p className="lp-mono flex items-center gap-2 text-[12px] text-[var(--lp-dim)]">
              {x.when} <span className="rounded border border-[var(--lp-line-2)] px-1.5 py-px text-[11px]">{x.eco}</span>
            </p>
            <h3 className="lp-display mt-2 text-[22px]">{x.name}</h3>
            <p className="mt-2 text-[15px] leading-relaxed text-[var(--lp-muted)]">{x.what}</p>
            <p className={`mt-4 flex gap-2 border-t border-[var(--lp-line)] pt-3 text-[14px] ${x.tone === 'dim' ? 'text-[var(--lp-muted)]' : 'text-[var(--lp-teal)]'}`}>
              <span aria-hidden>{x.tone === 'dim' ? '•' : '✓'}</span>
              <span>
                <span className="font-medium text-white">depguard: </span>
                {x.caught}
              </span>
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}
