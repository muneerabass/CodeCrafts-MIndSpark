import './landing.css';
import Link from 'next/link';
import { redirect } from 'next/navigation';
import { landingFonts } from '@/lib/landing-fonts';
import { MobileNav } from '@/components/landing/mobile-nav';
import { ArrowRight, ArrowUpRight, Bot, Check, ChevronRight, Database, GitPullRequest, Laptop, Workflow } from 'lucide-react';
import { Logo, GitHubIcon } from '@/components/icons';
import { Layers } from '@/components/landing/layers';
import { HeroPRCard, HeroTerminal } from '@/components/landing/hero-flow';
import { ThreatSphere } from '@/components/landing/threat-sphere';
import { TryIt } from '@/components/landing/try-it';
import { Incidents } from '@/components/landing/incidents';
import { getCtx } from '@/lib/session';

// Pulse timing: the sweep crosses the rail in 70% of the 5s loop, so each of the 4 gaps takes 0.875s.
const STEP = (5 * 0.7) / 4;

const SIGN_IN = '/sign-in';
const SIGN_UP = '/sign-in?mode=signup';

export const metadata = {
  title: { absolute: 'depguard · Supply-chain security for every dependency you install' },
};

const REPO = process.env.GITHUB_REPO_URL ?? 'https://github.com/Muneerabbas/CodeCrafts-MIndSpark';
const DOCS = `${REPO}/tree/master/docs`;

const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems', 'NuGet', 'Packagist'];

const STATS = [
  ['8', 'package ecosystems'],
  ['6', 'suspicious-package checks'],
  ['0–100', 'risk score on every attack path'],
  ['1', 'policy for PRs, CI and laptops'],
] as const;

const SIGNALS = [
  { kind: 'Malware', eco: 'npm', title: 'Install script reads cloud credentials', detail: 'A postinstall hook opens ~/.aws/credentials and posts it to a remote host.', action: 'Block install' },
  { kind: 'Typosquat', eco: 'PyPI', title: 'Package name one keystroke from a popular library', detail: 'Published last week by a new author, with a near-identical README.', action: 'Flag on PR' },
  { kind: 'CVE', eco: 'npm', title: 'Known vulnerability, three levels deep', detail: 'Matched against OSV, with the direct dependency that pulls it in.', action: 'Bump express' },
  { kind: 'License', eco: 'Maven', title: 'Copyleft license in a proprietary service', detail: 'Violates your no-copyleft rule. Shown as a policy violation.', action: 'Policy violation' },
];

const SOURCES = [
  ['OSV', 'advisories'],
  ['deps.dev', 'metadata'],
  ['static', 'package heuristics'],
  ['SPDX', 'licenses'],
];

const STAGES = [
  { n: '01', name: 'Developer machine', icon: Laptop, gets: ['npm / pip installs', 'IDE extensions', 'MCP servers'] },
  { n: '02', name: 'AI coding agent', icon: Bot, gets: ['packages it adds', 'plugins', 'tools it runs'] },
  { n: '03', name: 'Pull request', icon: GitPullRequest, gets: ['new dependencies', 'version bumps', 'transitive deps'] },
  { n: '04', name: 'CI/CD pipeline', icon: Workflow, gets: ['build-time pulls', 'base images'] },
  { n: '05', name: 'Org-wide', icon: Database, gets: ['every repo', 'shared caches'] },
];

const ANSWERS = [
  { n: '01', name: 'Dev machine', head: 'Seen on install', sub: 'endpoint agent inventory' },
  { n: '02', name: 'AI agent', head: 'Same inventory', sub: 'agent changes, same checks' },
  { n: '03', name: 'Pull request', head: 'Checked on PR', sub: 'GitHub App policy check' },
  { n: '04', name: 'CI/CD', head: 'Gated in CI', sub: 'CLI fails the build' },
  { n: '05', name: 'Org-wide', head: 'One policy', sub: 'one inventory, every team' },
];

const STEPS = [
  { n: '01', title: 'Connect', body: 'Install the GitHub App or run the CLI against a repository. Invite your team into a private workspace.' },
  { n: '02', title: 'Scan', body: 'depguard resolves the dependency graph, matches advisories, inspects package contents and scores risk per project.' },
  { n: '03', title: 'Enforce', body: 'Write policy once. New risky dependencies are flagged on the pull request, before they merge.' },
];

const FOOTER = [
  {
    h: 'Product',
    links: [
      ['Repositories', '#layers'],
      ['Malicious packages', '#layers'],
      ['Attack paths', '#layers'],
      ['Endpoints', '#layers'],
      ['Policy', '#layers'],
    ],
  },
  {
    h: 'Platform',
    links: [
      ['How it works', '#how'],
      ['What it catches', '#signals'],
      ['Sign in', SIGN_IN],
      ['Get started', SIGN_UP],
    ],
  },
  {
    h: 'Resources',
    links: [
      ['Documentation', DOCS],
      ['Risk model', `${REPO}/blob/master/docs/RISK-MODEL.md`],
      ['GitHub', REPO],
    ],
  },
  { h: 'Legal', links: [['Attributions', '/attributions']] },
];

function Eyebrow({ children, tone = 'teal' }: { children: React.ReactNode; tone?: 'teal' | 'red' | 'dim' }) {
  const c = tone === 'red' ? 'text-[var(--lp-red)]' : tone === 'dim' ? 'text-[var(--lp-dim)]' : 'text-[var(--lp-teal)]';
  return <p className={`lp-eyebrow ${c}`}>{children}</p>;
}

function SectionHead({ eyebrow, tone, a, b, bTone = 'dim', body }: { eyebrow: string; tone?: 'teal' | 'red'; a: string; b: string; bTone?: 'dim' | 'teal'; body: string }) {
  return (
    <div className="grid gap-8 md:grid-cols-2 md:items-end">
      <div>
        <Eyebrow tone={tone}>{eyebrow}</Eyebrow>
        <h2 className="lp-display mt-5 text-[34px] leading-[1.15] md:text-[40px]">
          {a}
          <br />
          <span className={bTone === 'teal' ? 'text-[var(--lp-teal)]' : 'text-[var(--lp-dim)]'}>{b}</span>
        </h2>
      </div>
      <p className="text-[17px] leading-relaxed text-[var(--lp-muted)]">{body}</p>
    </div>
  );
}

export default async function Home() {
  const ctx = await getCtx().catch(() => null);
  if (ctx) redirect(ctx.org ? '/dashboard' : '/onboarding');

  return (
    <div className={`lp ${landingFonts} min-h-dvh`}>
      {/* Announcement */}
      <div className="border-b border-[var(--lp-line)]">
        <a href="#layers" className="lp-frame lp-pad flex items-center justify-center gap-3 py-2.5 text-sm text-[var(--lp-fg)] hover:text-white">
          <span className="size-1.5 rounded-full bg-[var(--lp-teal)]" />
          New: attack paths show which direct dependency pulls in each finding
          <ChevronRight className="size-4 text-[var(--lp-dim)]" />
        </a>
      </div>

      {/* Nav */}
      <header className="sticky top-0 z-30 border-b border-[var(--lp-line)] bg-black lg:bg-black/80 lg:backdrop-blur-md">
        <div className="lp-frame lp-pad flex h-16 items-center gap-10">
          <Link href="/" className="flex items-center gap-2">
            <Logo className="size-6" />
            <span className="lp-display text-xl">depguard</span>
          </Link>
          <nav className="hidden items-center gap-8 text-[15px] text-[var(--lp-fg)] lg:flex">
            <a href="#try" className="hover:text-white">
              Try it
            </a>
            <a href="#incidents" className="hover:text-white">
              Real attacks
            </a>
            <a href="#signals" className="hover:text-white">
              What it catches
            </a>
            <a href="#layers" className="hover:text-white">
              Product
            </a>
            <a href="#how" className="hover:text-white">
              How it works
            </a>
            <a href={DOCS} className="hover:text-white">
              Docs
            </a>
          </nav>
          <div className="ml-auto flex items-center gap-3 text-[15px]">
            <Link href={SIGN_IN} className="hidden px-2 hover:text-white sm:block">
              Sign in
            </Link>
            <Link href={SIGN_UP} className="lp-btn lp-btn-primary px-3 py-2 text-sm">
              Get started
            </Link>
            <a href={REPO} aria-label="GitHub repository" className="lp-btn border border-[var(--lp-line-2)] px-3 py-2 text-sm hover:border-[var(--lp-dim)] max-sm:!hidden">
              <GitHubIcon /> GitHub
            </a>
            <MobileNav
              links={[
                ['Try it', '#try'],
                ['Real attacks', '#incidents'],
                ['What it catches', '#signals'],
                ['The problem', '#problem'],
                ['Product', '#layers'],
                ['How it works', '#how'],
                ['Docs', DOCS],
              ]}
              signIn={SIGN_IN}
              signUp={SIGN_UP}
            />
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden border-b border-[var(--lp-line)]">
        <div aria-hidden className="lp-streaks pointer-events-none absolute inset-0" />
        <div className="lp-frame relative bg-black">
          <div aria-hidden className="lp-aurora pointer-events-none absolute inset-0" />
          <div aria-hidden className="lp-grid pointer-events-none absolute inset-0" />
          <div className="lp-pad relative grid items-center gap-14 pt-16 pb-16 lg:min-h-[82vh] lg:grid-cols-[1fr_1.1fr] lg:pt-20">
            <div>
              <a
                href="#signals"
                className="inline-flex w-fit items-center gap-3 rounded-full border border-[var(--lp-line-2)] bg-white/[0.04] px-3.5 py-1.5 text-sm backdrop-blur hover:border-[var(--lp-dim)]"
              >
                <span className="relative flex size-2">
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-[var(--lp-teal)] opacity-60" />
                  <span className="relative inline-flex size-2 rounded-full bg-[var(--lp-teal)]" />
                </span>
                <span className="text-[13px] text-[var(--lp-fg)]">Now with AI security review on every pull request</span>
                <ChevronRight className="size-3.5" />
              </a>
              <h1 className="lp-display mt-7 text-[44px] leading-[1.04] md:text-[66px]">
                Your software supply chain is your <span className="lp-gradient-text">attack surface.</span>
              </h1>
              <p className="mt-6 max-w-xl text-[18px] leading-relaxed text-[var(--lp-fg)]/90">
                Every dependency is a potential entry point. depguard maps the paths into your codebase, catches malicious packages before execution, and gives security teams the control to stop them.
              </p>
              <ul className="mt-7 flex max-w-xl flex-wrap gap-2">
                {['Malware', 'CVEs & attack paths', 'Typosquats', 'Licenses', 'AI code review'].map((c) => (
                  <li key={c} className="inline-flex items-center gap-1.5 rounded-full border border-[var(--lp-line-2)] bg-white/[0.03] px-3 py-1 text-[13px] text-[var(--lp-fg)]">
                    <Check className="size-3.5 text-[var(--lp-teal)]" /> {c}
                  </li>
                ))}
              </ul>
              <div className="mt-9 flex flex-wrap items-center gap-4">
                <Link href={SIGN_UP} className="lp-btn lp-btn-primary px-6 py-3.5 text-[16px]">
                  Start scanning <ArrowRight className="size-4" />
                </Link>
                <Link href={`${SIGN_IN}?provider=github`} className="lp-btn lp-btn-ghost px-5 py-3.5 text-[16px]">
                  <GitHubIcon /> Sign in with GitHub
                </Link>
              </div>
              <p className="mt-6 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[var(--lp-dim)]">
                <span>GitHub App + CLI</span>
                <span aria-hidden>·</span>
                <span>Private, invite-only workspaces</span>
                <span aria-hidden>·</span>
                <a href="#how" className="lp-nudge inline-flex items-center gap-1 text-[var(--lp-fg)] hover:text-white">
                  How it works <ArrowRight className="size-3.5" />
                </a>
              </p>
            </div>

            <div className="relative mx-auto w-full max-w-[640px] lg:mx-0 xl:pt-[2rem]">
              <div className="absolute top-0 right-0 z-10 hidden xl:block">
                <HeroPRCard />
              </div>
              <ThreatSphere />
              <div className="relative z-10 -mt-20 flex justify-center lg:justify-start">
                <HeroTerminal />
              </div>
            </div>
          </div>

          {/* Ecosystems + numbers */}
          <div className="relative border-t border-[var(--lp-line)]">
            <div className="lp-marquee-wrap overflow-hidden py-6">
              <ul className="lp-marquee lp-mono gap-14 pr-14 text-lg text-[var(--lp-muted)]">
                {[...ECOSYSTEMS, ...ECOSYSTEMS].map((e, i) => (
                  <li key={i} className="flex items-center gap-14 whitespace-nowrap">
                    {e} <span className="text-[var(--lp-line-2)]">/</span>
                  </li>
                ))}
              </ul>
            </div>
            <dl className="grid grid-cols-2 border-t border-[var(--lp-line)] md:grid-cols-4">
              {STATS.map(([v, l], i) => (
                <div key={l} className={`lp-stat px-6 py-7 md:px-8 ${i % 2 ? 'border-l' : ''} ${i > 1 ? 'max-md:border-t' : ''} border-[var(--lp-line)] md:border-l md:first:border-l-0`}>
                  <dt className="lp-display text-[34px] text-white">{v}</dt>
                  <dd className="mt-1 text-sm text-[var(--lp-muted)]">{l}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
      </section>

      {/* Try it */}
      <section id="try" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad grid gap-12 py-24 lg:grid-cols-[1fr_1.1fr] lg:items-center">
          <div>
            <Eyebrow>Try it now</Eyebrow>
            <h2 className="lp-display mt-5 text-[34px] leading-[1.15] md:text-[40px]">
              Type a package.
              <br />
              <span className="text-[var(--lp-teal)]">See what depguard sees.</span>
            </h2>
            <p className="mt-5 max-w-md text-[17px] leading-relaxed text-[var(--lp-muted)]">
              An instant preview of the checks that run on every install and pull request: known malware, vulnerable versions and lookalike names. No sign-up.
            </p>
            <ul className="mt-6 space-y-2 text-[15px] text-[var(--lp-muted)]">
              {['Malware: blocked before any script runs', 'Vulnerabilities: with the exact fix command', 'Typosquats: one keystroke from a popular name'].map((l) => (
                <li key={l} className="flex items-center gap-2">
                  <Check className="size-4 text-[var(--lp-teal)]" /> {l}
                </li>
              ))}
            </ul>
          </div>
          <TryIt />
        </div>
      </section>

      {/* Signals */}
      <section id="signals" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad py-24">
          <SectionHead
            eyebrow="What it catches"
            a="A CVE feed isn't enough."
            b="Look at what packages do."
            body="Known vulnerabilities are half the picture. depguard also inspects package contents for install-time behaviour, checks licenses against your policy and traces every finding back to the dependency that introduced it."
          />
          <div className="mt-16">
            <div className="lp-eyebrow hidden grid-cols-[120px_90px_1fr_180px] gap-6 pb-4 text-[11px] text-[var(--lp-dim)] md:grid">
              <span>Signal</span>
              <span>Registry</span>
              <span>Example</span>
              <span className="text-right">Action</span>
            </div>
            {SIGNALS.map((s) => (
              <div key={s.title} className="lp-row grid gap-2 py-6 md:grid-cols-[120px_90px_1fr_180px] md:gap-6">
                <span className="lp-mono text-[15px] text-[var(--lp-muted)]">{s.kind}</span>
                <span className="lp-mono text-[15px] text-[var(--lp-dim)]">{s.eco}</span>
                <div>
                  <p className="text-[17px] font-medium text-white">{s.title}</p>
                  <p className="mt-1 text-[15px] text-[var(--lp-muted)]">{s.detail}</p>
                </div>
                <span className="lp-mono text-[15px] text-[var(--lp-teal)] md:text-right">{s.action}</span>
              </div>
            ))}
            <div className="lp-row flex flex-wrap items-center justify-between gap-6 pt-8">
              <p className="lp-mono flex flex-wrap gap-x-3 gap-y-2 text-[15px]">
                {SOURCES.map(([k, v], i) => (
                  <span key={k}>
                    <span className="text-white">{k}</span> <span className="text-[var(--lp-dim)]">{v}</span>
                    {i < SOURCES.length - 1 && <span className="ml-3 text-[var(--lp-dim)]">·</span>}
                  </span>
                ))}
              </p>
              <a href={`${REPO}/blob/master/docs/RISK-MODEL.md`} className="inline-flex items-center gap-2 text-[16px] text-[var(--lp-teal)] hover:text-white">
                Read the risk model <ArrowUpRight className="size-4" />
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Incidents */}
      <section id="incidents" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad py-24">
          <SectionHead
            eyebrow="Real attacks"
            tone="red"
            a="Would depguard catch it?"
            b="Six attacks everyone remembers."
            body="Supply-chain attacks are not hypothetical. Here is what happened in the best-known ones, and which depguard check answers each, including the one no scanner could see coming."
          />
          <Incidents />
        </div>
      </section>

      {/* Problem */}
      <section id="problem" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad py-24">
          <SectionHead
            eyebrow="The problem"
            tone="red"
            a="Nobody reviews what gets installed."
            b="It just runs."
            body="Third-party code enters at every hand-off, from a developer's terminal to a shared build cache. Each arrival executes with real permissions, and almost none of it is read by a human first."
          />

          <div className="relative mt-20">
            <div aria-hidden className="hidden lg:block">
              <div className="lp-rail">
                <div className="lp-sweep" />
              </div>
              <div className="lp-sweep-head">
                <span>
                  <svg viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M4 2l6 5-6 5" />
                  </svg>
                </span>
              </div>
              {[20, 40, 60, 80].map((x, i) => (
                <ChevronRight key={x} className="lp-chev" style={{ left: `${x}%`, animationDelay: `${(i + 0.5) * STEP}s` }} strokeWidth={1.75} />
              ))}
            </div>
            <div className="grid gap-x-6 gap-y-10 sm:grid-cols-2 lg:grid-cols-5">
              {STAGES.map((s, i) => (
                <div key={s.n} className="relative flex flex-col items-center">
                  <span className="lp-mono text-sm text-[var(--lp-dim)]">{s.n}</span>
                  <span className="lp-tile lp-hit relative mt-4 grid size-[72px] place-items-center border border-[var(--lp-line-2)] bg-[#0a0a0a]" style={{ animationDelay: `${i * STEP}s` }}>
                    <s.icon className="size-5 text-white" strokeWidth={1.5} />
                  </span>
                  <span className="mt-4 text-center text-[17px] text-white">{s.name}</span>
                  <div className="lp-hit-card mt-8 w-full flex-1 border border-[var(--lp-line-2)] bg-[var(--lp-panel)] p-5" style={{ animationDelay: `${i * STEP}s` }}>
                    <Eyebrow tone="dim">What gets in</Eyebrow>
                    <ul className="lp-mono mt-4 space-y-3 text-[15px] text-white">
                      {s.gets.map((g) => (
                        <li key={g} className="flex gap-2.5">
                          <span className="text-[var(--lp-red)]">•</span>
                          {g}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <p className="lp-eyebrow mt-12 text-center text-[13px] text-[var(--lp-muted)]">Five ways in. It only takes one.</p>

          {/* Answer */}
          <div className="mt-24">
            <div aria-hidden className="lp-beam" />
            <div className="mx-auto grid size-[72px] place-items-center border border-[var(--lp-teal)]/50 bg-[var(--lp-teal)]/[0.07] shadow-[0_0_40px_-8px_rgb(45_212_191/0.5)]">
              <Logo className="size-8" />
            </div>
            <div className="mt-10 text-center">
              <Eyebrow>The answer</Eyebrow>
              <h2 className="lp-display mt-5 text-[34px] md:text-[40px]">depguard watches every way in.</h2>
              <p className="mx-auto mt-5 max-w-2xl text-[17px] leading-relaxed text-[var(--lp-muted)]">
                One inventory and one policy, applied wherever a dependency shows up, so it is checked before it merges, builds or spreads.
              </p>
            </div>
            <div aria-hidden className="lp-guard-rail mx-auto mt-12 max-w-4xl" />
            <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
              {ANSWERS.map((a) => (
                <div key={a.n} className="lp-answer-card flex flex-col items-center p-6 text-center">
                  <p className="lp-mono text-sm">
                    <span className="text-[var(--lp-teal)]">{a.n}</span> <span className="text-[var(--lp-muted)]">{a.name}</span>
                  </p>
                  <span className="mt-5 grid size-8 place-items-center border border-[var(--lp-teal)]/50">
                    <Check className="size-4 text-[var(--lp-teal)]" />
                  </span>
                  <p className="mt-5 text-[17px] text-white">{a.head}</p>
                  <p className="lp-mono mt-3 text-sm leading-relaxed text-[var(--lp-muted)]">{a.sub}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Layers */}
      <section id="layers" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad py-24">
          <SectionHead
            eyebrow="Inside depguard"
            a="Pick a layer."
            b="See what depguard shows you."
            bTone="teal"
            body="Repositories, packages, attack paths, machines and policy, all in one console. Every view below mirrors a real screen in the product."
          />
          <div className="mt-14">
            <Layers />
          </div>
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="border-b border-[var(--lp-line)]">
        <div className="lp-frame lp-pad py-24">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="lp-display mt-5 max-w-2xl text-[34px] leading-[1.15] md:text-[40px]">
            Connected to enforced
            <br />
            <span className="text-[var(--lp-dim)]">in an afternoon.</span>
          </h2>
          <ol className="mt-16 grid gap-px border border-[var(--lp-line)] bg-[var(--lp-line)] md:grid-cols-3">
            {STEPS.map((s) => (
              <li key={s.n} className="bg-black p-8">
                <span className="lp-mono text-sm text-[var(--lp-teal)]">{s.n}</span>
                <h3 className="lp-display mt-4 text-2xl">{s.title}</h3>
                <p className="mt-3 text-[16px] leading-relaxed text-[var(--lp-muted)]">{s.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* CTA */}
      <section className="border-b border-[var(--lp-line)]">
        <div className="lp-frame relative overflow-hidden">
          <svg aria-hidden viewBox="0 0 1200 640" className="pointer-events-none absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid slice">
            <defs>
              <linearGradient id="lp-band" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0" stopColor="#8b5cf6" stopOpacity="0.55" />
                <stop offset="1" stopColor="#6d28d9" stopOpacity="0.15" />
              </linearGradient>
            </defs>
            <g fill="none" stroke="rgb(167 139 250 / 0.25)">
              <path d="M180 120 L340 60 L340 600 L180 540 Z" />
              <path d="M860 160 L940 130 L940 560 L860 590 Z" />
            </g>
            <path d="M340 160 L620 60 L840 60 L400 230 L400 600 L340 620 Z" fill="url(#lp-band)" />
            <path d="M860 470 L940 440 L940 560 L560 700 L400 700 Z" fill="url(#lp-band)" />
          </svg>
          <div className="lp-pad relative py-36 text-center">
            <h2 className="lp-display text-[44px] leading-[1.08] md:text-[56px]">
              Know what you ship.
              <br />
              Before it ships.
            </h2>
            <p className="mx-auto mt-6 max-w-md text-[17px] leading-relaxed text-[var(--lp-fg)]/90">Connect a repository and get your full dependency risk picture on the first scan.</p>
            <div className="mt-10 flex justify-center gap-4">
              <Link href={SIGN_UP} className="lp-btn lp-btn-primary px-6 py-3.5 text-[16px]">
                Start scanning
              </Link>
              <a href={DOCS} className="lp-btn lp-btn-ghost bg-black px-6 py-3.5 text-[16px]">
                Read the docs
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer>
        <div className="lp-frame lp-pad grid gap-12 py-16 md:grid-cols-[1.4fr_repeat(4,1fr)]">
          <div>
            <Link href="/" className="flex items-center gap-2">
              <Logo className="size-6" />
              <span className="lp-display text-xl">depguard</span>
            </Link>
            <p className="mt-4 max-w-xs text-[15px] leading-relaxed text-[var(--lp-muted)]">Supply-chain security for repositories, pipelines and developer machines.</p>
          </div>
          {FOOTER.map((col) => (
            <div key={col.h}>
              <p className="lp-eyebrow text-[12px] text-[var(--lp-muted)]">{col.h}</p>
              <ul className="mt-5 space-y-3 text-[15px]">
                {col.links.map(([label, href]) => (
                  <li key={label}>
                    <a href={href} className="text-[var(--lp-fg)] hover:text-white">
                      {label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="border-t border-[var(--lp-line)]">
          <p className="lp-frame lp-pad lp-mono py-6 text-sm text-[var(--lp-dim)]">© {new Date().getFullYear()} depguard</p>
        </div>
      </footer>
    </div>
  );
}
