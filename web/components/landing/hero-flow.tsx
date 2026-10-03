import { Logo } from '@/components/icons';

// Packages flow from registries into depguard and out to where they are enforced.
// Pure SVG/CSS animation (SMIL + keyframes): no client JS, paused for reduced motion via CSS.

const SOURCES = [
  { label: 'npm', y: 70 },
  { label: 'PyPI', y: 170 },
  { label: 'Go', y: 270 },
  { label: 'Maven', y: 370 },
];
const OUTS = [
  { label: 'PR check', sub: 'blocked · critical', y: 110, tone: 'red' },
  { label: 'CLI install', sub: 'stopped before run', y: 220, tone: 'violet' },
  { label: 'Dashboard', sub: 'ranked by risk', y: 330, tone: 'green' },
];
const CORE = { x: 300, y: 220 };

const inPath = (y: number) => `M118 ${y} C 200 ${y}, 220 ${CORE.y}, ${CORE.x - 58} ${CORE.y}`;
const outPath = (y: number) => `M${CORE.x + 58} ${CORE.y} C 380 ${CORE.y}, 390 ${y}, 452 ${y}`;

// Dots travelling into the core: colour says what depguard found.
const DOTS_IN = [
  { s: 0, c: '#34d399', d: 0 },
  { s: 1, c: '#f87171', d: 0.8 },
  { s: 2, c: '#34d399', d: 1.6 },
  { s: 3, c: '#fbbf24', d: 2.4 },
  { s: 0, c: '#34d399', d: 3.2 },
  { s: 2, c: '#f87171', d: 4 },
];
const DOTS_OUT = [
  { o: 0, c: '#f87171', d: 1.6 },
  { o: 1, c: '#a78bfa', d: 2.6 },
  { o: 2, c: '#34d399', d: 3.6 },
  { o: 0, c: '#f87171', d: 5.2 },
];

const outTone: Record<string, string> = { red: '#f87171', violet: '#a78bfa', green: '#34d399' };

export function HeroFlow() {
  return (
    <div className="lp-flow relative" aria-hidden>
      <svg viewBox="0 0 600 440" className="h-auto w-full overflow-visible">
        <defs>
          <radialGradient id="hf-core" cx="50%" cy="50%" r="50%">
            <stop offset="0" stopColor="#8b5cf6" stopOpacity="0.55" />
            <stop offset="1" stopColor="#8b5cf6" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="hf-line" x1="0" x2="1">
            <stop offset="0" stopColor="#ffffff" stopOpacity="0.06" />
            <stop offset="1" stopColor="#a78bfa" stopOpacity="0.45" />
          </linearGradient>
          <linearGradient id="hf-line-out" x1="0" x2="1">
            <stop offset="0" stopColor="#a78bfa" stopOpacity="0.45" />
            <stop offset="1" stopColor="#ffffff" stopOpacity="0.08" />
          </linearGradient>
        </defs>

        {/* wires */}
        {SOURCES.map((s) => (
          <path key={s.label} d={inPath(s.y)} fill="none" stroke="url(#hf-line)" strokeWidth="1.5" className="lp-wire" />
        ))}
        {OUTS.map((o) => (
          <path key={o.label} d={outPath(o.y)} fill="none" stroke="url(#hf-line-out)" strokeWidth="1.5" className="lp-wire" />
        ))}

        {/* travelling packages */}
        {DOTS_IN.map((p, i) => (
          <circle key={`i${i}`} r="4.5" fill={p.c} opacity="0" className="lp-dot">
            <animateMotion dur="2.4s" begin={`${p.d}s`} repeatCount="indefinite" path={inPath(SOURCES[p.s].y)} keyPoints="0;1" keyTimes="0;1" calcMode="linear" />
            <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur="2.4s" begin={`${p.d}s`} repeatCount="indefinite" />
          </circle>
        ))}
        {DOTS_OUT.map((p, i) => (
          <circle key={`o${i}`} r="4.5" fill={p.c} opacity="0" className="lp-dot">
            <animateMotion dur="2s" begin={`${p.d}s`} repeatCount="indefinite" path={outPath(OUTS[p.o].y)} />
            <animate attributeName="opacity" values="0;1;1;0" keyTimes="0;0.1;0.85;1" dur="2s" begin={`${p.d}s`} repeatCount="indefinite" />
          </circle>
        ))}

        {/* sources */}
        {SOURCES.map((s, i) => (
          <g key={s.label} transform={`translate(18 ${s.y - 18})`} className="lp-node" style={{ animationDelay: `${i * 0.12}s` }}>
            <rect width="100" height="36" rx="8" fill="#0b0b10" stroke="rgb(255 255 255 / 14%)" />
            <circle cx="18" cy="18" r="4" fill="#a78bfa" />
            <text x="32" y="23" fill="#e5e7eb" fontSize="14" fontFamily="var(--lp-mono), monospace">
              {s.label}
            </text>
          </g>
        ))}

        {/* core */}
        <circle cx={CORE.x} cy={CORE.y} r="120" fill="url(#hf-core)" className="lp-core-glow" />
        <circle cx={CORE.x} cy={CORE.y} r="78" fill="none" stroke="rgb(167 139 250 / 25%)" strokeDasharray="4 7" className="lp-orbit" />
        <circle cx={CORE.x} cy={CORE.y} r="96" fill="none" stroke="rgb(167 139 250 / 12%)" strokeDasharray="2 10" className="lp-orbit lp-orbit-rev" />
        <circle cx={CORE.x} cy={CORE.y} r="58" fill="#0b0b12" stroke="rgb(167 139 250 / 60%)" strokeWidth="1.5" />
        <circle cx={CORE.x} cy={CORE.y} r="58" fill="none" stroke="#a78bfa" strokeWidth="2" className="lp-ping" />

        {/* outcomes */}
        {OUTS.map((o, i) => (
          <g key={o.label} transform={`translate(452 ${o.y - 24})`} className="lp-node" style={{ animationDelay: `${0.4 + i * 0.12}s` }}>
            <rect width="140" height="48" rx="10" fill="#0b0b10" stroke="rgb(255 255 255 / 14%)" />
            <rect x="0" y="10" width="3" height="28" rx="1.5" fill={outTone[o.tone]} />
            <text x="14" y="21" fill="#ffffff" fontSize="13.5" fontWeight="500">
              {o.label}
            </text>
            <text x="14" y="37" fill={outTone[o.tone]} fontSize="11.5" fontFamily="var(--lp-mono), monospace">
              {o.sub}
            </text>
          </g>
        ))}
      </svg>
      {/* logo sits on top of the core (HTML so it uses the real gradient logo) */}
      <div className="pointer-events-none absolute grid place-items-center" style={{ left: `${(CORE.x / 600) * 100}%`, top: `${(CORE.y / 440) * 100}%`, transform: 'translate(-50%, -50%)' }}>
        <Logo className="size-12 drop-shadow-[0_0_18px_rgb(167_139_250/0.6)]" />
      </div>
    </div>
  );
}

const TERMINAL = [
  { t: '$ npm install lodash@4.17.21', c: 'text-white' },
  { t: '  depguard ✓ clean · 0 advisories', c: 'text-emerald-400' },
  { t: '$ npm install event-stream-lite', c: 'text-white' },
  { t: '  depguard ✖ blocked · known malware (MAL-2026-1337)', c: 'text-red-400' },
  { t: '$ pip install requets', c: 'text-white' },
  { t: '  depguard ⚠ looks like "requests" · typosquat', c: 'text-amber-300' },
];

/** A terminal that "types" checked installs line by line, then loops. */
export function HeroTerminal() {
  return (
    <div className="lp-term w-full max-w-md overflow-hidden rounded-xl border border-[var(--lp-line-2)] bg-[#07070b]/95 shadow-2xl shadow-violet-950/40 backdrop-blur" aria-hidden>
      <div className="flex items-center gap-1.5 border-b border-[var(--lp-line)] px-3 py-2">
        <span className="size-2.5 rounded-full bg-red-400/70" />
        <span className="size-2.5 rounded-full bg-amber-300/70" />
        <span className="size-2.5 rounded-full bg-emerald-400/70" />
        <span className="lp-mono ml-2 text-[11px] text-[var(--lp-dim)]">~/app · depguard guard</span>
      </div>
      <div className="lp-mono space-y-1 px-4 py-3 text-[12.5px] leading-relaxed">
        {TERMINAL.map((l, i) => (
          <p key={i} className={`lp-line ${l.c}`} style={{ animationDelay: `${i * 0.9}s` }}>
            {l.t}
          </p>
        ))}
        <p className="lp-line text-white" style={{ animationDelay: `${TERMINAL.length * 0.9}s` }}>
          $ <span className="lp-caret" />
        </p>
      </div>
    </div>
  );
}

/** Floating pull-request verdict card. */
export function HeroPRCard() {
  return (
    <div className="lp-float w-64 rounded-xl border border-[var(--lp-line-2)] bg-[#0b0b12]/95 p-3.5 shadow-2xl shadow-violet-950/40 backdrop-blur" aria-hidden>
      <div className="flex items-center justify-between">
        <span className="lp-mono text-[11px] text-[var(--lp-dim)]">PR #482 · payments-api</span>
        <span className="rounded bg-red-500/90 px-1.5 py-0.5 text-[10px] font-semibold text-white">Critical 100</span>
      </div>
      <p className="mt-2 text-[13px] font-medium text-white">Add Stripe webhooks</p>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {[
          ['Malware', 'bg-red-500/15 text-red-300'],
          ['2 vulns', 'bg-orange-500/15 text-orange-300'],
          ['SQL injection', 'bg-amber-500/15 text-amber-200'],
        ].map(([l, c]) => (
          <span key={l} className={`rounded-md px-1.5 py-0.5 text-[10.5px] font-medium ${c}`}>
            {l}
          </span>
        ))}
      </div>
      <div className="mt-3 flex items-center gap-2 border-t border-[var(--lp-line)] pt-2.5 text-[11px] text-[var(--lp-muted)]">
        <span className="size-1.5 animate-pulse rounded-full bg-red-400" /> depguard check failing · fix before merging
      </div>
    </div>
  );
}
