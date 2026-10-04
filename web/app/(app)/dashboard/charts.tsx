'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { parseAsStringLiteral, useQueryState } from 'nuqs';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, XAxis, YAxis } from 'recharts';
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { Dashboard } from '@/lib/types';
import { cn } from '@/lib/utils';

export function RangeSelect() {
  const [range, setRange] = useQueryState('range', parseAsStringLiteral(['7d', '30d', '90d']).withDefault('30d').withOptions({ shallow: false }));
  return (
    <Select value={range} onValueChange={(v) => setRange(v as '7d' | '30d' | '90d')}>
      <SelectTrigger className="w-36 bg-background" aria-label="Time range">
        <SelectValue />
      </SelectTrigger>
      <SelectContent align="end">
        <SelectItem value="7d">7 days</SelectItem>
        <SelectItem value="30d">1 month</SelectItem>
        <SelectItem value="90d">3 months</SelectItem>
      </SelectContent>
    </Select>
  );
}

const reduced = () => typeof window !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches;

/** A number that counts up from 0 when it first renders (the real value is in the HTML). */
export function CountUp({ value, suffix = '' }: { value: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || reduced() || value === 0) return;
    const fmt = (v: number) => v.toLocaleString('en-GB') + suffix;
    let raf = 0;
    const t0 = performance.now();
    const step = (t: number) => {
      const p = Math.min(1, (t - t0) / 1100);
      el.textContent = fmt(Math.round(value * (1 - Math.pow(1 - p, 4))));
      if (p < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => {
      cancelAnimationFrame(raf);
      el.textContent = fmt(value);
    };
  }, [value, suffix]);
  return (
    <span ref={ref}>
      {value.toLocaleString('en-GB')}
      {suffix}
    </span>
  );
}

/** A link card with a soft spotlight that follows the pointer. */
export function Spotlight({ href, className, glow = 'var(--primary)', children, label }: { href: string; className?: string; glow?: string; children: React.ReactNode; label?: string }) {
  const ref = useRef<HTMLAnchorElement>(null);
  return (
    <Link
      ref={ref}
      href={href}
      aria-label={label}
      onMouseMove={(e) => {
        const r = ref.current!.getBoundingClientRect();
        ref.current!.style.setProperty('--sx', `${e.clientX - r.left}px`);
        ref.current!.style.setProperty('--sy', `${e.clientY - r.top}px`);
      }}
      style={{ ['--glow' as string]: glow }}
      className={cn(
        'group relative block overflow-hidden rounded-2xl border bg-card transition-all duration-300 hover:-translate-y-0.5 hover:border-[color-mix(in_oklab,var(--glow)_45%,transparent)] hover:shadow-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
        'before:pointer-events-none before:absolute before:inset-0 before:opacity-0 before:transition-opacity before:duration-300 before:content-[""] hover:before:opacity-100',
        'before:bg-[radial-gradient(260px_circle_at_var(--sx,50%)_var(--sy,0%),color-mix(in_oklab,var(--glow)_16%,transparent),transparent_70%)]',
        className,
      )}
    >
      {children}
    </Link>
  );
}

/** Tiny trend line for a KPI tile. */
export function Sparkline({ data, color, id }: { data: number[]; color: string; id: string }) {
  if (data.length < 2 || !data.some(Boolean)) return <div className="h-10" />;
  const rows = data.map((v, i) => ({ i, v }));
  return (
    <ChartContainer config={{ v: { label: 'Value', color } }} className="h-10 w-full [&_.recharts-surface]:overflow-visible" aria-hidden>
      <AreaChart data={rows} margin={{ top: 2, bottom: 2, left: 0, right: 0 }}>
        <defs>
          <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area dataKey="v" type="monotone" stroke={color} strokeWidth={1.75} fill={`url(#spark-${id})`} isAnimationActive={!reduced()} dot={false} />
      </AreaChart>
    </ChartContainer>
  );
}

/** Animated posture score ring. */
export function ScoreGauge({ score, color }: { score: number; color: string }) {
  const [shown, setShown] = useState(reduced() ? score : 0);
  useEffect(() => {
    const t = setTimeout(() => setShown(score), 80);
    return () => clearTimeout(t);
  }, [score]);
  const r = 52;
  const c = 2 * Math.PI * r;
  const arc = 0.75; // 270° gauge
  return (
    <div className="relative size-40 shrink-0">
      <svg viewBox="0 0 128 128" className="size-full -rotate-[225deg]" aria-hidden>
        <circle cx="64" cy="64" r={r} fill="none" stroke="currentColor" strokeWidth="10" strokeLinecap="round" className="text-muted" strokeDasharray={`${c * arc} ${c}`} />
        <circle
          cx="64"
          cy="64"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${(c * arc * shown) / 100} ${c}`}
          style={{ transition: 'stroke-dasharray 1.4s cubic-bezier(.2,.7,.2,1)', filter: `drop-shadow(0 0 6px color-mix(in oklab, ${color} 55%, transparent))` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-semibold tracking-tight tabular-nums">
          <CountUp value={score} />
        </span>
        <span className="text-[11px] tracking-wider text-muted-foreground uppercase">out of 100</span>
      </div>
    </div>
  );
}

// Severity palette validated with the dataviz checker (CVD + normal-vision separation pass; legend + tooltip as relief).
export const RISK = [
  { key: 'critical', label: 'Critical', color: '#dc2626', q: 'CRITICAL' },
  { key: 'high', label: 'High', color: '#f97316', q: 'HIGH' },
  { key: 'medium', label: 'Medium', color: '#ca8a04', q: 'MEDIUM' },
  { key: 'low', label: 'Low', color: '#0284c7', q: 'LOW' },
] as const;
type RiskKey = (typeof RISK)[number]['key'];

/** Open vulnerabilities by risk; hovering a slice or a legend row focuses it. */
export function RiskDonut({ data }: { data: Record<RiskKey, number> }) {
  const [active, setActive] = useState<number | null>(null);
  const rows = RISK.map((r) => ({ ...r, value: data[r.key] }));
  const total = rows.reduce((a, r) => a + r.value, 0);
  const focus = active === null ? null : rows[active];
  if (!total)
    return <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">No open vulnerabilities</div>;
  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row lg:flex-col xl:flex-row">
      <div className="relative size-44 shrink-0">
        <ChartContainer config={{}} className="size-full" role="img" aria-label="Open vulnerabilities by risk">
          <PieChart>
            <Pie
              data={rows}
              dataKey="value"
              nameKey="label"
              innerRadius={58}
              outerRadius={80}
              paddingAngle={rows.filter((r) => r.value).length > 1 ? 3 : 0}
              cornerRadius={6}
              stroke="none"
              isAnimationActive={!reduced()}
              onMouseLeave={() => setActive(null)}
            >
              {rows.map((r, i) => (
                <Cell key={r.key} fill={r.color} opacity={active === null || active === i ? 1 : 0.25} onMouseEnter={() => setActive(i)} style={{ transition: 'opacity .2s', cursor: 'pointer', outline: 'none' }} />
              ))}
            </Pie>
          </PieChart>
        </ChartContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-semibold tabular-nums">{(focus?.value ?? total).toLocaleString('en-GB')}</span>
          <span className="text-xs text-muted-foreground">{focus ? focus.label : 'open'}</span>
        </div>
      </div>
      <ul className="w-full min-w-0 flex-1 space-y-1.5" aria-label="Open vulnerabilities by risk">
        {rows.map((r, i) => (
          <li key={r.key}>
            <Link
              href={`/vulnerabilities?risk=${r.q}`}
              onMouseEnter={() => setActive(i)}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive(i)}
              onBlur={() => setActive(null)}
              className={cn('flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors hover:bg-muted', active === i && 'bg-muted')}
            >
              <span className="size-2.5 shrink-0 rounded-full" style={{ background: r.color }} />
              <span className="flex-1">{r.label}</span>
              <span className="font-medium tabular-nums">{r.value.toLocaleString('en-GB')}</span>
              <span className="w-10 text-right text-xs text-muted-foreground tabular-nums">{Math.round((r.value / total) * 100)}%</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

const day = (d: string) => `${d.slice(8, 10)}/${d.slice(5, 7)}`;
const axis = { tickLine: false, axisLine: false, tickMargin: 8, fontSize: 12 } as const;

function NoData({ text = 'No data' }: { text?: string }) {
  return <div className="flex h-56 items-center justify-center text-sm text-muted-foreground">{text}</div>;
}

const riskCfg = Object.fromEntries(RISK.map((r) => [r.key, { label: r.label, color: r.color }])) satisfies ChartConfig;

/** New vulnerabilities per day, stacked by risk. Legend pills toggle each series. */
export function VulnsOverTime({ data }: { data: Dashboard['vulns_over_time'] }) {
  const [off, setOff] = useState<Set<RiskKey>>(new Set());
  const totals = Object.fromEntries(RISK.map((r) => [r.key, data.reduce((a, d) => a + d[r.key], 0)])) as Record<RiskKey, number>;
  const empty = !data.some((d) => d.critical + d.high + d.medium + d.low);
  const toggle = (k: RiskKey) =>
    setOff((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else if (n.size < RISK.length - 1) n.add(k);
      return n;
    });
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2" role="group" aria-label="Show or hide risk levels">
        {RISK.map((r) => {
          const on = !off.has(r.key);
          return (
            <button
              key={r.key}
              type="button"
              aria-pressed={on}
              onClick={() => toggle(r.key)}
              className={cn('inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-all', on ? 'bg-background shadow-xs' : 'opacity-45 hover:opacity-80')}
            >
              <span className="size-2 rounded-full" style={{ background: r.color }} />
              {r.label}
              <span className="text-muted-foreground tabular-nums">{totals[r.key].toLocaleString('en-GB')}</span>
            </button>
          );
        })}
      </div>
      {empty ? (
        <NoData text="No new vulnerabilities in this period" />
      ) : (
        <ChartContainer config={riskCfg} className="h-64 w-full" role="img" aria-label="New vulnerabilities by risk per day">
          <AreaChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
            <defs>
              {RISK.map((r) => (
                <linearGradient key={r.key} id={`risk-${r.key}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={r.color} stopOpacity={0.55} />
                  <stop offset="100%" stopColor={r.color} stopOpacity={0.05} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} strokeOpacity={0.4} strokeDasharray="3 4" />
            <XAxis dataKey="date" tickFormatter={day} minTickGap={24} {...axis} />
            <YAxis allowDecimals={false} width={32} {...axis} />
            <ChartTooltip cursor={{ strokeOpacity: 0.4 }} content={<ChartTooltipContent indicator="dot" labelFormatter={(v) => day(String(v))} />} />
            {[...RISK].reverse().map((r) =>
              off.has(r.key) ? null : (
                <Area key={r.key} dataKey={r.key} stackId="r" type="monotone" stroke={r.color} strokeWidth={1.75} fill={`url(#risk-${r.key})`} isAnimationActive={!reduced()} />
              ),
            )}
          </AreaChart>
        </ChartContainer>
      )}
    </div>
  );
}

const countCfg = { count: { label: 'Violations', color: 'var(--chart-1)' } } satisfies ChartConfig;
export function ViolationsOverTime({ data }: { data: Dashboard['violations_over_time'] }) {
  if (!data.some((d) => d.count)) return <NoData />;
  return (
    <ChartContainer config={countCfg} className="h-56 w-full" role="img" aria-label="Policy violations per day">
      <AreaChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
        <defs>
          <linearGradient id="viol-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-count)" stopOpacity={0.45} />
            <stop offset="100%" stopColor="var(--color-count)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} strokeOpacity={0.4} strokeDasharray="3 4" />
        <XAxis dataKey="date" tickFormatter={day} minTickGap={24} {...axis} />
        <YAxis allowDecimals={false} width={32} {...axis} />
        <ChartTooltip content={<ChartTooltipContent indicator="line" labelFormatter={(v) => day(String(v))} />} />
        <Area dataKey="count" type="monotone" stroke="var(--color-count)" strokeWidth={2} fill="url(#viol-fill)" activeDot={{ r: 5, strokeWidth: 2 }} isAnimationActive={!reduced()} />
      </AreaChart>
    </ChartContainer>
  );
}

const CHECK_COLORS = ['var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)'];
const checkCfg = { count: { label: 'Violations', color: 'var(--chart-1)' } } satisfies ChartConfig;
/** Which kinds of rule fail most: horizontal bars, each linking to the filtered list. */
export function ViolationChecks({ data }: { data: Dashboard['violations_by_check'] }) {
  const router = useRouter();
  if (!data.length) return <NoData />;
  const rows = data.map((d) => ({ ...d, label: d.check[0].toUpperCase() + d.check.slice(1) }));
  return (
    <ChartContainer config={checkCfg} className="w-full" style={{ height: Math.max(160, rows.length * 44) }} role="img" aria-label="Policy violations by check">
      <BarChart data={rows} layout="vertical" margin={{ left: 4, right: 40 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="label" width={96} {...axis} />
        <ChartTooltip cursor={{ fillOpacity: 0.25 }} content={<ChartTooltipContent hideIndicator />} />
        <Bar
          dataKey="count"
          radius={[0, 6, 6, 0]}
          barSize={20}
          label={{ position: 'right', className: 'fill-foreground text-xs tabular-nums' }}
          className="cursor-pointer"
          onClick={(e) => {
            const c = (e.payload as { check?: string } | undefined)?.check;
            if (c) router.push(`/policy/violations?category=${encodeURIComponent(c)}`);
          }}
          isAnimationActive={!reduced()}
        >
          {rows.map((r, i) => (
            <Cell key={r.check} fill={CHECK_COLORS[i % CHECK_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}
