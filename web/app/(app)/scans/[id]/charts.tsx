'use client';

import { useState } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, Label, Pie, PieChart, XAxis, YAxis } from 'recharts';
import { Printer } from 'lucide-react';
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import { Button } from '@/components/ui/button';

// Same severity palette as the dashboard (CVD-checked there).
export const SEVERITY_COLORS = {
  critical: '#b91c1c',
  high: '#f97316',
  medium: '#a16207',
  low: '#0284c7',
} as const;
type Sev = keyof typeof SEVERITY_COLORS;
const axis = {
  tickLine: false,
  axisLine: false,
  tickMargin: 8,
  fontSize: 12,
} as const;
// Animations off so charts are fully drawn when the page is printed to PDF.
const still = { isAnimationActive: false } as const;

const sevCfg = {
  critical: { label: 'Critical', color: SEVERITY_COLORS.critical },
  high: { label: 'High', color: SEVERITY_COLORS.high },
  medium: { label: 'Medium', color: SEVERITY_COLORS.medium },
  low: { label: 'Low', color: SEVERITY_COLORS.low },
} satisfies ChartConfig;

export function SeverityDonut({ counts }: { counts: Record<Sev, number> }) {
  const data = (Object.keys(SEVERITY_COLORS) as Sev[]).map((k) => ({ key: k, value: counts[k] })).filter((d) => d.value);
  const total = data.reduce((n, d) => n + d.value, 0);
  if (!total) return <Empty text="No known vulnerabilities" />;
  return (
    <div className="flex items-center gap-4">
      <ChartContainer config={sevCfg} className="aspect-square h-44 shrink-0" role="img" aria-label={`Vulnerabilities by severity, ${total} in total`}>
        <PieChart>
          <ChartTooltip content={<ChartTooltipContent nameKey="key" hideLabel />} />
          <Pie data={data} dataKey="value" nameKey="key" innerRadius={52} outerRadius={78} strokeWidth={2} {...still}>
            {data.map((d) => (
              <Cell key={d.key} fill={SEVERITY_COLORS[d.key]} />
            ))}
            <Label
              content={({ viewBox }) =>
                viewBox && 'cx' in viewBox ? (
                  <text x={viewBox.cx} y={viewBox.cy} textAnchor="middle" dominantBaseline="middle">
                    <tspan x={viewBox.cx} y={viewBox.cy} className="fill-foreground text-2xl font-semibold">
                      {total}
                    </tspan>
                    <tspan x={viewBox.cx} y={(viewBox.cy ?? 0) + 20} className="fill-muted-foreground text-xs">
                      advisories
                    </tspan>
                  </text>
                ) : null
              }
            />
          </Pie>
        </PieChart>
      </ChartContainer>
      <ul className="grid flex-1 gap-1.5 text-sm">
        {(Object.keys(SEVERITY_COLORS) as Sev[]).map((k) => (
          <li key={k} className="flex items-center gap-2">
            <span className="size-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[k] }} aria-hidden />
            <span className="text-muted-foreground">{sevCfg[k].label}</span>
            <span className="ml-auto font-medium tabular-nums">{counts[k]}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const catCfg = {
  blocking: { label: 'Blocking', color: '#b91c1c' },
  warning: { label: 'Warning', color: '#d97706' },
} satisfies ChartConfig;

export function FindingsByCategory({ data }: { data: { category: string; blocking: number; warning: number }[] }) {
  if (!data.some((d) => d.blocking + d.warning)) return <Empty text="No policy findings" />;
  return (
    <ChartContainer config={catCfg} className="h-44 w-full" role="img" aria-label="Policy findings by category, blocking and warning">
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 16 }}>
        <CartesianGrid horizontal={false} strokeOpacity={0.5} />
        <XAxis type="number" allowDecimals={false} {...axis} />
        <YAxis type="category" dataKey="category" width={92} {...axis} />
        <ChartTooltip cursor={{ fillOpacity: 0.3 }} content={<ChartTooltipContent />} />
        <Bar dataKey="blocking" stackId="a" fill="var(--color-blocking)" radius={[4, 0, 0, 4]} maxBarSize={22} {...still} />
        <Bar dataKey="warning" stackId="a" fill="var(--color-warning)" radius={[0, 4, 4, 0]} maxBarSize={22} {...still} />
      </BarChart>
    </ChartContainer>
  );
}

const depthCfg = {
  count: { label: 'Vulnerable packages', color: 'var(--chart-1)' },
} satisfies ChartConfig;

export function VulnsByDepth({ data }: { data: { depth: string; count: number }[] }) {
  if (!data.some((d) => d.count)) return <Empty text="No vulnerable packages" />;
  return (
    <ChartContainer config={depthCfg} className="h-44 w-full" role="img" aria-label="Vulnerable packages by dependency depth">
      <BarChart data={data} margin={{ left: 0, right: 8 }}>
        <CartesianGrid vertical={false} strokeOpacity={0.5} />
        <XAxis dataKey="depth" interval={0} {...axis} />
        <YAxis allowDecimals={false} width={32} {...axis} />
        <ChartTooltip cursor={{ fillOpacity: 0.3 }} content={<ChartTooltipContent hideIndicator />} />
        <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} maxBarSize={40} {...still} />
      </BarChart>
    </ChartContainer>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="flex h-44 items-center justify-center text-sm text-muted-foreground">{text}</div>;
}

/** Opens the browser print dialog; the page has print styles, so "Save as PDF" gives a clean report. */
export function SavePdfButton() {
  return (
    <Button variant="outline" size="sm" onClick={() => window.print()}>
      <Printer /> Save as PDF
    </Button>
  );
}

/** Shows the first `shown` rows with a toggle for the rest; whatever is expanded is also what prints. */
export function ShowMore({
  rows,
  shown,
  label,
  as = 'ol',
  className,
  head,
}: {
  rows: React.ReactNode[];
  shown: number;
  label: string;
  as?: 'ol' | 'table';
  className?: string;
  head?: React.ReactNode;
}) {
  const [all, setAll] = useState(false);
  const visible = all ? rows : rows.slice(0, shown);
  return (
    <>
      {as === 'table' ? (
        <table className={className}>
          {head}
          <tbody>{visible}</tbody>
        </table>
      ) : (
        <ol className={className}>{visible}</ol>
      )}
      {rows.length > shown && (
        <button type="button" onClick={() => setAll(!all)} className="mt-2 text-sm font-medium text-primary hover:underline print:hidden">
          {all ? 'Show fewer' : `Show all ${rows.length} ${label}`}
        </button>
      )}
    </>
  );
}
