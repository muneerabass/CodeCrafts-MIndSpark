'use client';

import { parseAsStringLiteral, useQueryState } from 'nuqs';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, XAxis, YAxis } from 'recharts';
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { Dashboard } from '@/lib/types';

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

const day = (d: string) => `${d.slice(8, 10)}/${d.slice(5, 7)}`;
const axis = { tickLine: false, axisLine: false, tickMargin: 8, fontSize: 12 } as const;

function NoData() {
  return <div className="flex h-56 items-center justify-center text-sm text-muted-foreground">No data</div>;
}

const countCfg = { count: { label: 'Violations', color: 'var(--chart-1)' } } satisfies ChartConfig;
export function ViolationsOverTime({ data }: { data: Dashboard['violations_over_time'] }) {
  if (!data.some((d) => d.count)) return <NoData />;
  return (
    <ChartContainer config={countCfg} className="h-56 w-full" role="img" aria-label="Policy violations per day">
      <AreaChart data={data} margin={{ left: 0, right: 8 }}>
        <CartesianGrid vertical={false} strokeOpacity={0.5} />
        <XAxis dataKey="date" tickFormatter={day} minTickGap={24} {...axis} />
        <YAxis allowDecimals={false} width={32} {...axis} />
        <ChartTooltip content={<ChartTooltipContent labelFormatter={(v) => day(String(v))} />} />
        <Area dataKey="count" type="monotone" stroke="var(--color-count)" strokeWidth={2} fill="var(--color-count)" fillOpacity={0.15} />
      </AreaChart>
    </ChartContainer>
  );
}

const checkCfg = { count: { label: 'Violations', color: 'var(--chart-1)' } } satisfies ChartConfig;
export function ViolationChecks({ data }: { data: Dashboard['violations_by_check'] }) {
  if (!data.length) return <NoData />;
  const rows = data.map((d) => ({ ...d, check: d.check[0].toUpperCase() + d.check.slice(1) }));
  return (
    <ChartContainer config={checkCfg} className="h-56 w-full" role="img" aria-label="Policy violations by check">
      <BarChart data={rows} margin={{ left: 0, right: 8 }}>
        <CartesianGrid vertical={false} strokeOpacity={0.5} />
        <XAxis dataKey="check" {...axis} />
        <YAxis allowDecimals={false} width={32} {...axis} />
        <ChartTooltip cursor={{ fillOpacity: 0.3 }} content={<ChartTooltipContent hideIndicator />} />
        <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} maxBarSize={40} />
      </BarChart>
    </ChartContainer>
  );
}

// Severity palette validated with the dataviz checker (CVD + normal-vision separation pass; legend + tooltip as relief).
const riskCfg = {
  critical: { label: 'Critical', color: '#b91c1c' },
  high: { label: 'High', color: '#f97316' },
  medium: { label: 'Medium', color: '#a16207' },
  low: { label: 'Low', color: '#0284c7' },
} satisfies ChartConfig;
export function VulnsOverTime({ data }: { data: Dashboard['vulns_over_time'] }) {
  if (!data.some((d) => d.critical + d.high + d.medium + d.low)) return <NoData />;
  return (
    <ChartContainer config={riskCfg} className="h-64 w-full" role="img" aria-label="Vulnerabilities by risk per day">
      <BarChart data={data} margin={{ left: 0, right: 8 }}>
        <CartesianGrid vertical={false} strokeOpacity={0.5} />
        <XAxis dataKey="date" tickFormatter={day} minTickGap={24} {...axis} />
        <YAxis allowDecimals={false} width={32} {...axis} />
        <ChartTooltip cursor={{ fillOpacity: 0.3 }} content={<ChartTooltipContent labelFormatter={(v) => day(String(v))} />} />
        <ChartLegend content={<ChartLegendContent />} />
        {(['low', 'medium', 'high', 'critical'] as const).map((k, i) => (
          <Bar key={k} dataKey={k} stackId="r" fill={`var(--color-${k})`} stroke="var(--card)" strokeWidth={1} radius={i === 3 ? [4, 4, 0, 0] : 0} />
        ))}
      </BarChart>
    </ChartContainer>
  );
}
