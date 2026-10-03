'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from 'recharts';
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Chip, RiskBadge } from '@/components/badges';
import { Ecosystem } from '@/components/icons';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useAction } from '@/components/client';
import { saveProjectSettings } from '@/lib/actions';
import { titleCase } from '@/lib/format';
import type { LicenseReport, ProjectSettings, UsageModel } from '@/lib/types';
import { USAGE_MODELS } from '@/lib/format';

export function ProjectLicenseForm({ projectId, settings, canEdit }: { projectId: string; settings: ProjectSettings; canEdit: boolean }) {
  const initial = { license: settings.license_source === 'override' ? settings.license ?? '' : '', usage_model: settings.usage_model };
  const [v, setV] = useState(initial);
  const { pending, run } = useAction();
  const dirty = v.license !== initial.license || v.usage_model !== initial.usage_model;
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        run(() => saveProjectSettings(projectId, { license: v.license, usage_model: v.usage_model }), 'Project license settings saved');
      }}
    >
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
        <dt className="text-muted-foreground">Project license</dt>
        <dd className="font-mono font-medium">{settings.license ?? 'Unknown'}</dd>
        <dt className="text-muted-foreground">Source</dt>
        <dd>
          <Chip>{titleCase(settings.license_source ?? 'unknown')}</Chip>
        </dd>
        <dt className="text-muted-foreground">Detected</dt>
        <dd className="font-mono">{settings.detected_license ?? '—'}</dd>
      </dl>
      <div className="grid gap-1.5">
        <Label htmlFor="pl-license">License override (SPDX)</Label>
        <Input id="pl-license" value={v.license} placeholder={settings.detected_license ?? 'e.g. MIT'} disabled={!canEdit} onChange={(e) => setV({ ...v, license: e.target.value })} />
        <p className="text-xs text-muted-foreground">Leave empty to use the detected license.</p>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="pl-usage">Usage model</Label>
        <Select value={v.usage_model} onValueChange={(u) => setV({ ...v, usage_model: u as UsageModel })} disabled={!canEdit}>
          <SelectTrigger id="pl-usage" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {USAGE_MODELS.map((m) => (
              <SelectItem key={m.value} value={m.value}>
                {m.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">{USAGE_MODELS.find((m) => m.value === v.usage_model)?.hint}</p>
      </div>
      {canEdit && (
        <Button type="submit" className="w-fit" disabled={!dirty || pending}>
          {pending && <Loader2 className="animate-spin" />} Save
        </Button>
      )}
    </form>
  );
}

const catColor: Record<string, string> = {
  permissive: 'var(--chart-1)',
  unencumbered: 'var(--chart-1)',
  weak_copyleft: 'var(--chart-3)',
  strong_copyleft: 'var(--chart-4)',
  network_copyleft: 'var(--chart-4)',
  noncommercial: 'var(--chart-4)',
  unknown: 'var(--muted-foreground)',
  other: 'var(--chart-2)',
};
const distCfg = { count: { label: 'Packages', color: 'var(--chart-1)' } } satisfies ChartConfig;

export function LicenseDistribution({ data }: { data: LicenseReport['distribution'] }) {
  if (!data.length) return <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">No license data</div>;
  const rows = [...data].sort((a, b) => b.count - a.count).slice(0, 15);
  return (
    <ChartContainer config={distCfg} className="w-full" style={{ height: rows.length * 28 + 24 }} role="img" aria-label="License distribution">
      <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 16 }}>
        <CartesianGrid horizontal={false} strokeOpacity={0.5} />
        <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} fontSize={12} />
        <YAxis type="category" dataKey="license" width={130} tickLine={false} axisLine={false} fontSize={12} />
        <ChartTooltip cursor={{ fillOpacity: 0.3 }} content={<ChartTooltipContent hideIndicator />} />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={20}>
          {rows.map((r) => (
            <Cell key={r.license} fill={catColor[r.category] ?? 'var(--chart-1)'} />
          ))}
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}

type LFinding = LicenseReport['findings'][number];
const str = (v: unknown) => (v == null ? '' : String(v));

const cols: ColumnDef<LFinding, unknown>[] = [
  { header: 'Rule', cell: ({ row }) => <span className="font-medium">{row.original.rule}</span> },
  { header: 'Severity', cell: ({ row }) => <RiskBadge risk={row.original.severity} /> },
  {
    header: 'Package',
    cell: ({ row }) => (
      <span className="inline-flex items-center gap-2">
        <Ecosystem name={row.original.component.ecosystem} /> {row.original.component.name} <Chip>{row.original.component.version}</Chip>
      </span>
    ),
  },
  { header: 'License', cell: ({ row }) => <span className="font-mono text-xs">{str(row.original.details.license) || '—'}</span> },
  { header: 'Explanation', cell: ({ row }) => <span className="block max-w-xl text-sm whitespace-normal">{str(row.original.details.explanation) || row.original.summary}</span> },
];

export function LicenseFindingsTable({ data }: { data: LFinding[] }) {
  return <DataTable columns={cols} data={data} empty="No license issues for this version." />;
}
