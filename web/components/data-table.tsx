'use client';

import { useState } from 'react';
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef } from '@tanstack/react-table';
import { parseAsInteger, parseAsString, useQueryState, useQueryStates } from 'nuqs';
import { ArrowLeft, ArrowRight, Filter, X } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';

export type { ColumnDef };

export function DataTable<T>({
  columns,
  data,
  total,
  empty = 'No results.',
  defaultPageSize = 20,
}: {
  columns: ColumnDef<T, unknown>[];
  data: T[];
  /** When set, renders server pagination (page / page_size in the URL). */
  total?: number;
  empty?: React.ReactNode;
  defaultPageSize?: number;
}) {
  // eslint-disable-next-line react-hooks/incompatible-library -- TanStack Table is not compiler-aware; fine without the compiler.
  const table = useReactTable({ data, columns, getCoreRowModel: getCoreRowModel() });
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex-1 overflow-x-auto">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((hg) => (
              <TableRow key={hg.id} className="hover:bg-transparent">
                {hg.headers.map((h) => (
                  <TableHead key={h.id} className="h-11 px-3 font-normal text-muted-foreground">
                    {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((r) => (
                <TableRow key={r.id}>
                  {r.getVisibleCells().map((c) => (
                    <TableCell key={c.id} className="px-3 py-3">
                      {flexRender(c.column.columnDef.cell, c.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={columns.length} className="h-32 text-center">
                  {empty}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      {total !== undefined && <Pagination total={total} defaultPageSize={defaultPageSize} />}
    </div>
  );
}

export function Pagination({ total, defaultPageSize = 20 }: { total: number; defaultPageSize?: number }) {
  const [{ page, page_size }, set] = useQueryStates(
    { page: parseAsInteger.withDefault(1), page_size: parseAsInteger.withDefault(defaultPageSize) },
    { shallow: false },
  );
  const last = Math.max(1, Math.ceil(total / page_size));
  return (
    <div className="flex flex-wrap items-center justify-end gap-2 border-t bg-muted/30 px-3 py-2 text-sm">
      <span className="mr-auto text-muted-foreground">
        {total === 0 ? '0 results' : `${(page - 1) * page_size + 1}–${Math.min(page * page_size, total)} of ${total}`}
      </span>
      <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => set({ page: page - 1 })}>
        <ArrowLeft /> Previous
      </Button>
      <Button variant="ghost" size="sm" disabled={page >= last} onClick={() => set({ page: page + 1 })}>
        Next <ArrowRight />
      </Button>
      <Select value={String(page_size)} onValueChange={(v) => set({ page_size: Number(v), page: 1 })}>
        <SelectTrigger size="sm" className="w-20" aria-label="Rows per page">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {[10, 20, 50].map((n) => (
            <SelectItem key={n} value={String(n)}>
              {n}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

export type FilterDef =
  | { type: 'text'; key: string; label: string; placeholder?: string }
  | { type: 'select'; key: string; label: string; options: { value: string; label: string }[] }
  | { type: 'daterange'; label?: string; fromKey?: string; toKey?: string }
  | { type: 'date'; key: string; label: string }
  | { type: 'toggle'; key: string; label: string };

/** Filter bar whose state lives in the URL; changing a filter resets to page 1 and re-renders on the server. */
export function FilterBar({ filters, children }: { filters: FilterDef[]; children?: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-1 border-b px-3 py-2">
      <Filter className="mr-1 size-4 text-muted-foreground" aria-hidden />
      {filters.map((f, i) => (
        <FilterControl key={i} f={f} />
      ))}
      {children && <div className="ml-auto flex items-center gap-2">{children}</div>}
    </div>
  );
}

function useParam(key: string) {
  const [, setPage] = useQueryState('page', parseAsInteger.withOptions({ shallow: false }));
  const [v, setV] = useQueryState(key, parseAsString.withOptions({ shallow: false }));
  return [v, (nv: string | null) => Promise.all([setV(nv || null), setPage(null)])] as const;
}

function FilterControl({ f }: { f: FilterDef }) {
  if (f.type === 'toggle') return <ToggleFilter k={f.key} label={f.label} />;
  if (f.type === 'daterange') return <DateRangeFilter f={f} />;
  return <PopoverFilter f={f} />;
}

export function ToggleFilter({ k, label }: { k: string; label: string }) {
  const [v, set] = useParam(k);
  const id = `f-${k}`;
  return (
    <div className="flex items-center gap-2 border-l px-3">
      <Switch id={id} checked={v === 'true'} onCheckedChange={(c) => set(c ? 'true' : null)} />
      <Label htmlFor={id} className="font-normal">
        {label}
      </Label>
    </div>
  );
}

function TriggerButton({ label, display: value, onClear, ...props }: { label: string; display?: string | null; onClear: () => void } & React.ComponentProps<'button'>) {
  return (
    <span className="inline-flex items-center">
      <Button variant="ghost" size="sm" className={cn('font-normal', value && 'text-primary')} {...props}>
        {label}
        {value && <span className="max-w-32 truncate font-medium">: {value}</span>}
      </Button>
      {value && (
        <button type="button" onClick={onClear} aria-label={`Clear ${label} filter`} className="-ml-1 rounded p-0.5 text-muted-foreground hover:text-foreground">
          <X className="size-3.5" />
        </button>
      )}
    </span>
  );
}

function PopoverFilter({ f }: { f: Extract<FilterDef, { type: 'text' | 'select' | 'date' }> }) {
  const [v, set] = useParam(f.key);
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(v ?? '');
  const display = f.type === 'select' ? f.options.find((o) => o.value === v)?.label ?? v : v;
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setDraft(v ?? '');
      }}
    >
      <PopoverTrigger asChild>
        <TriggerButton label={f.label} display={display} onClear={() => set(null)} />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64">
        {f.type === 'select' ? (
          <div className="flex flex-col gap-0.5" role="listbox" aria-label={f.label}>
            {f.options.map((o) => (
              <button
                key={o.value}
                type="button"
                role="option"
                aria-selected={v === o.value}
                className={cn('rounded px-2 py-1.5 text-left text-sm hover:bg-muted', v === o.value && 'bg-accent text-accent-foreground')}
                onClick={() => {
                  set(v === o.value ? null : o.value);
                  setOpen(false);
                }}
              >
                {o.label}
              </button>
            ))}
          </div>
        ) : (
          <form
            className="flex flex-col gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              set(draft.trim() || null);
              setOpen(false);
            }}
          >
            <Label htmlFor={`f-${f.key}`}>{f.label}</Label>
            <Input
              id={`f-${f.key}`}
              type={f.type === 'date' ? 'date' : 'text'}
              autoFocus
              value={draft}
              placeholder={f.type === 'text' ? f.placeholder ?? `Filter by ${f.label.toLowerCase()}` : undefined}
              onChange={(e) => setDraft(e.target.value)}
            />
            <Button type="submit" size="sm">
              Apply
            </Button>
          </form>
        )}
      </PopoverContent>
    </Popover>
  );
}

function DateRangeFilter({ f }: { f: Extract<FilterDef, { type: 'daterange' }> }) {
  const fromKey = f.fromKey ?? 'from';
  const toKey = f.toKey ?? 'to';
  const [{ from, to }, set] = useQueryStates(
    { from: parseAsString, to: parseAsString, page: parseAsInteger },
    { shallow: false, urlKeys: { from: fromKey, to: toKey } },
  );
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState({ from: from ?? '', to: to ?? '' });
  const value = from || to ? `${from ?? '…'} → ${to ?? '…'}` : null;
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setDraft({ from: from ?? '', to: to ?? '' });
      }}
    >
      <PopoverTrigger asChild>
        <TriggerButton label={f.label ?? 'Date range'} display={value} onClear={() => set({ from: null, to: null, page: null })} />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64">
        <form
          className="flex flex-col gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            set({ from: draft.from || null, to: draft.to || null, page: null });
            setOpen(false);
          }}
        >
          <Label htmlFor="f-from">From</Label>
          <Input id="f-from" type="date" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
          <Label htmlFor="f-to">To</Label>
          <Input id="f-to" type="date" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
          <Button type="submit" size="sm">
            Apply
          </Button>
        </form>
      </PopoverContent>
    </Popover>
  );
}
