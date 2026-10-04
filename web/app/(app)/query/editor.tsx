'use client';

import { downloadCsv } from '@/lib/csv';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { ChevronRight, Download, Loader2, Play, Save, Table2, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useAction } from '@/components/client';
import { deleteQuery, runQuery, saveQuery } from '@/lib/actions';
import type { QueryResult, QuerySchema, SavedQuery } from '@/lib/types';

const Monaco = dynamic(() => import('@monaco-editor/react'), {
  ssr: false,
  loading: () => <div className="flex h-full items-center justify-center text-sm text-muted-foreground">Loading editor…</div>,
});

const DEFAULT_SQL = `-- Read-only SQL over your tenant's q_* views. Queries need a time bound; 10s timeout, 1,000 rows max.
SELECT name, ecosystem, version, updated_at
FROM q_components
WHERE updated_at > now() - interval '30 days'
ORDER BY updated_at DESC
LIMIT 100`;

export function QueryEditor({ schema, saved }: { schema: QuerySchema; saved: SavedQuery[] }) {
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const { pending, run } = useAction();
  const [running, setRunning] = useState(false);

  async function execute() {
    setRunning(true);
    setError(null);
    const r = await runQuery(sql);
    setRunning(false);
    if (r.ok) setResult(r.data);
    else {
      setResult(null);
      setError(r.error);
    }
  }

  function exportCsv() {
    if (result) downloadCsv('depguard-query', result.columns, result.rows);
  }

  return (
    <div className="grid min-h-0 flex-1 lg:grid-cols-[260px_1fr]">
      <aside className="space-y-6 border-b p-4 lg:border-r lg:border-b-0" aria-label="Schema and saved queries">
        <section>
          <h2 className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">Tables</h2>
          <ul className="space-y-1 text-sm">
            {schema.tables.map((t) => (
              <li key={t.name}>
                <details>
                  <summary className="flex cursor-pointer items-center gap-1.5 rounded px-1 py-1 hover:bg-muted [&::-webkit-details-marker]:hidden">
                    <ChevronRight className="size-3.5 transition-transform [details[open]_&]:rotate-90" aria-hidden />
                    <Table2 className="size-3.5 text-primary" aria-hidden />
                    <span className="font-mono">{t.name}</span>
                  </summary>
                  <ul className="ml-7 space-y-0.5 py-1">
                    {t.columns.map((c) => (
                      <li key={c.name} className="flex justify-between gap-2 font-mono text-xs">
                        <span>{c.name}</span>
                        <span className="text-muted-foreground">{c.type}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              </li>
            ))}
          </ul>
        </section>
        <section>
          <h2 className="mb-2 text-xs font-semibold tracking-wide text-muted-foreground uppercase">Saved queries</h2>
          {saved.length ? (
            <ul className="space-y-1 text-sm">
              {saved.map((q) => (
                <li key={q.id} className="group flex items-center gap-1">
                  <button type="button" className="min-w-0 flex-1 truncate rounded px-1 py-1 text-left hover:bg-muted" onClick={() => setSql(q.sql)} title="Load into editor">
                    {q.name}
                  </button>
                  <Button variant="ghost" size="icon" className="size-7" aria-label={`Delete saved query ${q.name}`} disabled={pending} onClick={() => run(() => deleteQuery(q.id), 'Query deleted')}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">Nothing saved yet.</p>
          )}
        </section>
      </aside>

      <section className="flex min-w-0 flex-col">
        <div className="h-64 border-b" aria-label="SQL editor">
          <Monaco
            language="sql"
            value={sql}
            onChange={(v) => setSql(v ?? '')}
            options={{ minimap: { enabled: false }, fontSize: 13, scrollBeyondLastLine: false, wordWrap: 'on', automaticLayout: true }}
            onMount={(editor, monaco) => editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => document.getElementById('run-query')?.click())}
          />
        </div>
        <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2">
          <Button id="run-query" size="sm" onClick={execute} disabled={running || !sql.trim()}>
            {running ? <Loader2 className="animate-spin" /> : <Play />} Run
          </Button>
          <span className="hidden text-xs text-muted-foreground sm:inline">Ctrl/⌘ + Enter</span>
          <form
            className="ml-auto flex items-center gap-2"
            onSubmit={async (e) => {
              e.preventDefault();
              if (await run(() => saveQuery(name, sql), 'Query saved')) setName('');
            }}
          >
            <Label htmlFor="query-name" className="sr-only">
              Query name
            </Label>
            <Input id="query-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Name this query" className="h-8 w-48" />
            <Button type="submit" size="sm" variant="outline" disabled={pending || !name.trim()}>
              <Save /> Save
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={exportCsv} disabled={!result?.rows.length}>
              <Download /> CSV
            </Button>
          </form>
        </div>
        <div className="min-h-48 flex-1 overflow-auto" aria-live="polite">
          {error && (
            <p role="alert" className="m-4 rounded-md border border-red-200 bg-red-50 p-3 font-mono text-sm text-red-800">
              {error}
            </p>
          )}
          {!result && !error && <p className="p-4 text-sm text-muted-foreground">Run a query to see results here.</p>}
          {result && (
            <>
              <p className="px-4 py-2 text-xs text-muted-foreground">
                {result.rows.length} row{result.rows.length === 1 ? '' : 's'} in {result.elapsed_ms} ms
                {result.truncated && <span className="ml-2 font-medium text-amber-700">· Truncated to the first {result.rows.length} rows — add a LIMIT or narrow the time range.</span>}
              </p>
              <Table>
                <TableHeader>
                  <TableRow>
                    {result.columns.map((c) => (
                      <TableHead key={c} className="font-mono text-xs">
                        {c}
                      </TableHead>
                    ))}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.rows.map((r, i) => (
                    <TableRow key={i}>
                      {r.map((v, j) => (
                        <TableCell key={j} className="font-mono text-xs">
                          {v == null ? <span className="text-muted-foreground">NULL</span> : typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          )}
        </div>
      </section>
    </div>
  );
}
