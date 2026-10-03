'use client';

import { useEffect, useMemo, useState } from 'react';
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps, type ReactFlowInstance } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';
import { ChevronDown, ChevronRight, Info, Search, Siren } from 'lucide-react';
import { Chip, RiskBadge } from '@/components/badges';
import { Breadcrumbs, PathDetail } from '@/components/paths';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import type { GraphNode, PathGraph, PathItem } from '@/lib/types';

const NODE_W = 210;
const NODE_H = 50;
const APP = 'app';
const GRAPH_GROUPS = 8; // vulnerable packages drawn in the graph by default
const LIST_PAGE = 15;

type Level = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'app';
const levelCls: Record<Level, string> = {
  critical: 'border-red-600 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100',
  high: 'border-orange-500 bg-orange-50 text-orange-900 dark:bg-orange-950 dark:text-orange-100',
  medium: 'border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-100',
  low: 'border-sky-500 bg-sky-50 text-sky-900 dark:bg-sky-950 dark:text-sky-100',
  clean: 'border-border bg-background text-foreground',
  app: 'border-primary bg-primary text-primary-foreground',
};
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

function nodeLevel(n?: GraphNode): Level {
  if (!n) return 'clean';
  if (n.malware) return 'critical';
  if (n.max_risk) return (({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium' }) as Record<string, Level>)[n.max_risk] ?? 'low';
  return 'clean';
}

type DepData = { label: string; sub: string; level: Level; flags: string[]; selected: boolean; dim: boolean };

function DepNode({ data }: NodeProps<Node<DepData>>) {
  return (
    <div
      className={cn(
        'flex h-[50px] w-[210px] flex-col justify-center rounded-lg border-2 px-2.5 text-xs shadow-sm transition-opacity',
        levelCls[data.level],
        data.selected && 'ring-2 ring-primary ring-offset-2',
        data.dim && 'opacity-35',
      )}
    >
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <span className="truncate font-semibold">{data.label}</span>
      <span className="truncate opacity-80">{[data.sub, ...data.flags].filter(Boolean).join(' · ')}</span>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}
const nodeTypes = { dep: DepNode };

/** All paths that end in one vulnerable (or flagged) package. */
type Group = { key: string; target: PathItem['target']; paths: PathItem[]; best: PathItem; kev: boolean; minDepth: number };

const idOfChain = (c: PathItem['chain'][number]) => c.component_id ?? `${c.name}@${c.version}`;
const pathKey = (p: PathItem) => p.chain.map(idOfChain).join('>');

export function AttackPaths({ graph, appName }: { graph: PathGraph; appName: string }) {
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph.nodes]);
  const [sev, setSev] = useState<Set<string>>(new Set(SEVERITIES));
  const [withSuspicious, setWithSuspicious] = useState(false);
  const [q, setQ] = useState('');
  const [showAllInGraph, setShowAllInGraph] = useState(false);
  const [listLimit, setListLimit] = useState(LIST_PAGE);
  const [open, setOpen] = useState<string | null>(null);
  const [selKey, setSelKey] = useState<string | null>(null);

  // Group paths by target package, worst first.
  const allGroups = useMemo(() => {
    const m = new Map<string, Group>();
    for (const p of graph.paths) {
      const k = p.target.component_id ?? `${p.target.name}@${p.target.version}`;
      const g = m.get(k);
      const kev = p.advisories.some((a) => a.kev);
      if (!g) m.set(k, { key: k, target: p.target, paths: [p], best: p, kev, minDepth: p.depth || 99 });
      else {
        g.paths.push(p);
        g.kev ||= kev;
        if (p.score > g.best.score) g.best = p;
        if (p.depth && p.depth < g.minDepth) g.minDepth = p.depth;
      }
    }
    return [...m.values()].sort((a, b) => b.best.score - a.best.score);
  }, [graph.paths]);

  const isVuln = (g: Group) => g.best.advisories.length > 0;
  const groups = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return allGroups.filter(
      (g) =>
        (withSuspicious || isVuln(g)) &&
        (!isVuln(g) || sev.has(g.best.risk)) &&
        (!needle || g.paths.some((p) => p.chain.some((c) => c.name.toLowerCase().includes(needle)))),
    );
  }, [allGroups, sev, withSuspicious, q]);

  const selected = useMemo(() => {
    for (const g of groups) for (const p of g.paths) if (pathKey(p) === selKey) return p;
    return groups[0]?.best ?? null;
  }, [groups, selKey]);

  // Graph: only the chains of the groups in view (≤2 per package), so it stays readable.
  const shown = showAllInGraph ? groups : groups.slice(0, GRAPH_GROUPS);
  const { nodes, edges } = useMemo(() => {
    const ids = new Set<string>();
    const edgeSet = new Map<string, { from: string; to: string }>();
    for (const g of shown) {
      for (const p of g.paths.slice(0, 2)) {
        let from = APP;
        for (const c of p.chain) {
          const id = idOfChain(c);
          ids.add(id);
          edgeSet.set(`${from}->${id}`, { from, to: id });
          from = id;
        }
      }
    }
    const onSel = new Set<string>();
    if (selected) {
      let from = APP;
      for (const c of selected.chain) {
        const id = idOfChain(c);
        onSel.add(`${from}->${id}`);
        onSel.add(id);
        from = id;
      }
    }
    const dg = new dagre.graphlib.Graph();
    dg.setGraph({ rankdir: 'LR', nodesep: 16, ranksep: 64, marginx: 10, marginy: 10 });
    dg.setDefaultEdgeLabel(() => ({}));
    dg.setNode(APP, { width: NODE_W, height: NODE_H });
    for (const id of ids) dg.setNode(id, { width: NODE_W, height: NODE_H });
    for (const e of edgeSet.values()) dg.setEdge(e.from, e.to);
    dagre.layout(dg);
    const pos = (id: string) => {
      const p = dg.node(id);
      return { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 };
    };
    const hasSel = onSel.size > 0;
    const ns: Node<DepData>[] = [
      { id: APP, type: 'dep', position: pos(APP), data: { label: 'Your app', sub: appName, level: 'app', flags: [], selected: false, dim: false } },
      ...[...ids].map((id) => {
        const n = nodeById.get(id);
        const [name, version] = n ? [n.name, n.version] : [id, ''];
        return {
          id,
          type: 'dep',
          position: pos(id),
          data: {
            label: version ? `${name}@${version}` : name,
            sub: n?.direct ? 'direct' : n?.depth ? `depth ${n.depth}` : '',
            level: nodeLevel(n),
            flags: n ? ([n.malware && 'malware', n.vulns > 0 && `${n.vulns} vuln${n.vulns > 1 ? 's' : ''}`].filter(Boolean) as string[]) : [],
            selected: !!selected && idOfChain(selected.chain[selected.chain.length - 1]) === id,
            dim: hasSel && !onSel.has(id),
          },
        };
      }),
    ];
    const es: Edge[] = [...edgeSet.values()].map((e) => {
      const on = onSel.has(`${e.from}->${e.to}`);
      return {
        id: `${e.from}->${e.to}`,
        source: e.from,
        target: e.to,
        animated: on,
        zIndex: on ? 1 : 0,
        style: on ? { stroke: 'var(--primary)', strokeWidth: 2.5 } : { stroke: 'var(--border)', strokeWidth: 1.25, opacity: hasSel ? 0.5 : 1 },
      };
    });
    return { nodes: ns, edges: es };
  }, [shown, selected, nodeById, appName]);

  // Zoom to the selected chain.
  const [rf, setRf] = useState<ReactFlowInstance<Node<DepData>, Edge> | null>(null);
  useEffect(() => {
    if (!rf || !selected) return;
    const ids = [APP, ...selected.chain.map(idOfChain)];
    const t = setTimeout(() => rf.fitView({ nodes: ids.map((id) => ({ id })), padding: 0.3, maxZoom: 1.1, duration: 350 }), 50);
    return () => clearTimeout(t);
  }, [rf, selected, nodes]);

  // Summary numbers.
  const vulnGroups = allGroups.filter(isVuln);
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, vulnGroups.filter((g) => g.best.risk === s).length]));
  const direct = vulnGroups.filter((g) => g.minDepth === 1).length;
  const deepest = Math.max(0, ...graph.paths.map((p) => p.depth));
  const kevCount = vulnGroups.filter((g) => g.kev).length;
  const suspiciousOnly = allGroups.length - vulnGroups.length;

  const toggleSev = (s: string) => {
    const next = new Set(sev);
    if (next.has(s)) next.delete(s);
    else next.add(s);
    setSev(next.size ? next : new Set(SEVERITIES));
  };

  return (
    <div className="grid gap-4 p-4">
      {/* summary */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Vulnerable packages reachable" value={vulnGroups.length} sub={`${graph.paths.length}${graph.truncated ? '+' : ''} paths`} />
        <Stat label="Critical / High" value={`${bySev.CRITICAL} / ${bySev.HIGH}`} sub={`${bySev.MEDIUM} medium · ${bySev.LOW} low`} tone={bySev.CRITICAL ? 'text-red-600' : bySev.HIGH ? 'text-orange-600' : undefined} />
        <Stat label="Direct vs transitive" value={`${direct} / ${vulnGroups.length - direct}`} sub="fix direct ones in package.json" />
        <Stat label="Deepest path" value={deepest || '—'} sub="levels below your app" />
        <Stat label="Actively exploited" value={kevCount} sub="in CISA KEV" tone={kevCount ? 'text-red-600' : undefined} />
      </div>

      {graph.source !== 'lockfile' && (
        <p role="note" className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100">
          <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          {graph.source === 'depsdev'
            ? 'This lockfile does not record which package depends on which, so chains come from deps.dev and may differ slightly from what is installed. Rescan after updating to get exact paths.'
            : 'No dependency graph is available for this version; packages are shown on their own.'}
        </p>
      )}

      {/* filters */}
      <div className="flex flex-wrap items-center gap-2">
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => toggleSev(s)}
            aria-pressed={sev.has(s)}
            className={cn('rounded-full border px-3 py-1 text-xs font-medium transition-colors', sev.has(s) ? 'border-transparent bg-foreground text-background' : 'text-muted-foreground hover:bg-muted')}
          >
            {s[0] + s.slice(1).toLowerCase()} <span className="tabular-nums opacity-70">{bySev[s]}</span>
          </button>
        ))}
        {suspiciousOnly > 0 && (
          <label className="ml-1 inline-flex items-center gap-1.5 text-xs text-muted-foreground">
            <input type="checkbox" checked={withSuspicious} onChange={(e) => setWithSuspicious(e.target.checked)} className="accent-primary" />
            Include suspicious-only packages ({suspiciousOnly})
          </label>
        )}
        <div className="relative ml-auto w-full sm:w-64">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find a package on a path…" aria-label="Find a package" className="h-8 pl-8 text-sm" />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_24rem]">
        {/* graph */}
        <Card className="gap-2 py-3">
          <CardHeader className="px-4">
            <CardTitle className="flex flex-wrap items-center gap-2 text-base">
              How vulnerable packages reach your app
              <span className="text-xs font-normal text-muted-foreground">
                {shown.length < groups.length ? `top ${shown.length} of ${groups.length}` : `${groups.length} packages`} · click a node or a row
              </span>
              {groups.length > GRAPH_GROUPS && (
                <Button variant="ghost" size="sm" className="ml-auto h-7" onClick={() => setShowAllInGraph(!showAllInGraph)}>
                  {showAllInGraph ? 'Show top only' : `Show all ${groups.length}`}
                </Button>
              )}
            </CardTitle>
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              {(['critical', 'high', 'medium', 'low', 'clean'] as Level[]).map((l) => (
                <span key={l} className="inline-flex items-center gap-1 capitalize">
                  <span className={cn('size-3 rounded-sm border-2', levelCls[l])} aria-hidden /> {l === 'clean' ? 'on the way (no issue)' : l}
                </span>
              ))}
            </div>
          </CardHeader>
          <CardContent className="px-3">
            <div className="h-[560px] rounded-lg border bg-muted/20" role="figure" aria-label="Dependency attack path graph">
              {groups.length ? (
                <ReactFlow
                  key={`${shown.length}-${[...sev].join()}-${withSuspicious}-${q}`}
                  nodes={nodes}
                  edges={edges}
                  nodeTypes={nodeTypes}
                  fitView
                  fitViewOptions={{ padding: 0.12, minZoom: 0.6, maxZoom: 1.1 }}
                  minZoom={0.1}
                  nodesDraggable={false}
                  nodesConnectable={false}
                  proOptions={{ hideAttribution: true }}
                  onInit={setRf}
                  onNodeClick={(_, n) => {
                    if (n.id === APP) return setSelKey(null);
                    const g = groups.find((x) => x.key === n.id) ?? groups.find((x) => x.paths.some((p) => p.chain.some((c) => idOfChain(c) === n.id)));
                    if (g) {
                      setSelKey(pathKey(g.best));
                      setOpen(g.key);
                    }
                  }}
                >
                  <Background gap={20} />
                  <Controls showInteractive={false} />
                </ReactFlow>
              ) : (
                <div className="flex h-full items-center justify-center text-sm text-muted-foreground">No paths match these filters.</div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* selected */}
        <Card className="gap-3 self-start lg:sticky lg:top-16" aria-label="Selected path">
          <CardHeader>
            <CardTitle className="text-base">Selected path</CardTitle>
            <CardDescription>The chain from your app to the vulnerable package, its advisories and the fix.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-sm">{selected ? <PathDetail p={selected} /> : <p className="text-muted-foreground">Select a path.</p>}</CardContent>
        </Card>
      </div>

      {/* grouped list */}
      <Card className="gap-0 py-0">
        <CardHeader className="border-b py-4">
          <CardTitle className="text-base">Vulnerable packages and their paths ({groups.length})</CardTitle>
          <CardDescription>Ranked by risk score (severity, exploit likelihood, depth and whether your code imports the entry dependency).</CardDescription>
        </CardHeader>
        <ol className="divide-y" aria-label="Ranked attack paths">
          {groups.slice(0, listLimit).map((g) => {
            const expanded = open === g.key;
            const b = g.best;
            return (
              <li key={g.key}>
                <button
                  type="button"
                  onClick={() => {
                    setOpen(expanded ? null : g.key);
                    setSelKey(pathKey(b));
                  }}
                  aria-expanded={expanded}
                  className={cn('flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left text-sm hover:bg-muted/50', selected && g.paths.includes(selected) && 'bg-accent/50')}
                >
                  {expanded ? <ChevronDown className="size-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="size-4 shrink-0 text-muted-foreground" />}
                  <ScorePill score={b.score} />
                  <RiskBadge risk={b.risk} />
                  <span className="font-semibold">
                    {g.target.name}
                    <span className="font-normal text-muted-foreground">@{g.target.version}</span>
                  </span>
                  <Chip>{g.minDepth === 1 ? 'direct' : g.minDepth === 99 ? 'depth unknown' : `depth ${g.minDepth}`}</Chip>
                  {g.kev && (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-red-600">
                      <Siren className="size-3.5" aria-hidden /> exploited
                    </span>
                  )}
                  {b.advisories.length > 0 && <span className="text-xs text-muted-foreground">{b.advisories.length} advisor{b.advisories.length === 1 ? 'y' : 'ies'}</span>}
                  <span className="text-xs text-muted-foreground">
                    {g.paths.length} path{g.paths.length === 1 ? '' : 's'}
                  </span>
                  <span className="ml-auto max-w-md truncate text-xs text-muted-foreground" title={b.fix}>
                    {b.fix}
                  </span>
                </button>
                {expanded && (
                  <ul className="space-y-1 bg-muted/30 px-4 py-2 pl-12">
                    {g.paths.map((p) => (
                      <li key={pathKey(p)}>
                        <button type="button" onClick={() => setSelKey(pathKey(p))} className={cn('flex w-full flex-wrap items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-background', selected === p && 'bg-background ring-1 ring-primary/40')}>
                          <ScorePill score={p.score} small />
                          <Breadcrumbs p={p} />
                          {p.imported === false && <Chip>not imported</Chip>}
                          {p.dev && <Chip>dev only</Chip>}
                          {p.approximate && <Chip className="bg-amber-100 text-amber-800">approximate</Chip>}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ol>
        {groups.length > listLimit && (
          <div className="border-t p-3 text-center">
            <Button variant="ghost" size="sm" onClick={() => setListLimit(listLimit + LIST_PAGE * 2)}>
              Show more ({groups.length - listLimit} remaining)
            </Button>
          </div>
        )}
      </Card>
    </div>
  );
}

function Stat({ label, value, sub, tone }: { label: string; value: React.ReactNode; sub: string; tone?: string }) {
  return (
    <div className="rounded-xl border bg-card p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={cn('mt-1 text-2xl font-semibold tabular-nums', tone)}>{value}</div>
      <div className="text-xs text-muted-foreground">{sub}</div>
    </div>
  );
}

function ScorePill({ score, small }: { score: number; small?: boolean }) {
  const tone = score >= 30 ? 'bg-red-600' : score >= 15 ? 'bg-orange-500' : 'bg-sky-600';
  return (
    <span className={cn('inline-flex shrink-0 items-center justify-center rounded-md font-semibold text-white tabular-nums', tone, small ? 'h-5 w-8 text-[11px]' : 'h-6 w-10 text-xs')} title="Risk score (0–100)">
      {score}
    </span>
  );
}
