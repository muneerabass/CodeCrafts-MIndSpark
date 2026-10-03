'use client';

import { useMemo, useState } from 'react';
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import dagre from '@dagrejs/dagre';
import { RiskBadge } from '@/components/badges';
import { Breadcrumbs, PathDetail } from '@/components/paths';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { GraphNode, PathGraph, PathItem } from '@/lib/types';

const NODE_W = 200;
const NODE_H = 48;
const MAX_NODES = 300;
const APP = 'app';

type Level = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'app';
const levelCls: Record<Level, string> = {
  critical: 'border-red-500 bg-red-50 text-red-900 dark:bg-red-950 dark:text-red-100',
  high: 'border-orange-500 bg-orange-50 text-orange-900 dark:bg-orange-950 dark:text-orange-100',
  medium: 'border-amber-400 bg-amber-50 text-amber-900 dark:bg-amber-950 dark:text-amber-100',
  low: 'border-sky-400 bg-sky-50 text-sky-900 dark:bg-sky-950 dark:text-sky-100',
  clean: 'border-border bg-background text-foreground',
  app: 'border-primary bg-primary text-primary-foreground',
};
const LEGEND: Level[] = ['critical', 'high', 'medium', 'low', 'clean'];

function level(n: GraphNode): Level {
  if (n.malware) return 'critical';
  if (n.max_risk) return (({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium' }) as Record<string, Level>)[n.max_risk] ?? 'low';
  return n.suspicious || n.license_issue ? 'medium' : 'clean';
}

type DepData = { label: string; sub: string; level: Level; flags: string[]; selected: boolean };

function DepNode({ data }: NodeProps<Node<DepData>>) {
  return (
    <div className={cn('flex h-12 w-[200px] flex-col justify-center rounded-md border-2 px-2 text-xs shadow-xs', levelCls[data.level], data.selected && 'ring-2 ring-primary ring-offset-2')}>
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <span className="truncate font-medium">{data.label}</span>
      <span className="truncate opacity-75">{[data.sub, ...data.flags].filter(Boolean).join(' · ')}</span>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </div>
  );
}
const nodeTypes = { dep: DepNode };

/** Keeps only nodes on a path from the app to a flagged node (vulnerable, malicious, suspicious, license), capped. */
function subgraph(g: PathGraph) {
  const parents = new Map<string, string[]>();
  for (const e of g.edges) parents.set(e.to, [...(parents.get(e.to) ?? []), e.from]);
  const flagged = g.nodes.filter((n) => n.vulns > 0 || n.malware || n.suspicious || n.license_issue).map((n) => n.id);
  const keep = new Set<string>();
  const queue = [...flagged];
  let capped = false;
  while (queue.length) {
    const id = queue.shift()!;
    if (keep.has(id) || id === APP) continue;
    if (keep.size >= MAX_NODES) {
      capped = true;
      break;
    }
    keep.add(id);
    queue.push(...(parents.get(id) ?? []));
  }
  return {
    nodes: g.nodes.filter((n) => keep.has(n.id)),
    edges: g.edges.filter((e) => keep.has(e.to) && (e.from === APP || keep.has(e.from))),
    capped: capped || !!g.truncated,
  };
}

const chainIds = (p: PathItem, idOf: (name: string, version: string) => string | undefined) =>
  [APP, ...p.chain.map((c) => c.component_id ?? idOf(c.name, c.version) ?? `${c.name}@${c.version}`)];

export function AttackPaths({ graph, appName }: { graph: PathGraph; appName: string }) {
  const ranked = useMemo(() => [...graph.paths].sort((a, b) => b.score - a.score), [graph.paths]);
  const sub = useMemo(() => subgraph(graph), [graph]);
  const idOf = useMemo(() => {
    const m = new Map(graph.nodes.map((n) => [`${n.name}@${n.version}`, n.id]));
    return (name: string, version: string) => m.get(`${name}@${version}`);
  }, [graph.nodes]);
  const [sel, setSel] = useState(0);
  const [selNode, setSelNode] = useState<string | null>(null);
  const path = ranked[sel];
  const onPath = useMemo(() => (path ? chainIds(path, idOf) : []), [path, idOf]);

  const positions = useMemo(() => {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: 'LR', nodesep: 20, ranksep: 70 });
    g.setDefaultEdgeLabel(() => ({}));
    g.setNode(APP, { width: NODE_W, height: NODE_H });
    for (const n of sub.nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
    for (const e of sub.edges) g.setEdge(e.from, e.to);
    dagre.layout(g);
    return new Map(g.nodes().map((id) => [id, g.node(id)]));
  }, [sub]);

  const nodes: Node<DepData>[] = useMemo(() => {
    const pos = (id: string) => {
      const p = positions.get(id)!;
      return { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 };
    };
    return [
      { id: APP, type: 'dep', position: pos(APP), data: { label: 'Your app', sub: appName, level: 'app', flags: [], selected: false } },
      ...sub.nodes.map((n) => ({
        id: n.id,
        type: 'dep',
        position: pos(n.id),
        data: {
          label: `${n.name}@${n.version}`,
          sub: n.direct ? 'direct' : n.depth ? `depth ${n.depth}` : '',
          level: level(n),
          flags: [n.malware && 'malware', n.vulns > 0 && `${n.vulns} vuln${n.vulns > 1 ? 's' : ''}`, n.suspicious && 'suspicious', n.license_issue && 'license'].filter(Boolean) as string[],
          selected: n.id === selNode,
        },
      })),
    ];
  }, [sub, positions, appName, selNode]);

  const edges: Edge[] = useMemo(() => {
    const hot = new Set(onPath.slice(1).map((to, i) => `${onPath[i]}->${to}`));
    return sub.edges.map((e) => {
      const on = hot.has(`${e.from}->${e.to}`);
      return { id: `${e.from}->${e.to}`, source: e.from, target: e.to, animated: on, zIndex: on ? 1 : 0, style: on ? { stroke: 'var(--primary)', strokeWidth: 2.5 } : { stroke: 'var(--border)', strokeWidth: 1.5 } };
    });
  }, [sub.edges, onPath]);

  const clicked = graph.nodes.find((n) => n.id === selNode);

  return (
    <div className="grid gap-4 p-4 lg:grid-cols-[1fr_22rem]">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          {LEGEND.map((l) => (
            <span key={l} className="inline-flex items-center gap-1 capitalize">
              <span className={cn('size-3 rounded-sm border-2', levelCls[l])} aria-hidden /> {l}
            </span>
          ))}
          <span className="ml-auto">Source: {graph.source}</span>
        </div>
        {sub.capped && (
          <p role="note" className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
            Large graph: showing only dependencies on paths to flagged packages (at most {MAX_NODES} nodes).
          </p>
        )}
        <div className="h-[520px] rounded-lg border bg-muted/20" role="figure" aria-label="Dependency attack path graph">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.1}
            nodesDraggable={false}
            nodesConnectable={false}
            onNodeClick={(_, n) => {
              setSelNode(n.id === APP ? null : n.id);
              const i = ranked.findIndex((p) => chainIds(p, idOf).includes(n.id));
              if (i >= 0) setSel(i);
            }}
          >
            <Background />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      </div>

      <Card className="gap-3 self-start" aria-label="Selected path">
        <CardHeader>
          <CardTitle className="text-base">Selected path</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {clicked && !ranked.some((p) => chainIds(p, idOf).includes(clicked.id)) && (
            <p className="rounded-md bg-muted p-2 text-xs">
              <span className="font-medium">
                {clicked.name}@{clicked.version}
              </span>{' '}
              is {[clicked.suspicious && 'flagged as suspicious', clicked.license_issue && 'a license issue'].filter(Boolean).join(' and ') || 'not on a vulnerable path'}. See the Licenses tab or Package Analysis for details.
            </p>
          )}
          {path ? <PathDetail p={path} /> : <p className="text-muted-foreground">No vulnerable paths in this version.</p>}
        </CardContent>
      </Card>

      <Card className="gap-0 py-0 lg:col-span-2">
        <CardHeader className="border-b py-4">
          <CardTitle>Ranked attack paths ({ranked.length})</CardTitle>
        </CardHeader>
        <ol className="divide-y" aria-label="Ranked attack paths">
          {ranked.map((p, i) => (
            <li key={i}>
              <button type="button" onClick={() => setSel(i)} aria-current={i === sel} className={cn('flex w-full flex-wrap items-center gap-3 px-4 py-3 text-left text-sm hover:bg-muted/50', i === sel && 'bg-accent/60')}>
                <span className="w-10 shrink-0 rounded-md bg-primary/10 py-0.5 text-center font-semibold tabular-nums text-primary" title="Path score (0–100)">
                  {p.score}
                </span>
                <RiskBadge risk={p.risk} />
                <Breadcrumbs p={p} />
                <span className="ml-auto text-xs text-muted-foreground">{p.fix}</span>
              </button>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}
