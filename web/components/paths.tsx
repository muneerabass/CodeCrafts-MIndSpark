import Link from "next/link";
import { ChevronRight, Siren } from "lucide-react";
import { Chip, RiskBadge } from "@/components/badges";
import { cn } from "@/lib/utils";
import type { PathItem } from "@/lib/types";

/** app › direct › … › target, target in bold. */
export function Breadcrumbs({ p }: { p: PathItem }) {
  return (
    <span className="inline-flex flex-wrap items-center gap-1 font-mono text-xs">
      <span className="text-muted-foreground">app</span>
      {p.chain.map((c, i) => (
        <span key={i} className="inline-flex items-center gap-1">
          <ChevronRight className="size-3 text-muted-foreground" aria-hidden />
          <span
            className={cn(
              i === p.chain.length - 1 && "font-semibold text-foreground",
            )}
          >
            {c.name}@{c.version}
          </span>
        </span>
      ))}
    </span>
  );
}

export function PathDetail({ p }: { p: PathItem }) {
  return (
    <div className="space-y-3">
      <Breadcrumbs p={p} />
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
        <dt className="text-muted-foreground">Target</dt>
        <dd className="font-medium">
          {p.target.name}@{p.target.version}
        </dd>
        <dt className="text-muted-foreground">Risk</dt>
        <dd className="flex items-center gap-2">
          <RiskBadge risk={p.risk} />{" "}
          <span className="tabular-nums">score {p.score}</span>
        </dd>
        <dt className="text-muted-foreground">Depth</dt>
        <dd>
          {p.depth === 1 ? "Direct dependency" : `${p.depth} levels deep`}
        </dd>
        <dt className="text-muted-foreground">Imported</dt>
        <dd>
          {p.imported === null
            ? "Unknown"
            : p.imported
              ? `Yes (${p.direct_head})`
              : `No (${p.direct_head})`}
        </dd>
        {(p.dev || p.approximate) && (
          <>
            <dt className="text-muted-foreground">Notes</dt>
            <dd className="flex flex-wrap gap-1">
              {p.dev && <Chip>dev only</Chip>}
              {p.approximate && (
                <Chip className="bg-amber-100 text-amber-800">
                  approximate (deps.dev)
                </Chip>
              )}
            </dd>
          </>
        )}
      </dl>
      <div className="overflow-x-auto">
        <table className="w-full text-xs [&_td]:px-1.5 [&_th]:px-1.5 [&_th]:whitespace-nowrap [&_td]:whitespace-nowrap">
          <thead className="text-muted-foreground">
            <tr>
              <th className="py-1 text-left font-normal">Advisory</th>
              <th className="text-left font-normal">Risk</th>
              <th className="text-right font-normal">EPSS</th>
              <th className="text-center font-normal">KEV</th>
              <th className="text-right font-normal">Fixed in</th>
            </tr>
          </thead>
          <tbody>
            {p.advisories.map((a) => (
              <tr key={a.id} className="border-t">
                <td className="py-1">
                  <Link
                    href={`/vulnerabilities/${encodeURIComponent(a.id)}`}
                    className="font-mono hover:text-primary hover:underline"
                  >
                    {a.id}
                  </Link>
                </td>
                <td>
                  <RiskBadge risk={a.risk} />
                </td>
                <td className="text-right tabular-nums">
                  {a.epss != null ? `${(a.epss * 100).toFixed(1)}%` : "—"}
                </td>
                <td className="text-center">
                  {a.kev ? (
                    <Siren
                      className="inline size-3.5 text-red-600"
                      aria-label="Known exploited"
                    />
                  ) : (
                    "—"
                  )}
                </td>
                <td className="text-right font-mono">{a.fixed_in || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="rounded-md border border-primary/20 bg-accent p-2 text-accent-foreground">
        <span className="font-medium">Fix: </span>
        {p.fix}
      </p>
    </div>
  );
}
