import Link from "next/link";
import {
  AlarmClock,
  Bug,
  FileChartLine,
  Hexagon,
  Scale,
  ShieldCheck,
  ShieldX,
} from "lucide-react";
import { api, apiOr404, one, type SearchParams } from "@/lib/api";
import { fmtDate, fmtDateTime, titleCase } from "@/lib/format";
import type {
  FixQueue,
  LicenseReport,
  List,
  ProjectDetail,
  Settings,
  VersionSummary,
  Violation,
} from "@/lib/types";
import { PageHeader } from "@/components/page";
import { DueBadge, RiskBadge } from "@/components/badges";
import { SavePdfButton } from "../../../scans/[id]/charts";
import { cn } from "@/lib/utils";

export const metadata = { title: "Compliance report" };

const usage: Record<string, string> = {
  internal: "Internal use only",
  saas: "Network service (SaaS)",
  distributed_binary: "Distributed as a binary",
  distributed_source: "Distributed as source",
};
const catTone: Record<string, string> = {
  permissive: "text-emerald-700 dark:text-emerald-400",
  "weak-copyleft": "text-amber-700 dark:text-amber-400",
  copyleft: "text-red-700 dark:text-red-400",
  "strong-copyleft": "text-red-700 dark:text-red-400",
};

function Section({
  n,
  title,
  children,
}: {
  n: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="break-inside-avoid-page space-y-3">
      <h2 className="flex items-baseline gap-2 border-b pb-1.5 text-lg font-semibold">
        <span className="text-sm text-muted-foreground tabular-nums">{n}.</span>{" "}
        {title}
      </h2>
      {children}
    </section>
  );
}

export default async function ComplianceReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: SearchParams;
}) {
  const { id } = await params;
  const sp = await searchParams;
  const project = await apiOr404<ProjectDetail>(
    `/projects/${encodeURIComponent(id)}`,
  );
  const version =
    project.versions.find((v) => v.id === one(sp.version)) ??
    project.versions[0];
  if (!version)
    return (
      <p className="p-6 text-sm text-muted-foreground">
        This project has no scanned versions yet.
      </p>
    );
  const base = `/projects/${encodeURIComponent(id)}/versions/${encodeURIComponent(version.id)}`;
  const [summary, lic, queue, viol, settings] = await Promise.all([
    api<VersionSummary>(`${base}/summary`),
    api<LicenseReport>(`${base}/licenses`),
    api<FixQueue>("/fix-queue", { query: { project_id: id } }),
    api<List<Violation>>(`${base}/violations`, { query: { page_size: 50 } }),
    api<Settings>("/settings"),
  ]);
  const byRisk = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } as Record<
    string,
    number
  >;
  for (const it of queue.items) byRisk[it.risk] = (byRisk[it.risk] ?? 0) + 1;
  const overdue = queue.items.filter((i) => i.overdue).length;
  const blocking = viol.items.filter((v) => v.blocking);
  const pass = byRisk.CRITICAL === 0 && overdue === 0 && blocking.length === 0;
  const now = new Date().toISOString();

  return (
    <>
      <PageHeader
        crumbs={[
          { label: "Projects", href: "/projects" },
          {
            label: project.name,
            href: `/projects/${encodeURIComponent(id)}?version=${encodeURIComponent(version.id)}`,
          },
          { label: "Compliance report" },
        ]}
        actions={<SavePdfButton />}
      />
      <article className="report mx-auto w-full max-w-4xl space-y-8 p-4 md:p-8 print:max-w-none print:p-0">
        <header className="space-y-3">
          <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
            depguard · software supply chain compliance report
          </p>
          <h1 className="text-3xl font-semibold">{project.name}</h1>
          <dl className="grid gap-x-8 gap-y-1 text-sm sm:grid-cols-2 [&>div]:flex-wrap">
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Branch</dt>
              <dd className="font-medium">{version.name}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Last scan</dt>
              <dd className="font-medium">{fmtDateTime(summary.updated_at)}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Report generated</dt>
              <dd className="font-medium">{fmtDateTime(now)}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Enforcement</dt>
              <dd className="font-medium">
                {settings.block_mode
                  ? "Blocking issues fail pull requests"
                  : "Report only"}
              </dd>
            </div>
          </dl>
        </header>

        <div
          className={cn(
            "flex items-start gap-3 rounded-xl border p-4",
            pass
              ? "border-emerald-500/40 bg-emerald-500/5"
              : "border-red-500/40 bg-red-500/5",
          )}
        >
          {pass ? (
            <ShieldCheck
              className="mt-0.5 size-6 shrink-0 text-emerald-600"
              aria-hidden
            />
          ) : (
            <ShieldX
              className="mt-0.5 size-6 shrink-0 text-red-600"
              aria-hidden
            />
          )}
          <div>
            <p className="font-semibold">
              {pass
                ? "No critical vulnerabilities, missed deadlines or blocking policy violations."
                : "Action required before this release meets policy."}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              As of {fmtDate(now)}, {project.name}@{version.name} uses{" "}
              {summary.components.toLocaleString("en-GB")} packages.{" "}
              {queue.total} have known vulnerabilities ({byRisk.CRITICAL}{" "}
              critical, {byRisk.HIGH} high), {overdue}{" "}
              {overdue === 1 ? "is" : "are"} past the fix deadline, and{" "}
              {blocking.length} blocking policy violation
              {blocking.length === 1 ? "" : "s"}{" "}
              {blocking.length === 1 ? "is" : "are"} open.
            </p>
          </div>
        </div>

        <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {[
            { icon: Hexagon, label: "Packages", value: summary.components },
            { icon: Bug, label: "Vulnerable packages", value: queue.total },
            { icon: AlarmClock, label: "Past deadline", value: overdue },
            {
              icon: FileChartLine,
              label: "Policy violations",
              value: summary.violations,
            },
            {
              icon: Scale,
              label: "License issues",
              value: lic.findings.length,
            },
          ].map((k) => (
            <div key={k.label} className="rounded-xl border p-3">
              <k.icon className="size-4 text-muted-foreground" aria-hidden />
              <dd className="mt-2 text-2xl font-semibold tabular-nums">
                {k.value.toLocaleString("en-GB")}
              </dd>
              <dt className="text-xs text-muted-foreground">{k.label}</dt>
            </div>
          ))}
        </dl>

        <Section n={1} title="Open vulnerabilities">
          <p className="text-sm text-muted-foreground">
            Fix deadlines: critical {queue.sla.critical || "–"} days, high{" "}
            {queue.sla.high || "–"}, medium {queue.sla.medium || "–"}, low{" "}
            {queue.sla.low || "–"}, counted from when depguard first found each
            issue.
          </p>
          {queue.items.length === 0 ? (
            <p className="text-sm">No known vulnerabilities.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[32rem] text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="py-2 pr-3 font-medium">Package</th>
                    <th className="py-2 pr-3 font-medium">Risk</th>
                    <th className="py-2 pr-3 font-medium">Advisories</th>
                    <th className="py-2 pr-3 font-medium">Fixed in</th>
                    <th className="py-2 font-medium">Deadline</th>
                  </tr>
                </thead>
                <tbody>
                  {queue.items.map((it) => (
                    <tr
                      key={`${it.name}@${it.version}`}
                      className="border-b align-top last:border-0"
                    >
                      <td className="py-2 pr-3">
                        <span className="font-medium">{it.name}</span>{" "}
                        <span className="font-mono text-xs text-muted-foreground">
                          {it.version}
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <RiskBadge risk={it.risk} />
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {it.advisories.map((a) => a.id).join(", ")}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {it.fixed_in || "–"}
                      </td>
                      <td className="py-2">
                        <DueBadge due={it.due_at} overdue={it.overdue} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>

        <Section n={2} title="Licenses">
          <p className="text-sm">
            Project license:{" "}
            <span className="font-medium">
              {lic.project_license ?? "not declared"}
            </span>{" "}
            · Distribution:{" "}
            <span className="font-medium">
              {usage[lic.usage_model] ?? lic.usage_model}
            </span>
          </p>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[32rem] text-sm">
              <thead>
                <tr className="border-b text-left text-xs text-muted-foreground">
                  <th className="py-2 pr-3 font-medium">License</th>
                  <th className="py-2 pr-3 font-medium">Category</th>
                  <th className="py-2 text-right font-medium">Packages</th>
                </tr>
              </thead>
              <tbody>
                {lic.distribution.map((d) => (
                  <tr key={d.license} className="border-b last:border-0">
                    <td className="py-1.5 pr-3 font-mono text-xs">
                      {d.license}
                    </td>
                    <td className={cn("py-1.5 pr-3", catTone[d.category])}>
                      {titleCase(d.category)}
                    </td>
                    <td className="py-1.5 text-right tabular-nums">
                      {d.count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {lic.findings.length > 0 && (
            <ul className="space-y-1 text-sm">
              {lic.findings.map((f, i) => (
                <li key={i}>
                  <span className="font-medium">
                    {f.component.name} {f.component.version}
                  </span>{" "}
                  <span className="text-muted-foreground">· {f.summary}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section n={3} title="Policy violations">
          {viol.items.length === 0 ? (
            <p className="text-sm">No policy violations.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {viol.items.map((v) => (
                <li key={v.id} className="flex flex-wrap gap-x-2">
                  <span
                    className={cn(
                      "font-medium",
                      v.blocking ? "text-red-700 dark:text-red-400" : "",
                    )}
                  >
                    {v.blocking ? "Blocking" : "Warning"}
                  </span>
                  <span className="font-mono text-xs leading-5">
                    {v.rule_name}
                  </span>
                  <span>
                    {v.component.name} {v.component.version}
                  </span>
                  <span className="text-muted-foreground">· {v.summary}</span>
                </li>
              ))}
              {viol.total > viol.items.length && (
                <li className="text-muted-foreground">
                  …and {viol.total - viol.items.length} more in depguard.
                </li>
              )}
            </ul>
          )}
        </Section>

        <Section n={4} title="Software bill of materials">
          <p className="text-sm">
            The complete list of {summary.components.toLocaleString("en-GB")}{" "}
            packages, with dependency relationships and known vulnerabilities,
            is available as a machine-readable SBOM:{" "}
            <a
              className="text-primary hover:underline"
              href={`/api/projects/${encodeURIComponent(id)}/sbom?format=cyclonedx&version=${encodeURIComponent(version.id)}`}
              download
            >
              CycloneDX 1.6
            </a>{" "}
            ·{" "}
            <a
              className="text-primary hover:underline"
              href={`/api/projects/${encodeURIComponent(id)}/sbom?format=spdx&version=${encodeURIComponent(version.id)}`}
              download
            >
              SPDX 2.3
            </a>
            .
          </p>
        </Section>

        <footer className="border-t pt-4 text-xs text-muted-foreground">
          Generated by depguard on {fmtDateTime(now)} from the latest scan of{" "}
          {project.name}@{version.name}. Vulnerability data: OSV, CISA KEV,
          FIRST EPSS.{" "}
          <Link
            className="print:hidden"
            href={`/projects/${encodeURIComponent(id)}?version=${encodeURIComponent(version.id)}`}
          >
            Back to project
          </Link>
        </footer>
      </article>
    </>
  );
}
