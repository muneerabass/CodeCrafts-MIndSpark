'use client';

import { Bot, Download, KeyRound, ShieldCheck, User } from 'lucide-react';
import { DataTable, type ColumnDef } from '@/components/data-table';
import { Button } from '@/components/ui/button';
import { downloadCsv } from '@/lib/csv';
import { fmtDateTime } from '@/lib/format';
import type { AuditEntry } from '@/lib/types';

// Human-readable names for recorded routes and web actions.
const LABELS: Record<string, string> = {
  'PUT /policy': 'Changed the policy',
  'PUT /settings': 'Changed preferences',
  'PUT /settings/pr': 'Changed pull request settings',
  'PUT /settings/fixes': 'Changed auto-fix settings',
  'PUT /settings/sla': 'Changed fix deadlines',
  'PUT /settings/notifications': 'Changed notifications',
  'POST /settings/notifications/test': 'Sent a test notification',
  'POST /api-keys': 'Created an API key',
  'DELETE /api-keys/{id}': 'Revoked an API key',
  'POST /exclusions': 'Added a package exclusion',
  'PUT /exclusions/{id}': 'Edited a package exclusion',
  'DELETE /exclusions/{id}': 'Removed a package exclusion',
  'POST /scans': 'Started a scan',
  'POST /v1/scans': 'Uploaded a scan (CLI/CI)',
  'POST /projects/{id}/fixes': 'Opened a fix pull request',
  'PUT /projects/{id}/settings': 'Changed project settings',
  'POST /projects/{id}/pull-requests/{number}/{action}': 'Acted on a pull request',
  'POST /package-analyses/{id}/verify': 'Verified a malware analysis',
  'POST /jira/issues': 'Created a Jira ticket',
  'POST /queries': 'Saved a query',
  'DELETE /queries/{id}': 'Deleted a saved query',
  'PATCH /admin/tenants/{id}': 'Platform admin changed the tenant',
  'web:org.rename': 'Renamed the organization',
  'web:member.invite': 'Invited a member',
  'web:member.role': 'Changed a member’s role',
  'web:member.remove': 'Removed a member',
  'web:invitation.cancel': 'Cancelled an invitation',
};
const label = (a: string) => LABELS[a] ?? a;
const kindIcon = { user: User, api_key: KeyRound, admin: ShieldCheck, system: Bot };
const detailText = (e: AuditEntry) =>
  [e.target_type && `${e.target_type} ${e.target_id}`, ...Object.entries(e.details ?? {}).map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)]
    .filter(Boolean)
    .join(' · ');

const cols: ColumnDef<AuditEntry, unknown>[] = [
  { header: 'When', cell: ({ row }) => <span className="text-sm whitespace-nowrap text-muted-foreground">{fmtDateTime(row.original.created_at)}</span> },
  {
    header: 'Who',
    cell: ({ row }) => {
      const e = row.original;
      const Icon = kindIcon[e.actor_kind] ?? User;
      return (
        <span className="inline-flex items-center gap-2 text-sm">
          <Icon className="size-4 text-muted-foreground" aria-hidden />
          <span>
            {e.actor_kind === 'api_key' ? 'API key' : e.actor_email || e.actor_id}
            <span className="block text-xs text-muted-foreground">
              {e.actor_kind === 'admin' ? 'platform admin' : e.actor_role}
              {e.ip && ` · ${e.ip}`}
            </span>
          </span>
        </span>
      );
    },
  },
  {
    header: 'What',
    cell: ({ row }) => (
      <span className="text-sm">
        <span className="font-medium">{label(row.original.action)}</span>
        <span className="block font-mono text-[11px] text-muted-foreground">{row.original.action}</span>
      </span>
    ),
  },
  { header: 'Details', cell: ({ row }) => <span className="block max-w-md truncate text-xs text-muted-foreground" title={detailText(row.original)}>{detailText(row.original) || '–'}</span> },
];

export function AuditTable({ data, total }: { data: AuditEntry[]; total: number }) {
  return (
    <>
      <div className="flex justify-end px-3 pt-3">
        <Button
          variant="outline"
          size="sm"
          disabled={!data.length}
          onClick={() =>
            downloadCsv(
              'depguard-audit-log',
              ['time', 'actor', 'actor_kind', 'role', 'action', 'description', 'target_type', 'target_id', 'details', 'ip'],
              data.map((e) => [e.created_at, e.actor_email || e.actor_id, e.actor_kind, e.actor_role, e.action, label(e.action), e.target_type, e.target_id, e.details, e.ip]),
            )
          }
        >
          <Download /> Export CSV
        </Button>
      </div>
      <DataTable columns={cols} data={data} total={total} defaultPageSize={50} />
    </>
  );
}
