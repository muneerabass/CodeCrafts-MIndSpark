import { api } from './api';
import type { JiraLink, List, NotificationsResponse } from './types';

/** Jira links of the tenant and whether new tickets can be created. */
export async function jiraState(canEdit: boolean) {
  const [links, n] = await Promise.all([api<List<JiraLink>>('/jira/links', { query: { page_size: 50 } }), api<NotificationsResponse>('/settings/notifications')]);
  const j = n.settings.jira;
  const enabled = canEdit && n.jira_token_set && Boolean(j.base_url && j.email && j.project_key);
  return { enabled, find: (kind: JiraLink['ref_kind'], ref: string) => links.items.find((l) => l.ref_kind === kind && l.ref === ref) };
}
