// Shapes of the Go API (docs/CONTRACTS.md). Keep in sync by hand.

export type List<T> = { items: T[]; total: number };
export type Risk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type Role = 'owner' | 'admin' | 'member';

export type Dashboard = {
  projects: number;
  components: number;
  suspicious: number;
  malicious: number;
  violations: number;
  vulnerabilities: number;
  violations_over_time: { date: string; count: number }[];
  violations_by_check: { check: string; count: number }[];
  vulns_over_time: { date: string; critical: number; high: number; medium: number; low: number }[];
  top_projects: { id: string; name: string; vulns: number }[];
};

export type Project = {
  id: string;
  name: string;
  source: string;
  url: string;
  versions: number;
  components: number;
  violations: number;
  vulns: number;
  created_at: string;
};

export type ProjectVersion = { id: string; name: string; last_scan_at: string | null; updated_at: string };
export type ProjectDetail = {
  id: string;
  name: string;
  source: string;
  url: string;
  created_at: string;
  versions: ProjectVersion[];
};
export type VersionSummary = {
  components: number;
  vulns: number;
  violations: number;
  versions_available: number;
  updated_at: string;
};

export type ComponentRef = { id: string; name: string; version: string; ecosystem: string; purl?: string };
export type ProjectRef = { id: string; name: string };

export type VersionComponent = {
  id: string;
  name: string;
  version: string;
  type: string;
  ecosystem: string;
  violations: number;
  vulns: number;
  created_at: string;
  updated_at: string;
};
export type VulnRow = { id: string; summary: string; risk: Risk; published: string; modified: string };
export type Violation = {
  id: string;
  rule_name: string;
  category: string;
  summary: string;
  component: ComponentRef;
  project?: ProjectRef;
  version?: string;
  scan_id?: string;
  created_at: string;
};
export type VersionScan = {
  id: string;
  trigger: string;
  violations: number;
  vulns: number;
  status: string;
  created_at: string;
};

export type Repository = {
  id: string;
  full_name: string;
  default_branch: string;
  private: boolean;
  installation_id: string;
};

export type ComponentRow = {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  type: string;
  projects: number;
  violations: number;
  vulns: number;
  updated_at: string;
};

export type ScanRow = {
  id: string;
  project: ProjectRef;
  version: string;
  trigger: string;
  violations: number;
  vulns: number;
  status: string;
  created_at: string;
};

export type ScanPackage = {
  component: ComponentRef;
  manifest_path: string;
  change: string;
  malware: boolean;
  vulnerable: boolean;
  risky_license: boolean;
  vulns: { id: string; summary: string; risk: Risk }[];
  violations: { rule_name: string; category: string; summary: string }[];
};
export type ScanDetail = {
  id: string;
  project: ProjectRef;
  version: string;
  trigger: string;
  status: string;
  conclusion: string;
  pr_number: number | null;
  head_sha: string;
  created_at: string;
  finished_at: string | null;
  error: string | null;
  counts: { components: number; vulns: number; violations: number; malicious: number; suspicious: number };
  report_md: string;
  packages: ScanPackage[];
};

export type AnalysisStatus = 'clean' | 'suspicious' | 'malicious';
export type PackageAnalysis = {
  id: string;
  component: ComponentRef;
  project: ProjectRef;
  version: string;
  status: AnalysisStatus;
  verified: boolean;
  created_at: string;
};
export type PackageAnalysisDetail = PackageAnalysis & {
  source: string;
  evidence: unknown;
  verified_by: string | null;
  verified_at: string | null;
  scan_id: string | null;
};

export type VulnerabilityRow = {
  id: string;
  summary: string;
  risk: Risk;
  affected_components: number;
  affected_projects: number;
  published: string;
  modified: string;
};
export type VulnerabilityDetail = {
  id: string;
  summary: string;
  details: string;
  risk: Risk;
  aliases: string[];
  severity: { type: string; score: string }[] | null;
  published: string;
  modified: string;
  references: { type: string; url: string }[] | null;
  epss: number | null;
  kev: boolean;
};
export type AffectedComponent = { component: ComponentRef; projects: ProjectRef[] };

export type Policy = {
  presets: {
    vulnerability: { min_risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'OFF' };
    malware: { enabled: boolean };
    license: { deny: string[] };
    popularity: { enabled: boolean; min_stars: number };
    maintenance: { enabled: boolean; min_scorecard: number };
  };
  custom: CustomRule[];
};
export type CustomRule = { name: string; category: string; summary: string; expr: string };

export type Endpoint = {
  id: string;
  identifier: string;
  endpoint_type: string;
  hostname: string;
  os: string;
  last_sync_at: string | null;
  inventory_count: number;
  created_at: string;
};
export type InventoryItem = {
  id: string;
  kind: string;
  name: string;
  version: string;
  scope: string;
  config_path: string;
  updated_at: string;
};
export type PackageEvent = {
  id: string;
  timestamp: string;
  event_type: string;
  package_name: string;
  version: string;
  ecosystem: string;
};
export type AgentEvent = {
  id: string;
  timestamp: string;
  agent: string;
  action: string;
  target: string;
  result: string;
};

export type QueryResult = { columns: string[]; rows: unknown[][]; truncated: boolean; elapsed_ms: number };
export type QuerySchema = { tables: { name: string; columns: { name: string; type: string }[] }[] };
export type SavedQuery = { id: string; name: string; sql: string; created_at: string };

export type Settings = {
  tenant_id: string;
  domain: string;
  plan: string;
  block_mode: boolean;
  scan_draft_prs: boolean;
  suppress_clean_comments: boolean;
  /** Requested from the API (not yet in CONTRACTS.md): set when a super-admin disabled the tenant. */
  disabled_at?: string | null;
};

export type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  key?: string;
};

export type Exclusion = {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  reason: string;
  status: 'active' | 'expired';
  expires_at: string | null;
  created_at: string;
};

export type Integrations = {
  api_url?: string;
  mcp_url?: string;
  github: {
    install_url: string;
    installations: { id: string; account_login: string; status: string; repos: number }[];
  };
};

export type AdminTenant = {
  tenant_id: string;
  domain: string;
  plan: string;
  disabled_at: string | null;
  projects: number;
  installations: number;
};
export type AdminInstallation = {
  id: string;
  account_login: string;
  account_type: string;
  status: string;
  tenant_id: string | null;
  repos: number;
  created_at: string;
};
export type FeedStatus = {
  source: string;
  last_ok: string | null;
  last_error: string | null;
  cursor: string | null;
  updated_at: string;
};
export type WebhookDelivery = {
  delivery_id: string;
  event: string;
  status: string;
  error: string | null;
  received_at: string;
};
export type FailedJob = {
  id: number;
  kind: string;
  state: string;
  attempt: number;
  errors: string[] | null;
  finalized_at: string | null;
};
