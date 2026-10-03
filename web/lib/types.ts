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
  transitive_vulnerabilities: number;
  attack_paths: number;
  suspicious_findings: number;
  license_issues: number;
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
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Dependency-graph context: direct=null means unknown (no graph); depth 1 = direct. */
export type DepInfo = { direct: boolean | null; depth: number | null; dev: boolean | null };

export type VersionComponent = DepInfo & {
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
  severity?: Severity;
  blocking?: boolean;
  details?: Record<string, unknown>;
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

export type ComponentRow = DepInfo & {
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
  direct: boolean | null;
  depth: number | null;
  dev: boolean | null;
  via: string[];
  paths: string[][];
  imported: boolean | null;
  licenses: string[];
  graph_source: string | null;
};
export type Finding = {
  rule: string;
  category: string;
  severity: Severity;
  blocking: boolean;
  summary: string;
  component: ComponentRef;
  details: Record<string, unknown>;
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
  findings: Finding[];
};

// ---- attack paths ----
export type PathAdvisory = { id: string; risk: Risk; epss: number | null; kev: boolean; fixed_in: string | null };
export type PathItem = {
  chain: { name: string; version: string; component_id: string | null }[];
  target: { name: string; version: string; component_id: string };
  advisories: PathAdvisory[];
  risk: Risk;
  score: number;
  depth: number;
  direct_head: string;
  imported: boolean | null;
  dev: boolean;
  approximate: boolean;
  fix: string;
};
export type GraphNode = {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  direct: boolean | null;
  depth: number | null;
  vulns: number;
  max_risk: Risk | null;
  malware: boolean;
  suspicious: boolean;
  license_issue: boolean;
};
/** Edges start at "app" (the project itself) for direct dependencies. */
export type PathGraph = { source: string; nodes: GraphNode[]; edges: { from: string; to: string }[]; paths: PathItem[]; truncated?: boolean };
export type VulnPaths = { items: { project: ProjectRef; version: string; paths: PathItem[] }[] };

// ---- licenses ----
export type UsageModel = 'internal' | 'saas' | 'distributed_binary' | 'distributed_source';
export type ProjectSettings = { license: string | null; license_source: string | null; detected_license: string | null; usage_model: UsageModel };
export type LicenseReport = {
  project_license: string | null;
  usage_model: UsageModel;
  findings: { rule: string; severity: Severity; summary: string; component: ComponentRef; details: Record<string, unknown> }[];
  distribution: { license: string; count: number; category: string; summary?: string }[];
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
    license: { deny: string[]; enabled?: boolean; blocking_severity?: Severity };
    popularity: { enabled: boolean; min_stars: number };
    maintenance: { enabled: boolean; min_scorecard: number };
    suspicious?: SuspiciousPreset;
    packages?: PackageRule[];
  };
  custom: CustomRule[];
};
/** Package & version rule: banned package, allowed version range (min/max) or trusted package. */
export type PackageRule = { ecosystem?: string; name: string; versions?: string; deny?: boolean; allow?: boolean; reason?: string; severity?: Severity };
export type SuspiciousPreset = {
  typosquat: boolean;
  unmaintained: boolean;
  unmaintained_months: number;
  deprecated: boolean;
  new_package: boolean;
  no_source_repo: boolean;
  unusual_behaviour: boolean;
  blocking: string[];
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
  first_seen: string;
  last_seen: string;
};
export type PackageEvent = {
  id: number;
  ts: string;
  event_type: string;
  package_name: string | null;
  version: string | null;
  ecosystem: string | null;
  message?: string | null;
  details?: Record<string, unknown>;
};
export type AgentEvent = {
  id: string;
  session_id: string;
  ts: string;
  agent_name: string;
  action_type: string;
  result_status: string;
  tool_name: string | null;
  is_sensitive: boolean;
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
  errors: { error: string; at: string; attempt: number }[] | null;
  finalized_at: string | null;
};
