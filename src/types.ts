export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";
export type Category =
  | "secrets"
  | "access-control"
  | "auth"
  | "injection"
  | "config"
  | "data-protection"
  | "dependencies"
  | "logic";
export type FindingSource = "builtin" | "ai" | "semgrep" | "gitleaks" | "osv-scanner";

export interface Finding {
  /** Stable fingerprint: ruleId + file + line */
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  category: Category;
  confidence: Confidence;
  source: FindingSource;
  file?: string;
  line?: number;
  /** Code excerpt that triggered the finding (secrets are masked) */
  evidence?: string;
  description: string;
  remediation: string;
  references?: string[];
}

export interface SourceFile {
  /** Path relative to the scanned root, always forward slashes */
  path: string;
  content: string;
  lines: string[];
  /** Heuristic: file runs in the browser */
  clientSide: boolean;
}

export type RouteKind = "next-app" | "next-pages" | "express";

export interface Route {
  kind: RouteKind;
  method: string;
  path: string;
  file: string;
  line: number;
  handler: string;
  hasAuthCheck: boolean;
  usesIdParam: boolean;
  touchesDatabase: boolean;
  referencesCurrentUser: boolean;
  mutates: boolean;
}

export interface SqlPolicy {
  name: string;
  command: string;
  roles: string[];
  using?: string;
  check?: string;
  file: string;
  line: number;
}

export interface SqlTable {
  name: string;
  file: string;
  line: number;
  columns: string[];
  rlsEnabled: boolean;
  policies: SqlPolicy[];
}

export interface PersonalDataField {
  field: string;
  kind: PersonalDataKind;
  file: string;
  line: number;
}

export type PersonalDataKind =
  | "contact"
  | "identity"
  | "government-id"
  | "financial"
  | "health"
  | "location"
  | "credentials"
  | "biometric"
  | "children";

export interface Stack {
  languages: string[];
  frameworks: string[];
  databases: string[];
  auth: string[];
  aiProviders: string[];
  payments: string[];
  hasGlobalAuthMiddleware: boolean;
}

export interface AppModel {
  root: string;
  files: SourceFile[];
  stack: Stack;
  routes: Route[];
  tables: SqlTable[];
  personalData: PersonalDataField[];
}

export type SensitiveCategory = "health" | "financial" | "children" | "biometric" | "government-id" | "religious" | "ethnic" | "political" | "sexual";

export interface ComplianceProfile {
  project: string;
  /** ISO-ish codes: NG, EU, UK, US, GH, KE, ZA ... */
  jurisdictions: string[];
  users_located_in: string[];
  industry: string;
  collects_personal_data: boolean;
  sensitive_data: SensitiveCategory[];
  processes_payments: boolean;
  automated_decisions: boolean;
  children: boolean;
  serves: "consumers" | "businesses" | "both";
  /** auto = detect from code */
  uses_ai_providers: boolean | "auto";
  hosting_region?: string;
}

export type SignalStatus = "pass" | "fail" | "unknown";
export interface SignalResult {
  status: SignalStatus;
  evidence: string;
}

export type RequirementStatus = "pass" | "fail" | "needs-evidence" | "manual-review" | "not-applicable";

export interface Requirement {
  id: string;
  title: string;
  citation: string;
  citation_verified: boolean;
  summary: string;
  applies_when?: Partial<{
    collects_personal_data: boolean;
    sensitive_data_any: SensitiveCategory[];
    children: boolean;
    automated_decisions: boolean;
    processes_payments: boolean;
    uses_ai_providers: boolean;
    uses_processors: boolean;
  }>;
  verification: {
    type: "automated" | "hybrid" | "manual";
    signals?: string[];
    question?: string;
  };
  needs_lawyer: boolean;
  remediation: string;
}

export interface RulePack {
  pack: string;
  title: string;
  jurisdiction: string;
  version: string;
  source_url: string;
  effective_date: string;
  review_status: "unreviewed" | "reviewed";
  reviewed_by?: string;
  reviewed_on?: string;
  disclaimer: string;
  requirements: Requirement[];
}

export interface RequirementResult {
  pack: string;
  requirement: Requirement;
  status: RequirementStatus;
  signals: Array<{ id: string } & SignalResult>;
  note?: string;
}

export interface ToolRun {
  tool: string;
  status: "ran" | "skipped" | "failed";
  detail: string;
  findings: number;
}

export interface ReleaseDecision {
  verdict: "pass" | "warn" | "block";
  reasons: string[];
  failOn: Severity | "none";
}

export interface ScanResult {
  tool: { name: "save-my-code"; version: string };
  scannedAt: string;
  root: string;
  profile: ComplianceProfile | null;
  model: {
    fileCount: number;
    stack: Stack;
    routes: Array<Omit<Route, "handler">>;
    tables: SqlTable[];
    personalData: PersonalDataField[];
  };
  findings: Finding[];
  compliance: RequirementResult[];
  coverage: ToolRun[];
  decision: ReleaseDecision;
  limitations: string[];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
export const severityRank = (s: Severity) => SEVERITY_ORDER.indexOf(s);
