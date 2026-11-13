import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runAiReview } from "./ai/review.js";
import { runBuiltinChecks, sortFindings, BUILTIN_CHECKS } from "./checks/index.js";
import { evaluateCompliance } from "./compliance/engine.js";
import { findProfile, loadProfile } from "./compliance/profile.js";
import { runExternalTools } from "./external/tools.js";
import { buildAppModel } from "./model/appModel.js";
import type { ComplianceProfile, Finding, ReleaseDecision, ScanResult, Severity, ToolRun } from "./types.js";
import { severityRank } from "./types.js";

export const VERSION: string = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")).version;

export interface ScanOptions {
  profilePath?: string;
  ai?: boolean;
  external?: boolean;
  failOn?: Severity | "none";
  failOnCompliance?: boolean;
  /** Minimum confidence to report */
  minConfidence?: "low" | "medium" | "high";
}

export async function scan(rootArg: string, opts: ScanOptions = {}): Promise<ScanResult> {
  const root = resolve(rootArg);
  const model = buildAppModel(root);
  const coverage: ToolRun[] = [];

  let findings: Finding[] = runBuiltinChecks(model);
  coverage.push({ tool: "built-in checks", status: "ran", detail: BUILTIN_CHECKS.map((c) => c.name).join(", "), findings: findings.length });

  if (opts.external !== false) {
    const ext = runExternalTools(root);
    findings.push(...ext.findings);
    coverage.push(...ext.coverage);
  }

  if (opts.ai) {
    const ai = await runAiReview(model, sortFindings(findings));
    findings.push(...ai.findings);
    coverage.push(ai.run);
  } else {
    coverage.push({ tool: "ai-review", status: "skipped", detail: "not requested (use --ai, or run `save-my-code context` inside your coding agent)", findings: 0 });
  }

  const minRank = { low: 0, medium: 1, high: 2 }[opts.minConfidence ?? "low"];
  const confRank = { low: 0, medium: 1, high: 2 };
  findings = sortFindings(findings.filter((f) => confRank[f.confidence] >= minRank));

  const profilePath = opts.profilePath ? resolve(opts.profilePath) : findProfile(root);
  const profile: ComplianceProfile | null = profilePath ? loadProfile(profilePath) : null;
  const compliance = profile ? evaluateCompliance(model, findings, profile) : [];
  coverage.push({
    tool: "compliance rule packs",
    status: profile ? "ran" : "skipped",
    detail: profile ? `${[...new Set(compliance.map((c) => c.pack))].join(", ") || "no pack matches profile jurisdictions"}` : "no profile (run `save-my-code init`)",
    findings: compliance.filter((c) => c.status === "fail").length,
  });

  const decision = decide(findings, compliance, opts);
  return {
    tool: { name: "save-my-code", version: VERSION },
    scannedAt: new Date().toISOString(),
    root,
    profile,
    model: {
      fileCount: model.files.length,
      stack: model.stack,
      routes: model.routes.map(({ handler: _h, ...r }) => r),
      tables: model.tables,
      personalData: model.personalData,
    },
    findings,
    compliance,
    coverage,
    decision,
    limitations: limitations(coverage, compliance.length > 0),
  };
}

export function decide(findings: Finding[], compliance: ScanResult["compliance"], opts: ScanOptions): ReleaseDecision {
  const failOn = opts.failOn ?? "high";
  const reasons: string[] = [];
  let verdict: ReleaseDecision["verdict"] = "pass";
  const blocking = failOn === "none" ? [] : findings.filter((f) => severityRank(f.severity) <= severityRank(failOn));
  if (blocking.length) {
    verdict = "block";
    reasons.push(`${blocking.length} finding(s) at or above "${failOn}" severity.`);
  }
  const compFails = compliance.filter((c) => c.status === "fail");
  if (compFails.length) {
    if (opts.failOnCompliance) {
      verdict = "block";
      reasons.push(`${compFails.length} compliance requirement(s) failed.`);
    } else {
      if (verdict === "pass") verdict = "warn";
      reasons.push(`${compFails.length} compliance requirement(s) failed (not blocking; use --fail-on-compliance to block).`);
    }
  }
  const below = findings.length - blocking.length;
  if (below > 0 && verdict === "pass") {
    verdict = "warn";
    reasons.push(`${below} lower-severity finding(s) to review.`);
  }
  if (verdict === "pass") reasons.push("No findings at or above the threshold. This is not a guarantee of security or compliance; see limitations.");
  return { verdict, reasons, failOn };
}

function limitations(coverage: ToolRun[], hasCompliance: boolean): string[] {
  const l = [
    "Automated analysis cannot prove an application is free of vulnerabilities. It finds known patterns and likely defects; it cannot detect every logic flaw or previously unknown (zero-day) vulnerability.",
    "Built-in checks are static heuristics for JavaScript/TypeScript web stacks (Next.js, Express, Supabase, Prisma). Other languages and frameworks get secret, SQL and data-protection checks only.",
    "No runtime or penetration testing was performed. Findings were not exploited against a running instance.",
  ];
  for (const t of coverage) if (t.status !== "ran") l.push(`${t.tool} did not run: ${t.detail}.`);
  if (hasCompliance) l.push("Compliance results are an engineering interpretation, not legal advice. Rule packs marked unreviewed have not yet been checked by a qualified lawyer, and many obligations (lawful basis, contracts, registration) cannot be verified from code.");
  return l;
}
