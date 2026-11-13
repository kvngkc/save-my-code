import type { AppModel, Finding } from "../types.js";
import { severityRank } from "../types.js";
import { accessControlCheck } from "./accessControl.js";
import { authCheck, configCheck, injectionCheck } from "./authInjectionConfig.js";
import { dataProtectionCheck } from "./dataProtection.js";
import { secretsCheck } from "./secrets.js";
import type { Check } from "./util.js";
import { isDevOnly } from "./util.js";
import { isTest } from "../model/files.js";

export const BUILTIN_CHECKS: Array<{ name: string; run: Check }> = [
  { name: "secrets", run: secretsCheck },
  { name: "access-control", run: accessControlCheck },
  { name: "auth", run: authCheck },
  { name: "injection", run: injectionCheck },
  { name: "config", run: configCheck },
  { name: "data-protection", run: dataProtectionCheck },
];

export function runBuiltinChecks(model: AppModel): Finding[] {
  return BUILTIN_CHECKS.flatMap((c) => c.run(model)).map(downgradeDevOnly);
}

/** Findings in tests, evals and one-off scripts are reported, but at low severity: they don't ship to users. */
function downgradeDevOnly(f: Finding): Finding {
  if (!f.file || !isDevOnly(f.file) || f.severity === "info" || f.severity === "low") return f;
  if (f.category === "secrets" && !isTest(f.file)) return f; // a real key in a script is still a real key
  return { ...f, severity: "low", confidence: "low", description: f.description + " (Found in test, eval or script code that does not ship to users, so the risk is lower.)" };
}

export function sortFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings
    .filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
}
