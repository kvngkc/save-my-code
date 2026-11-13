import type { AppModel, Finding } from "../types.js";
import { severityRank } from "../types.js";
import { accessControlCheck } from "./accessControl.js";
import { authCheck, configCheck, injectionCheck } from "./authInjectionConfig.js";
import { dataProtectionCheck } from "./dataProtection.js";
import { secretsCheck } from "./secrets.js";
import type { Check } from "./util.js";

export const BUILTIN_CHECKS: Array<{ name: string; run: Check }> = [
  { name: "secrets", run: secretsCheck },
  { name: "access-control", run: accessControlCheck },
  { name: "auth", run: authCheck },
  { name: "injection", run: injectionCheck },
  { name: "config", run: configCheck },
  { name: "data-protection", run: dataProtectionCheck },
];

export function runBuiltinChecks(model: AppModel): Finding[] {
  return BUILTIN_CHECKS.flatMap((c) => c.run(model));
}

export function sortFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings
    .filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || (a.file ?? "").localeCompare(b.file ?? "") || (a.line ?? 0) - (b.line ?? 0));
}
