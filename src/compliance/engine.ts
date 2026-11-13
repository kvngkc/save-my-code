import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import type { AppModel, ComplianceProfile, Finding, Requirement, RequirementResult, RulePack } from "../types.js";
import { evaluateSignal } from "./signals.js";

export const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "rules");

/** Jurisdiction codes that a pack's jurisdiction also covers. */
const COVERS: Record<string, string[]> = {
  EU: ["EU", "EEA", "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"],
  NG: ["NG"],
};

export function loadRulePacks(dir = RULES_DIR): RulePack[] {
  return readdirSync(dir)
    .filter((f) => /\.ya?ml$/.test(f))
    .sort()
    .map((f) => parse(readFileSync(join(dir, f), "utf8")) as RulePack);
}

export function packApplies(pack: RulePack, profile: ComplianceProfile): boolean {
  const codes = COVERS[pack.jurisdiction] ?? [pack.jurisdiction];
  return [...profile.jurisdictions, ...profile.users_located_in].some((j) => codes.includes(j.toUpperCase()));
}

export function requirementApplies(req: Requirement, profile: ComplianceProfile, model: AppModel): boolean {
  const a = req.applies_when;
  if (!a) return true;
  const usesAi = profile.uses_ai_providers === "auto" ? model.stack.aiProviders.length > 0 : profile.uses_ai_providers;
  const usesProcessors = usesAi || profile.processes_payments || model.stack.payments.length > 0 || model.stack.databases.some((d) => ["Supabase", "Firebase"].includes(d));
  const sensitive = new Set(profile.sensitive_data);
  if (profile.children) sensitive.add("children");
  if (a.collects_personal_data !== undefined && a.collects_personal_data !== profile.collects_personal_data) return false;
  if (a.children !== undefined && a.children !== (profile.children || sensitive.has("children"))) return false;
  if (a.automated_decisions !== undefined && a.automated_decisions !== profile.automated_decisions) return false;
  if (a.processes_payments !== undefined && a.processes_payments !== (profile.processes_payments || model.stack.payments.length > 0)) return false;
  if (a.uses_ai_providers !== undefined && a.uses_ai_providers !== usesAi) return false;
  if (a.uses_processors !== undefined && a.uses_processors !== usesProcessors) return false;
  if (a.sensitive_data_any && !a.sensitive_data_any.some((s) => sensitive.has(s))) return false;
  return true;
}

export function evaluateCompliance(model: AppModel, findings: Finding[], profile: ComplianceProfile, packs = loadRulePacks()): RequirementResult[] {
  const results: RequirementResult[] = [];
  const ctx = { model, findings, profile };
  for (const pack of packs) {
    if (!packApplies(pack, profile)) continue;
    for (const req of pack.requirements) {
      if (!requirementApplies(req, profile, model)) {
        results.push({ pack: pack.pack, requirement: req, status: "not-applicable", signals: [] });
        continue;
      }
      const signals = (req.verification.signals ?? []).map((id) => ({ id, ...evaluateSignal(id, ctx) }));
      let status: RequirementResult["status"];
      if (req.verification.type === "manual") status = "manual-review";
      else if (signals.some((s) => s.status === "fail")) status = "fail";
      else if (req.verification.type === "automated" && signals.length && signals.every((s) => s.status === "pass")) status = "pass";
      else status = "needs-evidence";
      results.push({
        pack: pack.pack,
        requirement: req,
        status,
        signals,
        note: req.needs_lawyer ? "Interpretation depends on your facts. Confirm with a qualified data-protection lawyer." : undefined,
      });
    }
  }
  return results;
}
