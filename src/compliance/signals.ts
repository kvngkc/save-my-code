import type { AppModel, ComplianceProfile, Finding, SignalResult } from "../types.js";
import { isCode, isTest } from "../model/files.js";

export interface SignalContext {
  model: AppModel;
  findings: Finding[];
  profile: ComplianceProfile;
}

type Signal = (ctx: SignalContext) => SignalResult;

const anyFile = (m: AppModel, pathRe: RegExp, contentRe?: RegExp) =>
  m.files.find((f) => pathRe.test(f.path) && (!contentRe || contentRe.test(f.content)));
const anyCode = (m: AppModel, re: RegExp) => m.files.find((f) => isCode(f.path) && !isTest(f.path) && re.test(f.content));
const blocking = (fs: Finding[], cats: string[]) => fs.filter((f) => cats.includes(f.category) && (f.severity === "critical" || f.severity === "high"));
const list = (fs: Finding[]) => fs.slice(0, 3).map((f) => `${f.title}${f.file ? ` (${f.file}:${f.line})` : ""}`).join("; ") + (fs.length > 3 ? `; +${fs.length - 3} more` : "");

export const SIGNALS: Record<string, Signal> = {
  privacy_notice_present: ({ model }) => {
    const f = anyFile(model, /privacy|data-protection|privacy-policy/i) ?? anyCode(model, /href=["'][^"']*privacy/i);
    return f ? { status: "pass", evidence: `Privacy notice found: ${f.path}` } : { status: "fail", evidence: "No privacy notice page, route or link found." };
  },

  consent_capture: ({ model }) => {
    const f = anyCode(model, /(type=["']checkbox["'][\s\S]{0,300}(consent|agree|privacy|terms)|(consent|agreeTo\w*|acceptTerms|terms_accepted|marketing_opt_in)\s*[:=])/i);
    return f
      ? { status: "pass", evidence: `Consent or terms acceptance captured in ${f.path}.` }
      : { status: "unknown", evidence: "No consent capture found in forms. Consent may not be needed if another lawful basis applies." };
  },

  account_deletion: ({ model }) => {
    const route = model.routes.find((r) => r.method === "DELETE" && /\/(account|accounts|users?|me|profile|profiles)(\/|$)/i.test(r.path));
    const f = route ? null : anyCode(model, /(auth\.admin\.deleteUser|deleteAccount|delete_account|deleteUser\s*\(|closeAccount)/);
    if (route) return { status: "pass", evidence: `Account deletion route: ${route.method} ${route.path} (${route.file})` };
    if (f) return { status: "pass", evidence: `Account deletion logic in ${f.path}` };
    return { status: "fail", evidence: "No way for users to delete their account or data was found." };
  },

  data_export: ({ model }) => {
    const f = anyCode(model, /(exportData|export_data|downloadMyData|download-data|data-export|dataPortability)/i);
    return f ? { status: "pass", evidence: `Data export in ${f.path}` } : { status: "unknown", evidence: "No self-service data export found. Access requests can be handled manually if a documented process exists." };
  },

  password_hashing: ({ model, findings }) => {
    const bad = findings.filter((f) => f.ruleId === "auth/plaintext-password" || f.ruleId === "auth/weak-password-hash");
    if (bad.length) return { status: "fail", evidence: list(bad) };
    const managed = model.stack.auth.filter((a) => ["Supabase Auth", "Clerk", "Auth0", "Auth.js"].includes(a));
    if (managed.length) return { status: "pass", evidence: `Managed authentication: ${managed.join(", ")}` };
    if (anyCode(model, /\b(bcrypt|argon2|scrypt|pbkdf2)\b/)) return { status: "pass", evidence: "Password hashing library in use." };
    return { status: "unknown", evidence: "No password storage detected." };
  },

  no_exposed_secrets: ({ findings }) => {
    const bad = blocking(findings, ["secrets"]);
    return bad.length ? { status: "fail", evidence: list(bad) } : { status: "pass", evidence: "No high-severity secret exposure found." };
  },

  access_control_enforced: ({ findings }) => {
    const bad = blocking(findings, ["access-control"]);
    return bad.length ? { status: "fail", evidence: list(bad) } : { status: "pass", evidence: "No high-severity access-control findings." };
  },

  no_critical_vulnerabilities: ({ findings }) => {
    const bad = blocking(findings, ["auth", "injection", "config"]).filter((f) => !/^auth\/(plaintext-password|weak-password-hash)$/.test(f.ruleId));
    return bad.length ? { status: "fail", evidence: list(bad) } : { status: "pass", evidence: "No high-severity auth, injection or configuration findings." };
  },

  no_secrets_in_logs: ({ findings }) => {
    const logs = findings.filter((f) => f.ruleId === "data-protection/secret-in-logs" || f.ruleId === "data-protection/pii-in-logs");
    const bad = logs.filter((f) => f.severity !== "low" && f.severity !== "info");
    if (bad.length) return { status: "fail", evidence: list(bad) };
    if (logs.length) return { status: "unknown", evidence: `Possible personal data in logs (low confidence): ${list(logs)}` };
    return { status: "pass", evidence: "No personal data or credentials found in log statements." };
  },

  breach_process_documented: ({ model }) => {
    const f = anyFile(model, /(SECURITY\.md|incident|breach|runbook)/i, /(breach|incident|notify|72)/i);
    return f ? { status: "pass", evidence: `Incident/breach process documented in ${f.path}` } : { status: "unknown", evidence: "No breach-response document found in the repository (it may exist elsewhere)." };
  },

  retention_policy: ({ model }) => {
    const f = anyCode(model, /(retention|purge|deleteOlderThan|expires_at|\bttl\b|pg_cron|cron\.schedule)/i) ?? anyFile(model, /retention/i);
    return f ? { status: "pass", evidence: `Retention or purge logic found in ${f.path}` } : { status: "unknown", evidence: "No data retention or automatic deletion logic found." };
  },

  age_gate: ({ model }) => {
    const f = anyCode(model, /(age\s*[<>]=?\s*(13|16|18)|(13|16|18)\s*[<>]=?\s*age|isMinor|parentalConsent|guardian_consent|ageVerification)/i);
    return f ? { status: "pass", evidence: `Age check found in ${f.path}` } : { status: "fail", evidence: "No age verification or parental consent flow found." };
  },

  sensitive_data_protected: ({ findings, model }) => {
    const bad = findings.filter((f) => f.ruleId === "data-protection/sensitive-identifier-stored" || (f.category === "access-control" && f.severity === "critical"));
    if (bad.length) return { status: "fail", evidence: list(bad) };
    const kinds = [...new Set(model.personalData.filter((p) => ["health", "government-id", "biometric", "financial"].includes(p.kind)).map((p) => p.kind))];
    return { status: kinds.length ? "unknown" : "pass", evidence: kinds.length ? `Sensitive fields detected (${kinds.join(", ")}); confirm encryption at rest and access restrictions.` : "No sensitive data fields detected." };
  },

  ai_provider_transfer: ({ model, findings }) => {
    const providers = model.stack.aiProviders;
    if (!providers.length) return { status: "pass", evidence: "No AI provider SDKs detected." };
    const pii = findings.filter((f) => f.ruleId === "data-protection/pii-to-ai-provider");
    return pii.length
      ? { status: "fail", evidence: `Personal data likely sent to ${providers.join(", ")}: ${list(pii)}` }
      : { status: "unknown", evidence: `AI providers in use (${providers.join(", ")}); confirm no personal data is sent, or document the transfer basis.` };
  },

  processors_identified: ({ model }) => {
    const processors = [...model.stack.aiProviders, ...model.stack.payments, ...model.stack.databases.filter((d) => ["Supabase", "Firebase"].includes(d)), ...model.stack.auth.filter((a) => ["Clerk", "Auth0"].includes(a))];
    return { status: "unknown", evidence: processors.length ? `Third-party processors detected: ${processors.join(", ")}. Confirm data processing agreements exist.` : "No third-party processors detected in code." };
  },
};

export function evaluateSignal(id: string, ctx: SignalContext): SignalResult {
  const fn = SIGNALS[id];
  if (!fn) return { status: "unknown", evidence: `Unknown signal "${id}" (rule pack references a check this version does not implement).` };
  return fn(ctx);
}
