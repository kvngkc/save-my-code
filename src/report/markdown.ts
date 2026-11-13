import type { Finding, RequirementResult, ScanResult, Severity } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";

const ICON: Record<Severity, string> = { critical: "🟥", high: "🟧", medium: "🟨", low: "🟦", info: "⬜" };
const STATUS: Record<RequirementResult["status"], string> = {
  pass: "✅ Pass",
  fail: "❌ Fail",
  "needs-evidence": "🟡 Needs evidence",
  "manual-review": "📝 Manual review",
  "not-applicable": "➖ N/A",
};
const VERDICT = { pass: "✅ PASS", warn: "⚠️ WARN", block: "⛔ BLOCK" };

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export function renderMarkdown(r: ScanResult): string {
  const c = countBySeverity(r.findings);
  const L: string[] = [];
  L.push(`# Save-My-Code assurance report`);
  L.push("");
  L.push(`**Project:** ${r.profile?.project ?? r.root}  `);
  L.push(`**Scanned:** ${r.scannedAt}  `);
  L.push(`**Release decision:** ${VERDICT[r.decision.verdict]} (fail-on: ${r.decision.failOn})`);
  L.push("");
  for (const reason of r.decision.reasons) L.push(`- ${reason}`);
  L.push("");
  L.push(`| Critical | High | Medium | Low | Info |`);
  L.push(`|---:|---:|---:|---:|---:|`);
  L.push(`| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${c.info} |`);
  L.push("");

  const s = r.model.stack;
  L.push(`## What was scanned`);
  L.push("");
  L.push(`- **Files:** ${r.model.fileCount}`);
  L.push(`- **Stack:** ${[...s.frameworks, ...s.databases].join(", ") || "not detected"}`);
  L.push(`- **Auth:** ${s.auth.join(", ") || "none detected"}`);
  L.push(`- **AI providers:** ${s.aiProviders.join(", ") || "none detected"}`);
  L.push(`- **Payments:** ${s.payments.join(", ") || "none detected"}`);
  L.push(`- **Routes found:** ${r.model.routes.length} (${r.model.routes.filter((x) => !x.hasAuthCheck).length} without an auth check in the handler)`);
  L.push(`- **Database tables:** ${r.model.tables.length} (${r.model.tables.filter((t) => !t.rlsEnabled).length} without Row Level Security)`);
  const kinds = [...new Set(r.model.personalData.map((p) => p.kind))];
  L.push(`- **Personal data categories detected:** ${kinds.join(", ") || "none"}`);
  L.push("");

  L.push(`## Findings`);
  L.push("");
  if (!r.findings.length) L.push("No findings.");
  for (const sev of SEVERITY_ORDER) {
    const group = r.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    L.push(`### ${ICON[sev]} ${sev[0].toUpperCase() + sev.slice(1)} (${group.length})`);
    L.push("");
    group.forEach((f) => {
      L.push(`#### ${f.title}`);
      L.push("");
      L.push(`\`${f.ruleId}\` · ${f.category} · confidence: ${f.confidence} · source: ${f.source}${f.file ? ` · \`${f.file}${f.line ? `:${f.line}` : ""}\`` : ""}`);
      L.push("");
      if (f.evidence) {
        L.push("```");
        L.push(f.evidence);
        L.push("```");
      }
      L.push(f.description);
      L.push("");
      L.push(`**Fix:** ${f.remediation}`);
      if (f.references?.length) L.push(`\n_References: ${f.references.join("; ")}_`);
      L.push("");
    });
  }

  if (r.profile) {
    L.push(`## Compliance`);
    L.push("");
    L.push(`Jurisdictions: ${r.profile.jurisdictions.join(", ") || "-"} · Users in: ${r.profile.users_located_in.join(", ") || "-"} · Sensitive data: ${r.profile.sensitive_data.join(", ") || "none declared"}`);
    L.push("");
    const packs = [...new Set(r.compliance.map((x) => x.pack))];
    if (!packs.length) L.push("No rule pack matches the jurisdictions in the profile. Supported so far: NG (NDPA 2023), EU (GDPR).");
    for (const pack of packs) {
      const rows = r.compliance.filter((x) => x.pack === pack && x.status !== "not-applicable");
      L.push(`### ${pack}`);
      L.push("");
      L.push(`| Status | Requirement | Citation | Evidence |`);
      L.push(`|---|---|---|---|`);
      for (const x of rows) {
        const ev = x.signals.map((s) => `${s.status === "pass" ? "✓" : s.status === "fail" ? "✗" : "?"} ${s.evidence}`).join("<br>") || (x.requirement.verification.question ?? "");
        const cite = `${x.requirement.citation}${x.requirement.citation_verified ? "" : " ⚠︎"}`;
        L.push(`| ${STATUS[x.status]} | **${x.requirement.id}** ${x.requirement.title}${x.requirement.needs_lawyer ? " ⚖️" : ""} | ${cite} | ${ev.replace(/\|/g, "\\|")} |`);
      }
      L.push("");
    }
    L.push(`⚠︎ = citation not yet verified against the official text · ⚖️ = needs a lawyer's interpretation`);
    L.push("");
    const fails = r.compliance.filter((x) => x.status === "fail");
    if (fails.length) {
      L.push(`### What to fix for compliance`);
      L.push("");
      for (const x of fails) L.push(`- **${x.requirement.id}**: ${x.requirement.remediation.trim()}`);
      L.push("");
    }
    const questions = r.compliance.filter((x) => (x.status === "manual-review" || x.status === "needs-evidence") && x.requirement.verification.question);
    if (questions.length) {
      L.push(`### Questions you need to answer`);
      L.push("");
      for (const x of questions) L.push(`- **${x.requirement.id}**: ${x.requirement.verification.question}`);
      L.push("");
    }
  } else {
    L.push(`## Compliance`);
    L.push("");
    L.push("Skipped: no compliance profile. Run `save-my-code init` to describe where the app operates and what data it handles.");
    L.push("");
  }

  L.push(`## Coverage`);
  L.push("");
  L.push(`| Tool | Status | Detail | Findings |`);
  L.push(`|---|---|---|---:|`);
  for (const t of r.coverage) L.push(`| ${t.tool} | ${t.status} | ${t.detail} | ${t.findings} |`);
  L.push("");
  L.push(`## Limitations`);
  L.push("");
  for (const l of r.limitations) L.push(`- ${l}`);
  L.push("");
  return L.join("\n");
}
