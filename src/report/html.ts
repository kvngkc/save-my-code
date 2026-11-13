import type { RequirementResult, ScanResult, Severity } from "../types.js";
import { SEVERITY_ORDER } from "../types.js";
import { countBySeverity } from "./markdown.js";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const STATUS_LABEL: Record<RequirementResult["status"], string> = {
  pass: "Pass", fail: "Fail", "needs-evidence": "Needs evidence", "manual-review": "Manual review", "not-applicable": "N/A",
};

/** Self-contained HTML report (no external assets) suitable for sharing or attaching to a release. */
export function renderHtml(r: ScanResult): string {
  const c = countBySeverity(r.findings);
  const tiles = SEVERITY_ORDER.map((s) => `<div class="tile sev-${s}"><b>${c[s]}</b><span>${s}</span></div>`).join("");
  const findings = r.findings.length
    ? r.findings.map((f) => `
      <details class="finding sev-${f.severity}" ${f.severity === "critical" ? "open" : ""}>
        <summary><span class="badge sev-${f.severity}">${f.severity}</span> ${esc(f.title)}
          <small>${esc(f.file ?? "")}${f.line ? ":" + f.line : ""}</small></summary>
        <p class="meta"><code>${esc(f.ruleId)}</code> · ${esc(f.category)} · confidence ${esc(f.confidence)} · ${esc(f.source)}</p>
        ${f.evidence ? `<pre>${esc(f.evidence)}</pre>` : ""}
        <p>${esc(f.description)}</p>
        <p><b>Fix:</b> ${esc(f.remediation)}</p>
        ${f.references?.length ? `<p class="refs">${f.references.map(esc).join(" · ")}</p>` : ""}
      </details>`).join("")
    : `<p>No findings.</p>`;

  const packs = [...new Set(r.compliance.map((x) => x.pack))];
  const compliance = !r.profile
    ? `<p>Skipped: no compliance profile. Run <code>save-my-code init</code>.</p>`
    : packs.length === 0
      ? `<p>No rule pack matches the profile's jurisdictions. Supported: NG (NDPA 2023), EU (GDPR).</p>`
      : packs.map((p) => `
        <h3>${esc(p)}</h3>
        <table><thead><tr><th>Status</th><th>Requirement</th><th>Citation</th><th>Evidence</th></tr></thead><tbody>
        ${r.compliance.filter((x) => x.pack === p && x.status !== "not-applicable").map((x) => `
          <tr><td><span class="st st-${x.status}">${STATUS_LABEL[x.status]}</span></td>
          <td><b>${esc(x.requirement.id)}</b> ${esc(x.requirement.title)}${x.requirement.needs_lawyer ? ' <span title="Needs a lawyer\'s interpretation">⚖️</span>' : ""}</td>
          <td>${esc(x.requirement.citation)}${x.requirement.citation_verified ? "" : ' <span class="warn" title="Citation not yet verified against the official text">unverified</span>'}</td>
          <td>${x.signals.map((s) => `<div>${s.status === "pass" ? "✓" : s.status === "fail" ? "✗" : "?"} ${esc(s.evidence)}</div>`).join("") || esc(x.requirement.verification.question ?? "")}</td></tr>`).join("")}
        </tbody></table>`).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Save-My-Code report</title>
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--muted:#57534e;--card:#fff;--line:#e7e5e4;--crit:#b91c1c;--high:#c2410c;--med:#a16207;--low:#1d4ed8;--info:#57534e;--ok:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;--crit:#f87171;--high:#fb923c;--med:#facc15;--low:#60a5fa;--info:#a8a29e;--ok:#4ade80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px}h2{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--muted)}.verdict{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:700;margin:12px 0}
.v-pass{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}.v-warn{background:color-mix(in srgb,var(--med) 20%,transparent);color:var(--med)}.v-block{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px;text-align:center}
.tile b{display:block;font-size:24px}.tile span{color:var(--muted);text-transform:capitalize;font-size:13px}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:8px;padding:10px 14px;margin:8px 0}
.finding summary{cursor:pointer;font-weight:600}.finding small{display:block;font-weight:400;color:var(--muted);word-break:break-all}
.sev-critical{border-left-color:var(--crit)}.sev-high{border-left-color:var(--high)}.sev-medium{border-left-color:var(--med)}.sev-low{border-left-color:var(--low)}
.badge{font-size:11px;text-transform:uppercase;padding:2px 6px;border-radius:4px;color:#fff;background:var(--info)}
.badge.sev-critical{background:var(--crit)}.badge.sev-high{background:var(--high)}.badge.sev-medium{background:var(--med)}.badge.sev-low{background:var(--low)}
pre{background:var(--bg);border:1px solid var(--line);padding:8px;border-radius:6px;overflow-x:auto;font-size:13px}.meta,.refs{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px;display:block;overflow-x:auto}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.st{font-weight:600;white-space:nowrap}.st-pass{color:var(--ok)}.st-fail{color:var(--crit)}.st-needs-evidence{color:var(--med)}.st-manual-review{color:var(--low)}
.warn{font-size:11px;color:var(--med);border:1px solid currentColor;border-radius:4px;padding:0 4px}ul{padding-left:20px}
@media (max-width:600px){.tiles{grid-template-columns:repeat(3,1fr)}}
</style></head><body><main>
<h1>Save-My-Code report</h1>
<div class="sub">${esc(r.profile?.project ?? r.root)} · ${esc(r.scannedAt)}</div>
<div class="verdict v-${r.decision.verdict}">Release decision: ${r.decision.verdict.toUpperCase()}</div>
<ul>${r.decision.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
<div class="tiles">${tiles}</div>
<h2>Findings</h2>${findings}
<h2>Compliance</h2>${compliance}
<h2>Coverage</h2>
<table><thead><tr><th>Tool</th><th>Status</th><th>Detail</th><th>Findings</th></tr></thead><tbody>
${r.coverage.map((t) => `<tr><td>${esc(t.tool)}</td><td>${esc(t.status)}</td><td>${esc(t.detail)}</td><td>${t.findings}</td></tr>`).join("")}
</tbody></table>
<h2>Limitations</h2><ul>${r.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
</main></body></html>`;
}

export type { Severity };
