import { spawnSync } from "node:child_process";
import { relative, sep } from "node:path";
import type { Finding, Severity, ToolRun } from "../types.js";
import { finding } from "../checks/util.js";

function has(bin: string): boolean {
  const r = spawnSync(process.platform === "win32" ? "where" : "which", [bin], { encoding: "utf8" });
  return r.status === 0;
}

function run(bin: string, args: string[], cwd: string) {
  return spawnSync(bin, args, { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024, timeout: 10 * 60 * 1000 });
}

const rel = (root: string, p: string) => relative(root, p).split(sep).join("/") || p;

export interface ExternalResult {
  findings: Finding[];
  coverage: ToolRun[];
}

export function runExternalTools(root: string): ExternalResult {
  const findings: Finding[] = [];
  const coverage: ToolRun[] = [];
  for (const t of [semgrep, gitleaks, osvScanner]) {
    const res = t(root);
    findings.push(...res.findings);
    coverage.push(res.run);
  }
  return { findings, coverage };
}

function semgrep(root: string): { findings: Finding[]; run: ToolRun } {
  if (!has("semgrep")) return { findings: [], run: { tool: "semgrep", status: "skipped", detail: "not installed (pip install semgrep)", findings: 0 } };
  const r = run("semgrep", ["scan", "--config", "p/default", "--json", "--quiet", "--metrics", "off", "."], root);
  try {
    const out = JSON.parse(r.stdout);
    const sev: Record<string, Severity> = { ERROR: "high", WARNING: "medium", INFO: "low" };
    const fs = (out.results ?? []).map((x: any) =>
      finding({
        source: "semgrep",
        ruleId: `semgrep/${x.check_id}`,
        title: (x.extra?.message ?? x.check_id).split("\n")[0].slice(0, 140),
        severity: sev[x.extra?.severity] ?? "medium",
        category: /secret/i.test(x.check_id) ? "secrets" : /inject|sqli|xss|exec/i.test(x.check_id) ? "injection" : "config",
        confidence: "medium",
        file: rel(root, x.path),
        line: x.start?.line,
        evidence: x.extra?.lines?.slice(0, 300),
        description: x.extra?.message ?? "",
        remediation: x.extra?.fix ? `Suggested fix: ${x.extra.fix}` : "See the Semgrep rule documentation.",
        references: x.extra?.metadata?.references?.slice(0, 3),
      }),
    );
    return { findings: fs, run: { tool: "semgrep", status: "ran", detail: "ruleset p/default", findings: fs.length } };
  } catch {
    return { findings: [], run: { tool: "semgrep", status: "failed", detail: (r.stderr || "could not parse output").slice(0, 200), findings: 0 } };
  }
}

function gitleaks(root: string): { findings: Finding[]; run: ToolRun } {
  if (!has("gitleaks")) return { findings: [], run: { tool: "gitleaks", status: "skipped", detail: "not installed (https://github.com/gitleaks/gitleaks)", findings: 0 } };
  const r = run("gitleaks", ["detect", "--source", ".", "--report-format", "json", "--report-path", "/dev/stdout", "--no-banner", "--exit-code", "0"], root);
  try {
    const out = JSON.parse(r.stdout || "[]");
    const fs = out.map((x: any) =>
      finding({
        source: "gitleaks",
        ruleId: `gitleaks/${x.RuleID}`,
        title: `${x.Description ?? x.RuleID}${x.Commit ? " (in git history)" : ""}`,
        severity: "critical",
        category: "secrets",
        confidence: "high",
        file: x.File,
        line: x.StartLine,
        evidence: x.Secret ? `${String(x.Secret).slice(0, 4)}…` : undefined,
        description: x.Commit ? `Secret found in commit ${String(x.Commit).slice(0, 8)}. Removing it from the current files does not remove it from history.` : "Secret found in the working tree.",
        remediation: "Rotate the credential and purge it from git history.",
      }),
    );
    return { findings: fs, run: { tool: "gitleaks", status: "ran", detail: "working tree + git history", findings: fs.length } };
  } catch {
    return { findings: [], run: { tool: "gitleaks", status: "failed", detail: (r.stderr || "could not parse output").slice(0, 200), findings: 0 } };
  }
}

function osvScanner(root: string): { findings: Finding[]; run: ToolRun } {
  if (!has("osv-scanner")) return { findings: [], run: { tool: "osv-scanner", status: "skipped", detail: "not installed (https://google.github.io/osv-scanner/); dependency vulnerabilities not checked", findings: 0 } };
  const r = run("osv-scanner", ["scan", "--format", "json", "-r", "."], root);
  try {
    const out = JSON.parse(r.stdout);
    const fs: Finding[] = [];
    for (const res of out.results ?? []) {
      for (const pkg of res.packages ?? []) {
        for (const v of pkg.vulnerabilities ?? []) {
          const score = Number(pkg.groups?.find((g: any) => g.ids?.includes(v.id))?.max_severity ?? 0);
          fs.push(finding({
            source: "osv-scanner",
            ruleId: `dependencies/${v.id}`,
            title: `${pkg.package?.name}@${pkg.package?.version}: ${v.summary ?? v.id}`.slice(0, 160),
            severity: score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low",
            category: "dependencies",
            confidence: "high",
            file: rel(root, res.source?.path ?? ""),
            description: v.summary ?? v.details?.slice(0, 300) ?? v.id,
            remediation: "Upgrade to a patched version (see the advisory) or remove the dependency.",
            references: [`https://osv.dev/vulnerability/${v.id}`],
          }));
        }
      }
    }
    return { findings: fs, run: { tool: "osv-scanner", status: "ran", detail: "lockfiles", findings: fs.length } };
  } catch {
    return { findings: [], run: { tool: "osv-scanner", status: "failed", detail: (r.stderr || "could not parse output").slice(0, 200), findings: 0 } };
  }
}
