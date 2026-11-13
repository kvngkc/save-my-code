#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { loadRulePacks } from "./compliance/engine.js";
import { findProfile, profileTemplate } from "./compliance/profile.js";
import { buildAppModel } from "./model/appModel.js";
import { runBuiltinChecks, sortFindings } from "./checks/index.js";
import { renderContext } from "./report/context.js";
import { renderHtml } from "./report/html.js";
import { countBySeverity, renderMarkdown } from "./report/markdown.js";
import { renderSarif } from "./report/sarif.js";
import { scan, VERSION } from "./scan.js";
import type { ComplianceProfile, ScanResult, Severity } from "./types.js";

const HELP = `save-my-code ${VERSION} - independent assurance for AI-generated software

Usage:
  save-my-code init [path] [--yes]          Create a compliance profile (.save-my-code/profile.yml)
  save-my-code scan [path] [options]        Scan a project and write a report
  save-my-code context [path]               Print the app map + key source for a coding agent to review
  save-my-code rules                        List the compliance requirements in each rule pack

Scan options:
  --profile <file>          Compliance profile (default: .save-my-code/profile.yml in the project)
  --ai                      Run the AI review step (needs Anthropic credentials, e.g. ANTHROPIC_API_KEY)
  --no-external             Don't run semgrep / gitleaks / osv-scanner even if installed
  --format <list>           Comma-separated: md,json,html,sarif (default: md,json,html)
  --out <dir>               Report directory (default: <path>/.save-my-code/reports)
  --fail-on <severity>      critical | high | medium | low | none (default: high)
  --fail-on-compliance      Also block the release when a compliance requirement fails
  --min-confidence <level>  low | medium | high (default: low)
  --quiet                   Only print the verdict line

Exit codes: 0 pass/warn, 1 block, 2 usage or runtime error.
`;

function parseArgs(argv: string[]) {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=", 2);
      if (v !== undefined) flags[k] = v;
      else if (["profile", "format", "out", "fail-on", "min-confidence"].includes(k)) flags[k] = argv[++i] ?? "";
      else flags[k] = true;
    } else if (a === "-h") flags.help = true;
    else positional.push(a);
  }
  return { positional, flags };
}

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const color = (code: number) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = color(31), yellow = color(33), green = color(32), blue = color(34), dim = color(2), bold = color(1);
const SEV_COLOR: Record<Severity, (s: string) => string> = { critical: (s) => bold(red(s)), high: red, medium: yellow, low: blue, info: dim };

async function main() {
  const [cmd = "help", ...rest] = process.argv.slice(2);
  const { positional, flags } = parseArgs(rest);
  if (flags.help || cmd === "help" || cmd === "--help" || cmd === "-h") return void process.stdout.write(HELP);
  if (cmd === "--version" || cmd === "version") return void console.log(VERSION);
  const root = resolve(positional[0] ?? ".");
  if (cmd !== "rules" && !existsSync(root)) throw new UsageError(`Path not found: ${root}`);

  switch (cmd) {
    case "init":
      return init(root, !!flags.yes);
    case "scan":
      return runScan(root, flags);
    case "context": {
      const model = buildAppModel(root);
      return void process.stdout.write(renderContext(model, sortFindings(runBuiltinChecks(model))) + "\n");
    }
    case "rules":
      for (const p of loadRulePacks()) {
        console.log(bold(`${p.title}`) + dim(` [${p.pack} v${p.version}, ${p.review_status}]`));
        for (const r of p.requirements) console.log(`  ${r.id.padEnd(8)} ${r.title} ${dim(`(${r.citation}${r.citation_verified ? "" : ", unverified"})`)}`);
        console.log();
      }
      return;
    default:
      throw new UsageError(`Unknown command "${cmd}".\n\n${HELP}`);
  }
}

class UsageError extends Error {}

async function init(root: string, yes: boolean) {
  const target = join(root, ".save-my-code", "profile.yml");
  if (findProfile(root)) {
    console.log(`A profile already exists: ${findProfile(root)}`);
    return;
  }
  let answers: Partial<ComplianceProfile> = { project: root.split(/[\\/]/).pop() };
  if (!yes && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const ask = async (q: string, def: string) => ((await rl.question(`${q} ${dim(`[${def}]`)} `)).trim() || def);
    const yn = async (q: string, def: boolean) => /^y/i.test(await ask(q + " (y/n)", def ? "y" : "n"));
    const codes = (s: string) => s.split(/[,\s]+/).filter(Boolean).map((x) => x.toUpperCase());
    console.log(bold("Save-My-Code compliance profile") + dim("  (press Enter to accept defaults)\n"));
    answers.project = await ask("Project name?", answers.project ?? "my-app");
    answers.jurisdictions = codes(await ask("Where does the business operate? (country codes, e.g. NG, EU)", "NG"));
    answers.users_located_in = codes(await ask("Where are your users located?", answers.jurisdictions.join(",")));
    answers.industry = await ask("Industry? (healthcare, finance, education, ecommerce, saas, other)", "other");
    answers.collects_personal_data = await yn("Does it collect personal information (names, emails, phone numbers...)?", true);
    const sens = await ask("Sensitive data? (health, financial, children, biometric, government-id - comma separated, or none)", "none");
    answers.sensitive_data = sens === "none" ? [] : (sens.split(/[,\s]+/).filter(Boolean) as ComplianceProfile["sensitive_data"]);
    answers.processes_payments = await yn("Does it process payments?", false);
    answers.automated_decisions = await yn("Does it make automated decisions about people (scoring, eligibility)?", false);
    answers.children = await yn("Is it aimed at or likely used by children?", answers.sensitive_data.includes("children"));
    answers.serves = (await ask("Serves consumers, businesses or both?", "consumers")) as ComplianceProfile["serves"];
    rl.close();
  }
  mkdirSync(join(root, ".save-my-code"), { recursive: true });
  writeFileSync(target, profileTemplate(answers));
  console.log(green(`✓ Wrote ${target}`) + (yes ? dim("  (defaults - set jurisdictions and data types, or compliance checks will be skipped)") : ""));
  console.log(`Next: ${bold(`save-my-code scan ${displayPath(root)}`)}`);
}

const displayPath = (root: string) => (root === process.cwd() ? "" : root);

async function runScan(root: string, flags: Record<string, string | boolean>) {
  const failOn = (flags["fail-on"] as Severity | "none") ?? "high";
  if (!["critical", "high", "medium", "low", "info", "none"].includes(failOn)) throw new UsageError(`Invalid --fail-on: ${failOn}`);
  const formats = String(flags.format ?? "md,json,html").split(",").map((s) => s.trim());
  const result = await scan(root, {
    profilePath: flags.profile as string | undefined,
    ai: !!flags.ai,
    external: flags["no-external"] ? false : true,
    failOn,
    failOnCompliance: !!flags["fail-on-compliance"],
    minConfidence: (flags["min-confidence"] as "low" | "medium" | "high") ?? "low",
  });

  const outDir = resolve((flags.out as string) ?? join(root, ".save-my-code", "reports"));
  mkdirSync(outDir, { recursive: true });
  const written: string[] = [];
  const write = (name: string, body: string) => {
    writeFileSync(join(outDir, name), body);
    written.push(join(outDir, name));
  };
  if (formats.includes("md")) write("report.md", renderMarkdown(result));
  if (formats.includes("json")) write("report.json", JSON.stringify(result, null, 2));
  if (formats.includes("html")) write("report.html", renderHtml(result));
  if (formats.includes("sarif")) write("report.sarif", renderSarif(result));

  if (!flags.quiet) printSummary(result);
  const v = result.decision.verdict;
  console.log(`\n${bold("Release decision:")} ${v === "block" ? bold(red("BLOCK")) : v === "warn" ? bold(yellow("WARN")) : bold(green("PASS"))}  ${dim(result.decision.reasons.join(" "))}`);
  for (const w of written) console.log(dim(`  report: ${w}`));
  process.exitCode = v === "block" ? 1 : 0;
}

function printSummary(r: ScanResult) {
  const c = countBySeverity(r.findings);
  const s = r.model.stack;
  console.log(bold(`\nSave-My-Code ${r.tool.version}`) + dim(`  ${r.root}`));
  console.log(dim(`Stack: ${[...s.frameworks, ...s.databases].join(", ") || "unknown"} · ${r.model.fileCount} files · ${r.model.routes.length} routes · ${r.model.tables.length} tables`));
  console.log(`\n${SEV_COLOR.critical(`${c.critical} critical`)}  ${SEV_COLOR.high(`${c.high} high`)}  ${SEV_COLOR.medium(`${c.medium} medium`)}  ${SEV_COLOR.low(`${c.low} low`)}\n`);
  for (const f of r.findings.slice(0, 25)) {
    console.log(`  ${SEV_COLOR[f.severity](f.severity.toUpperCase().padEnd(8))} ${f.title}`);
    if (f.file) console.log(dim(`           ${f.file}${f.line ? `:${f.line}` : ""}`));
  }
  if (r.findings.length > 25) console.log(dim(`  … ${r.findings.length - 25} more in the report`));
  if (r.profile) {
    const counts = { pass: 0, fail: 0, "needs-evidence": 0, "manual-review": 0 } as Record<string, number>;
    for (const x of r.compliance) if (x.status !== "not-applicable") counts[x.status]++;
    console.log(`\n${bold("Compliance")} ${dim(`(${[...new Set(r.compliance.map((x) => x.pack))].join(", ") || "no matching pack"})`)}: ${green(`${counts.pass} pass`)}  ${red(`${counts.fail} fail`)}  ${yellow(`${counts["needs-evidence"]} need evidence`)}  ${blue(`${counts["manual-review"]} manual review`)}`);
    for (const x of r.compliance.filter((x) => x.status === "fail")) console.log(`  ${red("✗")} ${x.requirement.id} ${x.requirement.title}`);
  } else {
    console.log(dim(`\nCompliance: skipped (run \`save-my-code init\` to add a profile)`));
  }
  const skipped = r.coverage.filter((t) => t.status !== "ran");
  if (skipped.length) console.log(dim(`\nNot run: ${skipped.map((t) => `${t.tool} (${t.detail})`).join("; ")}`));
}

main().catch((err) => {
  console.error(err instanceof UsageError ? err.message : err?.stack ?? String(err));
  process.exitCode = 2;
});
