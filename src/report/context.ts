import type { AppModel, Finding } from "../types.js";
import { isCode, isTest } from "../model/files.js";

/**
 * Renders the application map plus the most security-relevant source files.
 * Used both as the AI reviewer's input and by `save-my-code context`, which lets a
 * coding agent (Claude Code, Cursor...) perform the review itself without an API key.
 */
export function renderContext(model: AppModel, findings: Finding[], opts: { numbered?: boolean; maxChars?: number } = {}): string {
  const { numbered = true, maxChars = 400_000 } = opts;
  const s = model.stack;
  const parts: string[] = [];
  parts.push(`# Application map`);
  parts.push(`Stack: ${[...s.frameworks, ...s.databases].join(", ") || "unknown"} | Auth: ${s.auth.join(", ") || "none detected"} | AI providers: ${s.aiProviders.join(", ") || "none"} | Payments: ${s.payments.join(", ") || "none"}${s.hasGlobalAuthMiddleware ? " | Global auth middleware present" : ""}`);

  parts.push(`\n## Routes (${model.routes.length})`);
  for (const r of model.routes) {
    parts.push(`- ${r.method} ${r.path}  (${r.file}:${r.line})  auth:${r.hasAuthCheck ? "yes" : "NO"} idParam:${r.usesIdParam ? "yes" : "no"} db:${r.touchesDatabase ? "yes" : "no"} ownerScoped:${r.referencesCurrentUser ? "yes" : "no"}`);
  }
  if (model.tables.length) {
    parts.push(`\n## Database tables (${model.tables.length})`);
    for (const t of model.tables) {
      parts.push(`- ${t.name} (${t.file}:${t.line}) RLS:${t.rlsEnabled ? "on" : "OFF"} columns: ${t.columns.join(", ")}`);
      for (const p of t.policies) parts.push(`    policy "${p.name}" for ${p.command} using (${p.using ?? ""})${p.check ? ` with check (${p.check})` : ""}`);
    }
  }
  if (model.personalData.length) {
    const byKind = new Map<string, Set<string>>();
    for (const p of model.personalData) (byKind.get(p.kind) ?? byKind.set(p.kind, new Set()).get(p.kind)!).add(p.field);
    parts.push(`\n## Personal data detected`);
    for (const [k, v] of byKind) parts.push(`- ${k}: ${[...v].join(", ")}`);
  }
  if (findings.length) {
    parts.push(`\n## Findings from deterministic checks (${findings.length})`);
    for (const f of findings) parts.push(`- [${f.severity}] ${f.title}${f.file ? ` (${f.file}:${f.line ?? "?"})` : ""}`);
  }

  parts.push(`\n# Source files`);
  let budget = maxChars - parts.join("\n").length;
  const routeFiles = new Set(model.routes.map((r) => r.file));
  const candidates = model.files
    .filter((f) => (isCode(f.path) || /\.(sql|prisma|rules)$/.test(f.path)) && !isTest(f.path) && !/(^|\/)\.env/.test(f.path))
    .map((f) => ({ f, score: priority(f.path, f.content, routeFiles) }))
    .sort((a, b) => b.score - a.score || a.f.path.localeCompare(b.f.path));
  let omitted = 0;
  for (const { f } of candidates) {
    const body = numbered ? f.lines.map((l, i) => `${String(i + 1).padStart(4)}| ${l}`).join("\n") : f.content;
    const block = `\n## ${f.path}${f.clientSide ? " (client-side)" : ""}\n\`\`\`\n${body}\n\`\`\``;
    if (block.length > budget) {
      omitted++;
      continue;
    }
    parts.push(block);
    budget -= block.length;
  }
  if (omitted) parts.push(`\n(${omitted} lower-priority files omitted to fit the review budget.)`);
  return parts.join("\n");
}

function priority(path: string, content: string, routeFiles: Set<string>): number {
  let s = 0;
  if (routeFiles.has(path)) s += 50;
  if (/\.sql$|\.prisma$|\.rules$/.test(path)) s += 45;
  if (/middleware|auth|session|permission|policy|guard|admin/i.test(path)) s += 40;
  if (/(server|actions?|api|lib|services?|db|supabase)\//i.test(path)) s += 20;
  if (/["']use server["']/.test(content)) s += 30;
  if (/(payment|checkout|price|amount|webhook|wallet|transfer)/i.test(content)) s += 10;
  if (/(components|ui)\//.test(path)) s -= 10;
  return s;
}
