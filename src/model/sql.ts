import type { SourceFile, SqlTable } from "../types.js";
import { lineOf } from "./files.js";

const ident = (s: string) => s.replace(/["`]/g, "").replace(/^public\./i, "").toLowerCase();

/**
 * Lightweight parser for Postgres/Supabase migrations. Handles the statements that
 * matter for access control: CREATE TABLE, ENABLE ROW LEVEL SECURITY, CREATE POLICY.
 * It is intentionally forgiving: unknown statements are ignored.
 */
export function parseSql(files: SourceFile[]): SqlTable[] {
  const tables = new Map<string, SqlTable>();
  // Files are processed in path order, so later migrations override earlier ones.
  for (const f of files) {
    const text = stripComments(f.content);
    for (const m of text.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?([\w."`]+)\s*\(([\s\S]*?)\);/gi)) {
      const name = ident(m[1]);
      const columns = m[2]
        .split(/,(?![^(]*\))/)
        .map((c) => c.trim().split(/\s+/)[0]?.replace(/["`]/g, ""))
        .filter((c): c is string => !!c && !/^(primary|foreign|unique|constraint|check)$/i.test(c));
      const existing = tables.get(name);
      tables.set(name, {
        name,
        file: f.path,
        line: lineOf(text, m.index!),
        columns,
        rlsEnabled: existing?.rlsEnabled ?? false,
        policies: existing?.policies ?? [],
      });
    }
    for (const m of text.matchAll(/alter\s+table\s+(?:only\s+)?([\w."`]+)\s+(enable|disable)\s+row\s+level\s+security/gi)) {
      const t = tables.get(ident(m[1]));
      if (t) t.rlsEnabled = m[2].toLowerCase() === "enable";
    }
    for (const m of text.matchAll(/create\s+policy\s+("[^"]+"|\w+)\s+on\s+([\w."`]+)([\s\S]*?);/gi)) {
      const t = tables.get(ident(m[2]));
      if (!t) continue;
      const body = m[3];
      const command = (body.match(/\bfor\s+(select|insert|update|delete|all)\b/i)?.[1] ?? "all").toLowerCase();
      t.policies.push({
        name: m[1].replace(/"/g, ""),
        command,
        using: balancedAfter(body, /\busing\s*\(/i),
        check: balancedAfter(body, /\bwith\s+check\s*\(/i),
        file: f.path,
        line: lineOf(text, m.index!),
      });
    }
    for (const m of text.matchAll(/drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|\w+)\s+on\s+([\w."`]+)/gi)) {
      const t = tables.get(ident(m[2]));
      if (t) t.policies = t.policies.filter((p) => p.name !== m[1].replace(/"/g, ""));
    }
  }
  return [...tables.values()];
}

/** Replace comments with spaces so offsets (and thus line numbers) are preserved. */
function stripComments(sql: string): string {
  return sql.replace(/--[^\n]*/g, (s) => " ".repeat(s.length)).replace(/\/\*[\s\S]*?\*\//g, (s) => s.replace(/[^\n]/g, " "));
}

function balancedAfter(text: string, opener: RegExp): string | undefined {
  const m = opener.exec(text);
  if (!m) return undefined;
  let depth = 1;
  const start = m.index + m[0].length;
  for (let i = start; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") {
      depth--;
      if (depth === 0) return text.slice(start, i).trim();
    }
  }
  return undefined;
}
