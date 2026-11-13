import type { AppModel, Finding, SqlTable } from "../types.js";
import { classifyField } from "../model/appModel.js";
import { excerpt, finding, OWASP, scan } from "./util.js";

const PUBLIC_ROUTE = /(^|\/)(health|status|webhooks?|public|auth\/(login|signin|signup|register|callback|reset|forgot|verify)|login|signup|register|og|sitemap|robots|cron)(\/|$)/i;

export function accessControlCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const mwNote = model.stack.hasGlobalAuthMiddleware
    ? " A global auth middleware was detected; confirm its matcher actually covers this route."
    : "";

  for (const r of model.routes) {
    const file = model.files.find((f) => f.path === r.file)!;
    if (PUBLIC_ROUTE.test(r.path)) continue;

    // IDOR: record looked up by client-supplied id with no ownership constraint.
    if (r.usesIdParam && r.touchesDatabase && !r.referencesCurrentUser) {
      const unauth = !r.hasAuthCheck;
      out.push(finding({
        ruleId: "access-control/idor",
        title: `${r.method} ${r.path} loads records by a client-supplied ID without checking ownership`,
        severity: unauth ? "critical" : r.mutates ? "critical" : "high",
        category: "access-control",
        confidence: unauth ? "high" : "medium",
        file: r.file,
        line: r.line,
        evidence: excerpt(file, r.line, 0),
        description:
          (unauth
            ? "The handler takes an ID from the request and queries the database with no authentication check at all. Anyone can enumerate IDs and read or change other users' records."
            : "The handler authenticates the caller but queries by the ID from the request without constraining the query to records the caller owns. Any logged-in user can access other users' records by changing the ID (insecure direct object reference).") + mwNote,
        remediation:
          "Scope the query to the authenticated user, e.g. `.eq('id', id).eq('user_id', user.id)` / `where: { id, userId: session.user.id }`, or enforce it in the database with Row Level Security. Return 404 when the record is not owned by the caller.",
        references: [OWASP.A01, "OWASP ASVS V4.2.1"],
      }));
      continue;
    }

    // Unauthenticated mutation
    if (r.mutates && r.touchesDatabase && !r.hasAuthCheck) {
      out.push(finding({
        ruleId: "access-control/unauthenticated-mutation",
        title: `${r.method} ${r.path} changes data without authentication`,
        severity: model.stack.hasGlobalAuthMiddleware ? "medium" : "high",
        category: "access-control",
        confidence: model.stack.hasGlobalAuthMiddleware ? "low" : "medium",
        file: r.file,
        line: r.line,
        evidence: excerpt(file, r.line, 0),
        description: "This route writes to the database but no authentication check was found in the handler." + mwNote,
        remediation: "Verify the session at the top of the handler and reject unauthenticated requests with 401.",
        references: [OWASP.A01, OWASP.A07],
      }));
    }

    // Admin routes without role checks
    if (/(^|\/)admin(\/|$)/i.test(r.path) && !/\b(role|isAdmin|is_admin|admin|permissions?|can\()\b/i.test(r.handler.replace(/\/admin/gi, ""))) {
      out.push(finding({
        ruleId: "access-control/admin-without-role-check",
        title: `Admin route ${r.method} ${r.path} has no role check`,
        severity: "high",
        category: "access-control",
        confidence: "medium",
        file: r.file,
        line: r.line,
        evidence: excerpt(file, r.line, 0),
        description: "The route lives under /admin but the handler never checks the caller's role. Being logged in may be enough to use it.",
        remediation: "Check an authoritative role (from the database or a signed claim, not from the request body) before performing admin actions.",
        references: [OWASP.A01, "OWASP ASVS V4.1.3"],
      }));
    }
  }

  out.push(...supabaseRls(model));
  out.push(...serviceRoleInClient(model));
  out.push(...clientTrustedRole(model));
  return out;
}

function tableHasPersonalData(t: SqlTable) {
  return t.columns.some((c) => classifyField(c) !== null) || /(user|profile|patient|customer|member|account|appointment|booking|order|payment)/i.test(t.name);
}

function supabaseRls(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const usesSupabase = model.stack.databases.includes("Supabase") || model.files.some((f) => /supabase\/migrations\//.test(f.path));
  if (!usesSupabase) return out;
  for (const t of model.tables) {
    const pii = tableHasPersonalData(t);
    if (!t.rlsEnabled) {
      out.push(finding({
        ruleId: "access-control/supabase-rls-disabled",
        title: `Table "${t.name}" has Row Level Security disabled`,
        severity: pii ? "critical" : "high",
        category: "access-control",
        confidence: "high",
        file: t.file,
        line: t.line,
        evidence: `create table ${t.name} (${t.columns.slice(0, 6).join(", ")}${t.columns.length > 6 ? ", …" : ""})`,
        description: `Supabase exposes every table in the public schema through its REST API using the anon key that ships in your frontend. Without RLS, anyone can read and modify all rows in "${t.name}"${pii ? ", which contains personal data" : ""}.`,
        remediation: `alter table ${t.name} enable row level security; then add policies such as: create policy "own rows" on ${t.name} for select using (auth.uid() = user_id);`,
        references: [OWASP.A01, "https://supabase.com/docs/guides/database/postgres/row-level-security"],
      }));
      continue;
    }
    for (const p of t.policies) {
      // Policies granted only to trusted server roles do not expose data to app users.
      if (p.roles.length && p.roles.every((r) => ["service_role", "postgres", "supabase_admin"].includes(r))) continue;
      const using = (p.using ?? "").replace(/\s+/g, "").toLowerCase();
      const check = (p.check ?? "").replace(/\s+/g, "").toLowerCase();
      const permissive = using === "true" || (p.command === "insert" && check === "true") || (!p.using && !p.check);
      const anyAuthed = /^auth\.role\(\)='authenticated'$|^\(selectauth\.role\(\)\)='authenticated'$|^auth\.uid\(\)isnotnull$/.test(using);
      if (!permissive && !anyAuthed) continue;
      const write = ["update", "delete", "all", "insert"].includes(p.command);
      if (!write && !pii) {
        out.push(finding({
          ruleId: "access-control/supabase-public-read",
          title: `Table "${t.name}" is readable by anyone`,
          severity: "info",
          category: "access-control",
          confidence: "medium",
          file: p.file,
          line: p.line,
          evidence: `for ${p.command} using (${p.using ?? ""})`,
          description: "No personal data columns were detected, so this is probably intentional public data (e.g. a directory). Confirm nothing sensitive is or will be stored here.",
          remediation: "No action needed if the data is meant to be public.",
          references: [OWASP.A01],
        }));
        continue;
      }
      out.push(finding({
        ruleId: anyAuthed ? "access-control/supabase-policy-any-user" : "access-control/supabase-policy-permissive",
        title: `Policy "${p.name}" on "${t.name}" lets ${anyAuthed ? "any logged-in user" : "anyone"} ${p.command === "all" ? "do anything" : p.command} on every row`,
        severity: write || (pii && !anyAuthed) ? "critical" : "high",
        category: "access-control",
        confidence: "high",
        file: p.file,
        line: p.line,
        evidence: `for ${p.command} using (${p.using ?? ""})${p.check ? ` with check (${p.check})` : ""}`,
        description: anyAuthed
          ? "The policy only checks that the caller is signed in, not that they own the row. Any user who signs up can access every other user's rows."
          : "The policy condition is always true, so RLS is enabled in name only.",
        remediation: `Constrain the policy to the row owner, e.g. using (auth.uid() = user_id)${write ? " with check (auth.uid() = user_id)" : ""}.`,
        references: [OWASP.A01],
      }));
    }
  }
  return out;
}

function serviceRoleInClient(model: AppModel): Finding[] {
  const out: Finding[] = [];
  for (const { file, line } of scan(model.files, /SERVICE_ROLE|service_role|serviceRoleKey/, (f) => f.clientSide)) {
    out.push(finding({
      ruleId: "access-control/service-role-in-client",
      title: "Supabase service-role key used in client-side code",
      severity: "critical",
      category: "access-control",
      confidence: "high",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "This file runs in the browser. Any key it uses is visible to every visitor, and the service-role key bypasses Row Level Security entirely.",
      remediation: "Use the anon key in the browser and rely on RLS. Move privileged operations to a server route that checks the user first.",
      references: [OWASP.A01],
    }));
  }
  return out;
}

function clientTrustedRole(model: AppModel): Finding[] {
  const out: Finding[] = [];
  for (const { file, line } of scan(model.files, /\b(req\.body|body|formData\.get\(\s*["'])\.?\s*(role|isAdmin|is_admin|plan|tier)\b/)) {
    if (file.clientSide) continue;
    out.push(finding({
      ruleId: "access-control/client-controlled-role",
      title: "Role or plan taken from the request body",
      severity: "high",
      category: "access-control",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "The server reads a privilege field (role/admin/plan) from data the client controls. A user can grant themselves admin or a paid plan by editing the request.",
      remediation: "Never accept privilege fields from the client. Derive them from the database or a signed server-side session, and strip them from user-editable updates.",
      references: [OWASP.A01, "OWASP ASVS V4.2.1"],
    }));
  }
  return out;
}
