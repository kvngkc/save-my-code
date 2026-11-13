import { describe, expect, it } from "vitest";
import { runBuiltinChecks } from "../src/checks/index.js";
import { parseSql } from "../src/model/sql.js";
import { accessControlCheck } from "../src/checks/accessControl.js";
import type { AppModel, SourceFile } from "../src/types.js";

// Regression tests for false positives found by scanning a large real-world
// open-source Next.js + Supabase codebase. Each snippet mirrors a real pattern.
const file = (path: string, content: string, clientSide = false): SourceFile => ({ path, content, lines: content.split("\n"), clientSide });
const model = (files: SourceFile[], extra: Partial<AppModel> = {}): AppModel => ({
  root: "/x", files, routes: [], tables: [], personalData: [],
  stack: { languages: [], frameworks: [], databases: ["Supabase"], auth: [], aiProviders: [], payments: [], hasGlobalAuthMiddleware: false },
  ...extra,
});
const rules = (m: AppModel) => runBuiltinChecks(m).filter((f) => f.severity !== "low" && f.severity !== "info").map((f) => f.ruleId);

describe("real-world false positives stay fixed", () => {
  it("Redis connection config is not password storage", () => {
    const m = model([file("worker/config.ts", `const client = createClient();\nreturn { host: url.hostname, password: url.password || undefined };`)]);
    expect(rules(m)).not.toContain("auth/plaintext-password");
  });

  it("policies granted only to service_role are not permissive", () => {
    const tables = parseSql([file("m.sql", `create table insights (id uuid, team_id uuid);\nalter table insights enable row level security;\ncreate policy "System can insert" on insights for insert to service_role with check (true);`)]);
    expect(tables[0].policies[0].roles).toEqual(["service_role"]);
    expect(accessControlCheck(model([], { tables }))).toEqual([]);
  });

  it("log messages that mention tokens are not logged tokens", () => {
    const m = model([file("api/banking.ts", `logger.error("Failed to create Plaid link token", details(error));\nconsole.log("Successfully refreshed Gmail access token", { accountId });`)]);
    expect(rules(m)).not.toContain("data-protection/secret-in-logs");
  });

  it("still catches an actual token passed to a logger", () => {
    const m = model([file("api/x.ts", `console.log("token is", accessToken);`)]);
    expect(rules(m)).toContain("data-protection/secret-in-logs");
  });

  it("environment variable names are not hardcoded secrets", () => {
    const m = model([file("accounting/index.ts", `const KEYS = { xero: { clientSecret: "XERO_CLIENT_SECRET" } };`)]);
    expect(rules(m)).not.toContain("secrets/hardcoded-credential");
  });

  it("the word eval in comments and strings is not eval()", () => {
    const m = model([file("evals/run.ts", ` * Run: bun run eval (watch mode)\nconsole.log("Matching eval (DB read-only)");`)]);
    expect(rules(m)).not.toContain("injection/eval");
  });

  it("fake tokens in tests are ignored", () => {
    const token = "xoxb-" + "test-token";
    const m = model([file("src/__tests__/slack.test.ts", `access_token: "${token}",`)]);
    expect(rules(m)).toEqual([]);
  });

  it("JSON-LD structured data is not an XSS sink", () => {
    const m = model([file("app/page.tsx", `<script type="application/ld+json" dangerouslySetInnerHTML={{\n  __html: JSON.stringify(jsonLd),\n}} />`)]);
    expect(rules(m)).not.toContain("injection/xss-raw-html");
  });
});
