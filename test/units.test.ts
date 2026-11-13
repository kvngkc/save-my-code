import { describe, expect, it } from "vitest";
import { locateEvidence } from "../src/ai/review.js";
import { secretsCheck } from "../src/checks/secrets.js";
import { extractRoutes } from "../src/model/appModel.js";
import { parseSql } from "../src/model/sql.js";
import { renderSarif } from "../src/report/sarif.js";
import type { AppModel, ScanResult, SourceFile } from "../src/types.js";

const file = (path: string, content: string, clientSide = false): SourceFile => ({ path, content, lines: content.split("\n"), clientSide });
const model = (files: SourceFile[]): AppModel => ({
  root: "/x", files, routes: [], tables: [], personalData: [],
  stack: { languages: [], frameworks: [], databases: [], auth: [], aiProviders: [], payments: [], hasGlobalAuthMiddleware: false },
});

describe("secret detection", () => {
  // Built by concatenation so this repository never contains a contiguous credential-shaped string.
  const awsKey = "AKIA" + "Q3EGRZ7XN2LPVK4D";
  const liveKey = "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
  const jwtPayload = Buffer.from(JSON.stringify({ role: "service_role", iss: "supabase" })).toString("base64url");
  const serviceJwt = "eyJhbGciOiJIUzI1NiJ9." + jwtPayload + ".c2lnbmF0dXJlc2lnbmF0dXJl";

  it("finds provider keys and masks them", () => {
    const fs = secretsCheck(model([file("src/pay.ts", `const k = "${liveKey}";\nconst a = "${awsKey}";`)]));
    expect(fs.map((f) => f.ruleId)).toEqual(expect.arrayContaining(["secrets/live-payment-secret", "secrets/aws-access-key"]));
    for (const f of fs) expect(f.evidence).not.toContain(liveKey);
  });

  it("decodes Supabase JWTs and flags service_role", () => {
    const fs = secretsCheck(model([file("src/client.ts", `createClient(url, "${serviceJwt}")`)]));
    expect(fs.some((f) => f.ruleId === "secrets/supabase-service-role-jwt")).toBe(true);
  });

  it("ignores placeholders and env lookups", () => {
    const fs = secretsCheck(model([file("src/a.ts", `const password = process.env.DB_PASSWORD;\nconst apiKey = "your-api-key-here";`)]));
    expect(fs).toEqual([]);
  });
});

describe("SQL parser", () => {
  it("tracks RLS and policies across migrations, including drops", () => {
    const tables = parseSql([
      file("m/001.sql", `create table if not exists public."orders" (id uuid primary key, user_id uuid, total numeric);\nalter table orders enable row level security;\ncreate policy "open" on orders for select using (true);`),
      file("m/002.sql", `-- tighten\ndrop policy "open" on public.orders;\ncreate policy "own" on orders for select using ( auth.uid() = user_id );`),
    ]);
    expect(tables).toHaveLength(1);
    expect(tables[0].rlsEnabled).toBe(true);
    expect(tables[0].columns).toEqual(["id", "user_id", "total"]);
    expect(tables[0].policies.map((p) => [p.name, p.using])).toEqual([["own", "auth.uid() = user_id"]]);
  });
});

describe("route extraction", () => {
  it("handles Express routes with middleware", () => {
    const routes = extractRoutes(file("server.js", `router.delete("/posts/:id", async (req, res) => {\n  await db.query("DELETE FROM posts WHERE id = $1", [req.params.id]);\n});`));
    expect(routes).toHaveLength(1);
    expect(routes[0]).toMatchObject({ method: "DELETE", path: "/posts/:id", usesIdParam: true, touchesDatabase: true, hasAuthCheck: false, mutates: true });
  });

  it("strips Next.js route groups from paths", () => {
    const routes = extractRoutes(file("app/(dashboard)/api/me/route.ts", `export const GET = async () => { return Response.json({}) }`));
    expect(routes[0].path).toBe("/api/me");
  });
});

describe("AI evidence verification", () => {
  const lines = ["a", "b", "  const x = await db.query(`SELECT * FROM t WHERE id=${id}`)", "d"];
  it("accepts evidence near the claimed line and corrects the line number", () => {
    expect(locateEvidence(lines, "const x = await db.query(`SELECT * FROM t WHERE id=${id}`)", 5)).toBe(3);
  });
  it("rejects fabricated evidence", () => {
    expect(locateEvidence(lines, "eval(userInput)", 3)).toBeNull();
  });
});

describe("SARIF", () => {
  it("emits valid 2.1.0 structure with security-severity", () => {
    const r = {
      tool: { name: "save-my-code", version: "0.0.0" },
      findings: [{ id: "abc", ruleId: "x/y", title: "T", severity: "high", category: "auth", confidence: "high", source: "builtin", file: "a.ts", line: 3, description: "d", remediation: "r" }],
    } as unknown as ScanResult;
    const s = JSON.parse(renderSarif(r));
    expect(s.version).toBe("2.1.0");
    expect(s.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(3);
    expect(s.runs[0].tool.driver.rules[0].properties["security-severity"]).toBe("8.0");
  });
});
