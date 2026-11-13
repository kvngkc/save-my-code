import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { scan } from "../src/scan.js";

const VULN = join(__dirname, "..", "examples", "naija-clinic-bookings");
const SAFE = join(__dirname, "fixtures", "safe-app");

describe("vulnerable demo app", async () => {
  const r = await scan(VULN, { external: false });
  const rules = new Set(r.findings.map((f) => f.ruleId));

  it.each([
    "access-control/idor",
    "access-control/supabase-rls-disabled",
    "access-control/supabase-policy-permissive",
    "access-control/service-role-in-client",
    "access-control/client-controlled-role",
    "access-control/admin-without-role-check",
    "auth/plaintext-password",
    "auth/hardcoded-jwt-secret",
    "auth/jwt-decode-without-verify",
    "auth/insecure-random-token",
    "injection/sql-string-building",
    "secrets/secret-in-public-env",
    "secrets/committed-env-file",
    "data-protection/secret-in-logs",
    "data-protection/pii-to-ai-provider",
    "data-protection/sensitive-identifier-stored",
  ])("detects %s", (rule) => {
    expect(rules.has(rule)).toBe(true);
  });

  it("flags both the GET and DELETE IDOR on appointments", () => {
    const idor = r.findings.filter((f) => f.ruleId === "access-control/idor");
    expect(idor.map((f) => f.title)).toEqual(
      expect.arrayContaining([expect.stringContaining("GET /api/appointments/[id]"), expect.stringContaining("DELETE /api/appointments/[id]")]),
    );
    expect(idor.every((f) => f.severity === "critical")).toBe(true);
  });

  it("treats the public clinic directory as informational, not critical", () => {
    const clinics = r.findings.filter((f) => f.title.includes('"clinics"'));
    expect(clinics.every((f) => f.severity === "info")).toBe(true);
  });

  it("blocks the release", () => {
    expect(r.decision.verdict).toBe("block");
  });

  it("maps findings to failing NDPA requirements", () => {
    const failed = r.compliance.filter((c) => c.status === "fail").map((c) => c.requirement.id);
    expect(failed).toEqual(expect.arrayContaining(["NDPA-03", "NDPA-06", "NDPA-08", "NDPA-09", "NDPA-12"]));
    expect(r.compliance.some((c) => c.pack === "gdpr")).toBe(false); // profile is NG only
  });

  it("never prints raw secrets in evidence", () => {
    const ev = r.findings.map((f) => f.evidence ?? "").join("\n");
    expect(ev).not.toContain("Clinic2024Lagos!");
    expect(ev).not.toContain("demo-service-role-not-a-real-key-123456");
  });
});

describe("secure fixture app", async () => {
  const r = await scan(SAFE, { external: false, profilePath: join(SAFE, ".save-my-code-profile.yml") });

  it("has no findings at medium severity or above", () => {
    expect(r.findings.filter((f) => ["critical", "high", "medium"].includes(f.severity))).toEqual([]);
  });

  it("passes the release gate", () => {
    expect(r.decision.verdict).toBe("pass");
  });

  it("detects owner-scoped routes, RLS and the privacy notice", () => {
    expect(r.model.tables.every((t) => t.rlsEnabled)).toBe(true);
    const status = Object.fromEntries(r.compliance.filter((c) => c.pack === "ndpa-2023").map((c) => [c.requirement.id, c.status]));
    expect(status["NDPA-03"]).not.toBe("fail");
    expect(status["NDPA-06"]).toBe("pass");
    expect(status["NDPA-08"]).not.toBe("fail");
    expect(status["NDPA-09"]).toBe("not-applicable");
  });

  it("applies both NDPA and GDPR when the profile lists NG and EU", () => {
    expect(new Set(r.compliance.map((c) => c.pack))).toEqual(new Set(["ndpa-2023", "gdpr"]));
  });
});
