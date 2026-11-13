import { createHash } from "node:crypto";
import type { AppModel, Finding, SourceFile } from "../types.js";
import { excerpt, isCode, isTest, lineOf } from "../model/files.js";

export type Check = (model: AppModel) => Finding[];

export function finding(f: Omit<Finding, "id" | "source"> & { source?: Finding["source"] }): Finding {
  const id = createHash("sha1").update(`${f.ruleId}|${f.file ?? ""}|${f.line ?? ""}|${f.evidence ?? ""}`).digest("hex").slice(0, 12);
  return { source: "builtin", ...f, id };
}

/** Run a regex over every matching file and yield file/line/match. */
export function* scan(
  files: SourceFile[],
  re: RegExp,
  filter: (f: SourceFile) => boolean = (f) => isCode(f.path) && !isTest(f.path),
): Generator<{ file: SourceFile; line: number; match: RegExpMatchArray }> {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  const global = new RegExp(re.source, flags);
  for (const file of files) {
    if (!filter(file)) continue;
    for (const match of file.content.matchAll(global)) {
      yield { file, line: lineOf(file.content, match.index!), match };
    }
  }
}

export { excerpt };

export function mask(secret: string): string {
  if (secret.length <= 8) return "****";
  return secret.slice(0, 4) + "…" + "*".repeat(6) + secret.slice(-2);
}

export const OWASP = {
  A01: "OWASP Top 10 A01: Broken Access Control",
  A02: "OWASP Top 10 A02: Cryptographic Failures",
  A03: "OWASP Top 10 A03: Injection",
  A05: "OWASP Top 10 A05: Security Misconfiguration",
  A06: "OWASP Top 10 A06: Vulnerable and Outdated Components",
  A07: "OWASP Top 10 A07: Identification and Authentication Failures",
  A09: "OWASP Top 10 A09: Security Logging and Monitoring Failures",
  ASVS: "OWASP ASVS 4.0",
};
