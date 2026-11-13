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
  skipComments = true,
): Generator<{ file: SourceFile; line: number; match: RegExpMatchArray }> {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  const global = new RegExp(re.source, flags);
  for (const file of files) {
    if (!filter(file)) continue;
    for (const match of file.content.matchAll(global)) {
      const line = lineOf(file.content, match.index!);
      if (skipComments && /^\s*(\/\/|\*|\/\*|#)/.test(file.lines[line - 1] ?? "")) continue;
      yield { file, line, match };
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

/** Code that never runs in production: tests, fixtures, evals, one-off scripts and seeds. */
export const isDevOnly = (p: string) => isTest(p) || /(^|\/)(scripts?|evals?|seeds?|benchmarks?|examples?|docs?)\//.test(p) || /\.(eval|bench|stories)\.[jt]sx?$/.test(p);

/** Strip string literals so log messages like "token refreshed" don't count as logging a token. */
export const stripStrings = (s: string) => s.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '""');
