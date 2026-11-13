import type { ScanResult, Severity } from "../types.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SCORE: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };

/** SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers. */
export function renderSarif(r: ScanResult): string {
  const rules = new Map<string, any>();
  for (const f of r.findings) {
    if (rules.has(f.ruleId)) continue;
    rules.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId.replace(/[^\w]+/g, "_"),
      shortDescription: { text: f.title.slice(0, 200) },
      help: { text: f.remediation },
      properties: { tags: ["security", f.category], "security-severity": SCORE[f.severity] },
    });
  }
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "save-my-code", version: r.tool.version, informationUri: "https://github.com/kvngkc/save-my-code", rules: [...rules.values()] } },
        results: r.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `${f.title}. ${f.description} Fix: ${f.remediation}` },
          partialFingerprints: { saveMyCode: f.id },
          locations: f.file
            ? [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, f.line ?? 1) } } }]
            : [],
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
