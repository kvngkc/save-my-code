import type { AppModel, Finding } from "../types.js";
import { isCode, isTest } from "../model/files.js";
import { excerpt, finding, OWASP, scan } from "./util.js";

const PII_WORDS = /\b(email|phone|full_?name|first_?name|last_?name|address|dob|date_?of_?birth|nin|bvn|diagnosis|symptoms|medical|health|patient|salary|card)\w*/i;
const AI_IMPORT = /(from\s+["'](openai|@anthropic-ai\/sdk|@google\/generative-ai|@google\/genai|ai|@ai-sdk\/[\w-]+|groq-sdk|@mistralai\/[\w-]+|cohere-ai)["']|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com)/;

export function dataProtectionCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const code = model.files.filter((f) => isCode(f.path) && !isTest(f.path));

  // Personal data sent to third-party AI providers
  for (const f of code) {
    const imp = f.content.match(AI_IMPORT);
    if (!imp) continue;
    const pii = f.content.match(PII_WORDS);
    if (!pii) continue;
    const line = f.content.slice(0, pii.index!).split("\n").length;
    out.push(finding({
      ruleId: "data-protection/pii-to-ai-provider",
      title: "Personal data appears to be sent to an external AI provider",
      severity: "medium",
      category: "data-protection",
      confidence: "low",
      file: f.path,
      line,
      evidence: excerpt(f, line),
      description: `This file calls an AI provider (${imp[2] ?? imp[1]}) and handles personal data fields (e.g. "${pii[0]}"). Sending personal data to a third party usually requires a lawful basis, a processor agreement, disclosure in your privacy notice and, when the provider is abroad, a cross-border transfer assessment.`,
      remediation: "Minimise or pseudonymise personal data before sending it, check the provider's data retention/training settings, sign a data processing agreement, and disclose the transfer in your privacy notice.",
      references: ["NDPA 2023 (cross-border transfer provisions)", "GDPR Art. 28, 44-49"],
    }));
  }

  // Personal or secret data in logs
  for (const { file, line, match } of scan(model.files, /\b(console\.(log|info|debug|warn|error)|logger\.\w+|print)\s*\(([^)]*)\)/)) {
    const args = match[3];
    const secret = /\b(password|passwd|token|secret|otp|pin|card_?number|cvv)\b/i.test(args);
    const pii = PII_WORDS.test(args) || /\b(req\.body|body|user|patient|customer)\b\s*[,)]/.test(args + ")");
    if (!secret && !pii) continue;
    out.push(finding({
      ruleId: secret ? "data-protection/secret-in-logs" : "data-protection/pii-in-logs",
      title: secret ? "Credentials written to logs" : "Personal data written to logs",
      severity: secret ? "high" : "low",
      category: "data-protection",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: secret
        ? "Passwords, tokens or OTPs in logs are readable by anyone with access to the hosting dashboard or log provider, and logs are rarely protected like the database."
        : "Logs are copied to third-party providers and retained for long periods. Personal data in logs widens the impact of a breach and complicates deletion requests.",
      remediation: "Remove the field from the log call or redact it with a logging helper.",
      references: [OWASP.A09],
    }));
  }

  // Government ID / financial identifiers stored in plaintext columns
  for (const t of model.tables) {
    const sensitive = t.columns.filter((c) => /^(nin|bvn|ssn|national_?id|card_?number|pan|cvv|passport_?(no|number))$/i.test(c));
    if (sensitive.length === 0) continue;
    out.push(finding({
      ruleId: "data-protection/sensitive-identifier-stored",
      title: `Table "${t.name}" stores ${sensitive.join(", ")}`,
      severity: sensitive.some((c) => /cvv|card_?number|pan/i.test(c)) ? "critical" : "medium",
      category: "data-protection",
      confidence: "high",
      file: t.file,
      line: t.line,
      evidence: `columns: ${sensitive.join(", ")}`,
      description: sensitive.some((c) => /cvv|card_?number|pan/i.test(c))
        ? "Storing card numbers or CVVs puts you in scope for PCI DSS, and storing CVVs after authorisation is prohibited outright."
        : "Government identifiers (NIN, BVN, SSN, passport numbers) enable identity fraud if leaked. Keep them only if you have a clear legal need, and protect them more strongly than ordinary data.",
      remediation: "Don't store card data: use your payment provider's tokens. For government IDs, store only what is necessary (e.g. verification status or last 4 digits), encrypt at rest at the column level, and restrict access.",
      references: ["PCI DSS 4.0 Req. 3", "NDPA 2023 (security and minimisation)"],
    }));
  }
  return out;
}
