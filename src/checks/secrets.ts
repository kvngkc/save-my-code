import type { AppModel, Finding } from "../types.js";
import { finding, mask, OWASP, scan } from "./util.js";

interface SecretPattern {
  id: string;
  name: string;
  re: RegExp;
  severity: Finding["severity"];
}

// Patterns are assembled from parts so this file never contains a literal that
// looks like a real credential to secret-scanning push protection.
const PATTERNS: SecretPattern[] = [
  { id: "aws-access-key", name: "AWS access key ID", re: new RegExp("\\b(AKIA|ASIA)[0-9A-Z]{16}\\b"), severity: "critical" },
  { id: "live-payment-secret", name: "Live payment secret key (Stripe/Paystack style)", re: new RegExp("\\b(sk|rk)_live_[0-9a-zA-Z]{20,}\\b"), severity: "critical" },
  { id: "flutterwave-secret", name: "Flutterwave secret key", re: new RegExp("FLWSECK" + "(_TEST)?-[0-9a-zA-Z]{20,}-X"), severity: "critical" },
  { id: "anthropic-key", name: "Anthropic API key", re: new RegExp("\\bsk-ant-[A-Za-z0-9_-]{20,}"), severity: "critical" },
  { id: "openai-key", name: "OpenAI API key", re: new RegExp("\\bsk-(proj-)?[A-Za-z0-9_-]{32,}"), severity: "critical" },
  { id: "github-token", name: "GitHub token", re: new RegExp("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"), severity: "critical" },
  { id: "google-api-key", name: "Google API key", re: new RegExp("\\bAIza[0-9A-Za-z_-]{35}\\b"), severity: "high" },
  { id: "private-key", name: "Private key", re: new RegExp("-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), severity: "critical" },
  { id: "slack-token", name: "Slack token", re: new RegExp("\\bxox[baprs]-[0-9A-Za-z-]{10,}"), severity: "high" },
];

const PLACEHOLDER = /(your[_-]|example|xxxx|changeme|placeholder|dummy|<|\.\.\.|\$\{|process\.env|import\.meta\.env|os\.environ)/i;
const GENERIC = /\b(password|passwd|secret|api_?key|auth_?token|access_?token|jwt_?secret|private_?key|client_?secret)\b\s*[:=]\s*["']([^"'\s]{8,})["']/i;
const ENV_ASSIGN = /^\s*([A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY|PRIVATE)[A-Z0-9_]*)\s*=\s*["']?([^"'\s#]{8,})/;

export function secretsCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const all = () => true;

  for (const p of PATTERNS) {
    for (const { file, line, match } of scan(model.files, p.re, all)) {
      if (/EXAMPLE/.test(match[0])) continue;
      out.push(finding({
        ruleId: `secrets/${p.id}`,
        title: `${p.name} committed to the repository`,
        severity: file.path.includes(".example") ? "low" : p.severity,
        category: "secrets",
        confidence: "high",
        file: file.path,
        line,
        evidence: mask(match[0]),
        description: `A value matching the format of a ${p.name} is present in source. Anyone with read access to the repository (or its history) can use it.`,
        remediation: "Revoke and rotate the credential now, remove it from git history (e.g. git filter-repo), and load it from an environment variable or secret manager.",
        references: [OWASP.A02],
      }));
    }
  }

  // Supabase service-role JWTs: decode and check the role claim.
  for (const { file, line, match } of scan(model.files, /eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/, all)) {
    try {
      const payload = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
      if (payload.role === "service_role") {
        out.push(finding({
          ruleId: "secrets/supabase-service-role-jwt",
          title: "Supabase service_role key committed to the repository",
          severity: "critical",
          category: "secrets",
          confidence: "high",
          file: file.path,
          line,
          evidence: mask(match[0]),
          description: "The service_role key bypasses all Row Level Security. Whoever holds it can read, change and delete every row in the database.",
          remediation: "Rotate the service_role key in the Supabase dashboard immediately, purge it from git history, and only use it in server-side code via an environment variable.",
          references: [OWASP.A01, OWASP.A02],
        }));
      }
    } catch { /* not a JWT */ }
  }

  // Committed .env files
  for (const f of model.files) {
    if (!/(^|\/)\.env(\.[\w-]+)?$/.test(f.path) || /\.(example|sample|template)$/.test(f.path)) continue;
    f.lines.forEach((text, i) => {
      const m = text.match(ENV_ASSIGN);
      if (m && !PLACEHOLDER.test(m[3])) {
        out.push(finding({
          ruleId: "secrets/committed-env-file",
          title: `Secret ${m[1]} in committed ${f.path}`,
          severity: "high",
          category: "secrets",
          confidence: "medium",
          file: f.path,
          line: i + 1,
          evidence: `${m[1]}=${mask(m[3])}`,
          description: "Environment files hold production credentials and should never be committed.",
          remediation: "Add .env* (except .env.example) to .gitignore, rotate the values, and remove the file from git history.",
          references: [OWASP.A05],
        }));
      }
    });
  }

  // Generic hardcoded credentials in code
  for (const { file, line, match } of scan(model.files, GENERIC)) {
    if (PLACEHOLDER.test(match[2])) continue;
    out.push(finding({
      ruleId: "secrets/hardcoded-credential",
      title: `Hardcoded ${match[1]} in source`,
      severity: "high",
      category: "secrets",
      confidence: "medium",
      file: file.path,
      line,
      evidence: `${match[1]} = "${mask(match[2])}"`,
      description: "A credential-like value is hardcoded in source code.",
      remediation: "Move the value to an environment variable or secret manager and rotate it.",
      references: [OWASP.A02],
    }));
  }

  // Secrets exposed to the browser through public env prefixes
  for (const { file, line, match } of scan(model.files, /\b(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)(\w*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)\w*)/, all)) {
    out.push(finding({
      ruleId: "secrets/secret-in-public-env",
      title: `Secret exposed to the browser via ${match[1]}${match[2]}`,
      severity: "critical",
      category: "secrets",
      confidence: "high",
      file: file.path,
      line,
      evidence: match[0],
      description: `Variables prefixed with ${match[1]} are bundled into client JavaScript and visible to every visitor.`,
      remediation: "Rename the variable without the public prefix, use it only in server code, and rotate the value because it has already shipped to browsers.",
      references: [OWASP.A02, OWASP.A05],
    }));
  }

  return dedupe(out);
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
