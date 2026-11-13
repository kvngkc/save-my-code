import type { AppModel, Finding } from "../types.js";
import { isCode, isTest } from "../model/files.js";
import { excerpt, finding, OWASP, scan } from "./util.js";

const HASHING = /\b(bcrypt|argon2|scrypt|pbkdf2|hashPassword|hash_password|passlib|make_password|generate_password_hash)\b/i;
const MANAGED_AUTH = ["Supabase Auth", "Clerk", "Auth0", "Auth.js"];

export function authCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const code = model.files.filter((f) => isCode(f.path) && !isTest(f.path) && !f.clientSide);

  // Plaintext password storage
  for (const f of code) {
    const m = f.content.match(/\b(insert|create|save|upsert|INSERT\s+INTO)\b[\s\S]{0,400}?\bpassword\b\s*[:,)]/);
    if (!m || HASHING.test(f.content) || /auth\.(signUp|admin\.createUser)/.test(f.content)) continue;
    const line = f.content.slice(0, m.index! + m[0].lastIndexOf("password")).split("\n").length;
    out.push(finding({
      ruleId: "auth/plaintext-password",
      title: "Password stored without hashing",
      severity: "critical",
      category: "auth",
      confidence: "medium",
      file: f.path,
      line,
      evidence: excerpt(f, line),
      description: "A password is written to the database and no password-hashing function (bcrypt, argon2, scrypt) is used in this file. A database leak would expose every user's password, and many users reuse passwords elsewhere.",
      remediation: "Hash passwords with argon2id or bcrypt before storing them, or use a managed auth provider (Supabase Auth, Clerk, Auth.js) instead of storing passwords yourself.",
      references: [OWASP.A02, OWASP.A07, "OWASP ASVS V2.4"],
    }));
  }

  for (const { file, line } of scan(model.files, /createHash\(\s*["'](md5|sha1|sha256)["']\s*\)/)) {
    if (!/password|passwd|pwd/i.test(file.content)) continue;
    out.push(finding({
      ruleId: "auth/weak-password-hash",
      title: "Fast hash function used for passwords",
      severity: "high",
      category: "auth",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "MD5/SHA hashes are designed to be fast, so leaked password hashes can be cracked in bulk with GPUs.",
      remediation: "Use argon2id, scrypt or bcrypt with a per-user salt.",
      references: [OWASP.A02, "OWASP ASVS V2.4.1"],
    }));
  }

  for (const { file, line } of scan(model.files, /\bjwt\.decode\(/)) {
    if (/jwt\.verify\(|jwtVerify\(/.test(file.content)) continue;
    out.push(finding({
      ruleId: "auth/jwt-decode-without-verify",
      title: "JWT decoded without signature verification",
      severity: "high",
      category: "auth",
      confidence: "high",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "jwt.decode() does not check the signature. Anyone can forge a token with any user ID or role.",
      remediation: "Use jwt.verify(token, secret, { algorithms: ['HS256'] }) (or jose's jwtVerify) and reject invalid tokens.",
      references: [OWASP.A07],
    }));
  }

  for (const { file, line, match } of scan(model.files, /\b(jwt\.sign|jwt\.verify)\([^)]*?,\s*["'`]([^"'`]{1,})["'`]/)) {
    out.push(finding({
      ruleId: "auth/hardcoded-jwt-secret",
      title: "JWT signing secret hardcoded in source",
      severity: "critical",
      category: "auth",
      confidence: "high",
      file: file.path,
      line,
      evidence: `${match[1]}(…, "${match[2].slice(0, 3)}…")`,
      description: "Anyone who reads the code can mint valid tokens for any user, including admins.",
      remediation: "Load a long random secret from an environment variable and rotate it.",
      references: [OWASP.A02, OWASP.A07],
    }));
  }

  for (const { file, line } of scan(model.files, /Math\.random\(\)/)) {
    const ctx = file.lines.slice(Math.max(0, line - 4), line + 3).join("\n");
    if (!/(token|otp|reset|code|secret|password|session|invite|verification)/i.test(ctx)) continue;
    out.push(finding({
      ruleId: "auth/insecure-random-token",
      title: "Security token generated with Math.random()",
      severity: "high",
      category: "auth",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Math.random() is predictable. OTPs, reset links or session tokens generated with it can be guessed.",
      remediation: "Use crypto.randomBytes / crypto.randomInt / crypto.randomUUID.",
      references: [OWASP.A02, "OWASP ASVS V2.3.1"],
    }));
  }

  // Login / OTP endpoints without rate limiting (project-wide signal)
  const hasRateLimit = model.files.some((f) => /\b(rate-?limit|ratelimit|limiter|throttle|slowDown|@upstash\/ratelimit|express-rate-limit)\b/i.test(f.content));
  const usesManagedAuth = model.stack.auth.some((a) => MANAGED_AUTH.includes(a));
  if (!hasRateLimit && !usesManagedAuth) {
    for (const r of model.routes.filter((r) => /(login|signin|sign-in|otp|verify|reset|forgot)/i.test(r.path) && r.method !== "GET")) {
      out.push(finding({
        ruleId: "auth/no-rate-limit",
        title: `No rate limiting on ${r.method} ${r.path}`,
        severity: "medium",
        category: "auth",
        confidence: "medium",
        file: r.file,
        line: r.line,
        description: "No rate limiting was found anywhere in the project. Login, OTP and reset endpoints can be brute-forced, and OTP/SMS endpoints can run up messaging bills.",
        remediation: "Add per-IP and per-account rate limits (e.g. express-rate-limit, @upstash/ratelimit) and lockout/backoff after repeated failures.",
        references: [OWASP.A07, "OWASP ASVS V2.2.1"],
      }));
    }
  }
  return out;
}

export function injectionCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  const sqlConcat = /\b(query|execute|raw|unsafe|exec)\s*\(\s*(`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^`]*\$\{[^`]*`|["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"']*["']\s*\+)/i;
  for (const { file, line } of scan(model.files, sqlConcat)) {
    out.push(finding({
      ruleId: "injection/sql-string-building",
      title: "SQL query built from string interpolation",
      severity: "high",
      category: "injection",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Values are interpolated directly into SQL. If any of them come from the request, an attacker can read or destroy the database.",
      remediation: "Use parameterised queries (`query('… WHERE id = $1', [id])`) or the ORM's query builder.",
      references: [OWASP.A03],
    }));
  }
  for (const { file, line } of scan(model.files, /\$(queryRawUnsafe|executeRawUnsafe)\(/)) {
    out.push(finding({
      ruleId: "injection/prisma-raw-unsafe",
      title: "Prisma raw unsafe query",
      severity: "high",
      category: "injection",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "$queryRawUnsafe/$executeRawUnsafe do not escape interpolated values.",
      remediation: "Use the tagged-template $queryRaw`…${value}` form, which parameterises values.",
      references: [OWASP.A03],
    }));
  }
  for (const { file, line } of scan(model.files, /\b(eval|new Function)\s*\(\s*(?!["'`])/)) {
    out.push(finding({
      ruleId: "injection/eval",
      title: "Dynamic code execution",
      severity: "high",
      category: "injection",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "eval()/new Function() on a non-literal value can execute attacker-controlled code.",
      remediation: "Remove eval. Parse data with JSON.parse or use a lookup table.",
      references: [OWASP.A03],
    }));
  }
  for (const { file, line } of scan(model.files, /\b(exec|execSync)\(\s*`[^`]*\$\{/)) {
    out.push(finding({
      ruleId: "injection/command",
      title: "Shell command built from interpolated values",
      severity: "high",
      category: "injection",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Interpolating values into a shell command allows command injection.",
      remediation: "Use execFile/spawn with an argument array and validate inputs against an allow-list.",
      references: [OWASP.A03],
    }));
  }
  for (const { file, line } of scan(model.files, /dangerouslySetInnerHTML|v-html=|\{@html\s/)) {
    if (/DOMPurify|sanitize/i.test(file.content)) continue;
    out.push(finding({
      ruleId: "injection/xss-raw-html",
      title: "Raw HTML rendered without sanitisation",
      severity: "medium",
      category: "injection",
      confidence: "low",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Rendering unsanitised HTML allows cross-site scripting if any part of it comes from users or an AI model.",
      remediation: "Sanitise with DOMPurify before rendering, or render as text.",
      references: [OWASP.A03],
    }));
  }
  return out;
}

export function configCheck(model: AppModel): Finding[] {
  const out: Finding[] = [];
  for (const { file, line } of scan(model.files, /origin\s*:\s*(["']\*["']|true)/)) {
    if (!/credentials\s*:\s*true/.test(file.content)) continue;
    out.push(finding({
      ruleId: "config/cors-wildcard-credentials",
      title: "CORS allows any origin with credentials",
      severity: "high",
      category: "config",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Any website can make authenticated requests to this API on behalf of a logged-in user and read the responses.",
      remediation: "Set an explicit allow-list of origins.",
      references: [OWASP.A05],
    }));
  }
  for (const { file, line } of scan(model.files, /\b(res\.cookie|cookies\(\)\.set|setCookie|cookie\.serialize)\s*\(/)) {
    const call = file.lines.slice(line - 1, line + 5).join(" ");
    if (/httpOnly\s*:\s*true/i.test(call)) continue;
    if (!/(session|token|auth|jwt|sid)/i.test(call)) continue;
    out.push(finding({
      ruleId: "config/insecure-session-cookie",
      title: "Session cookie set without httpOnly",
      severity: "medium",
      category: "config",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Without httpOnly, any XSS can steal the session token. Without secure/sameSite it can also leak over HTTP or be sent cross-site.",
      remediation: "Set { httpOnly: true, secure: true, sameSite: 'lax' } on session cookies.",
      references: [OWASP.A05, "OWASP ASVS V3.4"],
    }));
  }
  for (const { file, line } of scan(model.files, /\.(json|send)\(\s*\{[^}]*\b(err|error)\.(stack|message)\b/)) {
    out.push(finding({
      ruleId: "config/error-details-leaked",
      title: "Internal error details returned to the client",
      severity: "low",
      category: "config",
      confidence: "medium",
      file: file.path,
      line,
      evidence: excerpt(file, line),
      description: "Raw error messages and stack traces reveal internals (table names, file paths, query structure) to attackers.",
      remediation: "Log the full error server-side and return a generic message with a correlation ID.",
      references: [OWASP.A05],
    }));
  }
  if (!model.files.some((f) => /(^|\/)\.gitignore$/.test(f.path) && /\.env/.test(f.content)) && model.files.some((f) => /(^|\/)package\.json$/.test(f.path))) {
    out.push(finding({
      ruleId: "config/env-not-gitignored",
      title: ".env files are not in .gitignore",
      severity: "medium",
      category: "config",
      confidence: "medium",
      description: "Without a .gitignore rule, the next `git add .` can commit production secrets.",
      remediation: "Add `.env*` and `!.env.example` to .gitignore.",
      references: [OWASP.A05],
    }));
  }
  return out;
}
