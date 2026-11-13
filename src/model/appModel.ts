import type { AppModel, PersonalDataField, PersonalDataKind, Route, SourceFile, SqlTable, Stack } from "../types.js";
import { extractBlock, isCode, isTest, lineOf, loadFiles } from "./files.js";
import { parseSql } from "./sql.js";

export function buildAppModel(root: string): AppModel {
  const files = loadFiles(root);
  const stack = detectStack(files);
  const routes = files.filter((f) => isCode(f.path) && !isTest(f.path)).flatMap(extractRoutes);
  const tables: SqlTable[] = parseSql(files.filter((f) => f.path.endsWith(".sql")));
  const personalData = detectPersonalData(files);
  return { root, files, stack, routes, tables, personalData };
}

// ---------------------------------------------------------------- stack

const DEP_MAP: Array<[RegExp, keyof Omit<Stack, "languages" | "hasGlobalAuthMiddleware">, string]> = [
  [/^next$/, "frameworks", "Next.js"],
  [/^react$/, "frameworks", "React"],
  [/^vue$/, "frameworks", "Vue"],
  [/^nuxt$/, "frameworks", "Nuxt"],
  [/^@sveltejs\/kit$/, "frameworks", "SvelteKit"],
  [/^express$/, "frameworks", "Express"],
  [/^fastify$/, "frameworks", "Fastify"],
  [/^hono$/, "frameworks", "Hono"],
  [/^@nestjs\/core$/, "frameworks", "NestJS"],
  [/^@supabase\/supabase-js$/, "databases", "Supabase"],
  [/^@prisma\/client$|^prisma$/, "databases", "Prisma"],
  [/^drizzle-orm$/, "databases", "Drizzle"],
  [/^mongoose$|^mongodb$/, "databases", "MongoDB"],
  [/^pg$|^postgres$/, "databases", "PostgreSQL"],
  [/^mysql2?$/, "databases", "MySQL"],
  [/^firebase$|^firebase-admin$/, "databases", "Firebase"],
  [/^next-auth$|^@auth\/core$/, "auth", "Auth.js"],
  [/^@clerk\//, "auth", "Clerk"],
  [/^@supabase\/(auth-helpers|ssr)/, "auth", "Supabase Auth"],
  [/^@auth0\//, "auth", "Auth0"],
  [/^lucia$/, "auth", "Lucia"],
  [/^passport$/, "auth", "Passport"],
  [/^jsonwebtoken$|^jose$/, "auth", "JWT"],
  [/^bcrypt(js)?$|^argon2$/, "auth", "Password hashing library"],
  [/^openai$/, "aiProviders", "OpenAI"],
  [/^@anthropic-ai\/sdk$/, "aiProviders", "Anthropic"],
  [/^@google\/(generative-ai|genai)$/, "aiProviders", "Google Gemini"],
  [/^ai$|^@ai-sdk\//, "aiProviders", "Vercel AI SDK"],
  [/^groq-sdk$/, "aiProviders", "Groq"],
  [/^@mistralai\//, "aiProviders", "Mistral"],
  [/^cohere-ai$/, "aiProviders", "Cohere"],
  [/^stripe$|^@stripe\//, "payments", "Stripe"],
  [/paystack/i, "payments", "Paystack"],
  [/flutterwave/i, "payments", "Flutterwave"],
  [/^@paypal\//, "payments", "PayPal"],
];

export function detectStack(files: SourceFile[]): Stack {
  const stack: Stack = { languages: [], frameworks: [], databases: [], auth: [], aiProviders: [], payments: [], hasGlobalAuthMiddleware: false };
  const add = (k: keyof Stack, v: string) => {
    const arr = stack[k] as string[];
    if (!arr.includes(v)) arr.push(v);
  };
  for (const f of files.filter((f) => /(^|\/)package\.json$/.test(f.path))) {
    try {
      const pkg = JSON.parse(f.content);
      const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      for (const d of deps) for (const [re, key, label] of DEP_MAP) if (re.test(d)) add(key, label);
    } catch { /* ignore malformed package.json */ }
  }
  for (const f of files) {
    if (/\.tsx?$/.test(f.path)) add("languages", "TypeScript");
    else if (/\.(jsx?|mjs|cjs)$/.test(f.path)) add("languages", "JavaScript");
    else if (/\.py$/.test(f.path)) add("languages", "Python");
    else if (/\.sql$/.test(f.path)) add("languages", "SQL");
    if (!isCode(f.path)) continue;
    // imports catch deps declared in nested/monorepo package.json files we did not see
    const imports = [...f.content.matchAll(/(?:from\s+|require\(\s*)["']([^"']+)["']/g)].map((m) => m[1]);
    for (const imp of imports) for (const [re, key, label] of DEP_MAP) if (re.test(imp)) add(key, label);
    if (/api\.openai\.com/.test(f.content)) add("aiProviders", "OpenAI");
    if (/api\.anthropic\.com/.test(f.content)) add("aiProviders", "Anthropic");
    if (/api\.paystack\.co/.test(f.content)) add("payments", "Paystack");
    if (/api\.flutterwave\.com/.test(f.content)) add("payments", "Flutterwave");
  }
  if (stack.databases.includes("Supabase") && files.some((f) => /supabase\.auth\./.test(f.content))) add("auth", "Supabase Auth");
  const mw = files.find((f) => /(^|\/)(src\/)?middleware\.(t|j)s$/.test(f.path));
  if (mw && /(auth|session|getToken|clerkMiddleware|withAuth|getUser)/i.test(mw.content)) stack.hasGlobalAuthMiddleware = true;
  return stack;
}

// ---------------------------------------------------------------- routes

const AUTH_PATTERNS = /\b(getServerSession|getSession|auth\(\)|getAuth|currentUser|requireAuth|requireUser|isAuthenticated|ensureAuth|authenticate|verifyToken|jwt\.verify|jwtVerify|supabase\.auth\.getUser|auth\.getUser|getUser\(|req\.user|request\.user|ctx\.user|locals\.user|validateRequest|withAuth|protect)\b/;
const ID_PARAM = /\b(params\.(\w*id)|params\s*\)?\s*\.\s*\w*id|req\.params\.\w*id|req\.query\.\w*id|searchParams\.get\(\s*["']\w*id["']\)|body\.\w*[iI]d\b|\{\s*\w*[iI]d\s*\}\s*=\s*(await\s+)?(params|req\.params|req\.query|body))/i;
const DB_ACCESS = /\.(from|findUnique|findFirst|findMany|findById|findOne|update|updateMany|delete|deleteMany|deleteOne|upsert|insert|select|eq)\(|\b(query|execute)\(\s*[`"']|prisma\.|db\.|knex|sql`/;
const CURRENT_USER = /\b(session\??\.user\??\.id|user\??\.id|req\.user\??\.\w*id|currentUser\??\.id|userId\s*:\s*(session|user|auth)|auth\.uid\(\)|auth\(\)\??\.userId|locals\.user\??\.id|owner_?id|\.eq\(\s*["']user_id["']\s*,\s*(user|session))/i;
const MUTATION_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function extractRoutes(file: SourceFile): Route[] {
  const routes: Route[] = [];
  const p = file.path;
  const nextApp = p.match(/(?:^|\/)app\/(.*?)\/?route\.(t|j)sx?$/);
  const nextPages = p.match(/(?:^|\/)pages\/(api\/.*)\.(t|j)sx?$/);

  if (nextApp) {
    const urlPath = "/" + nextApp[1].replace(/\([^)]*\)\/?/g, "").replace(/\/$/, "");
    for (const m of file.content.matchAll(/export\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE)\b/g)) {
      routes.push(makeRoute(file, "next-app", m[1], urlPath, m.index!));
    }
  } else if (nextPages) {
    const urlPath = "/" + nextPages[1].replace(/\/index$/, "");
    const m = file.content.match(/export\s+default\s+(async\s+)?function|export\s+default\s+\w+/);
    if (m) {
      const methods = [...new Set([...file.content.matchAll(/method\s*===?\s*["'](GET|POST|PUT|PATCH|DELETE)["']/g)].map((x) => x[1]))];
      for (const method of methods.length ? methods : ["ANY"]) routes.push(makeRoute(file, "next-pages", method, urlPath, m.index!));
    }
  }
  for (const m of file.content.matchAll(/\b(app|router|api|server)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]/g)) {
    routes.push(makeRoute(file, "express", m[2].toUpperCase(), m[3], m.index!));
  }
  return routes;
}

function makeRoute(file: SourceFile, kind: Route["kind"], method: string, path: string, index: number): Route {
  let handler: string;
  if (kind === "express") {
    // route call: app.get('/x', mw, (req,res) => {...}) - take until the matching close paren
    handler = extractCall(file.content, index);
  } else {
    // Skip the parameter list first: destructured params like ({ params }) contain braces.
    const open = file.content.indexOf("(", index);
    const brace = file.content.indexOf("{", index);
    const start = open !== -1 && (brace === -1 || open < brace) ? index + extractCall(file.content, index).length : index;
    handler = file.content.slice(index, start) + extractBlock(file.content, start).slice(0);
  }
  // For Next.js handlers, shared helpers in the same file (e.g. requireUser) count as auth when called.
  const hasAuthCheck = AUTH_PATTERNS.test(handler);
  return {
    kind,
    method,
    path,
    file: file.path,
    line: lineOf(file.content, index),
    handler,
    hasAuthCheck,
    usesIdParam: ID_PARAM.test(handler) || (/\[\w*id\]|:\w*id/i.test(path) && /params/.test(handler)),
    touchesDatabase: DB_ACCESS.test(handler),
    referencesCurrentUser: CURRENT_USER.test(handler),
    mutates: MUTATION_METHODS.has(method) || /\.(insert|update|upsert|delete|create)\(/.test(handler),
  };
}

function extractCall(content: string, index: number, maxLen = 8000): string {
  const open = content.indexOf("(", index);
  let depth = 0;
  let inStr: string | null = null;
  for (let i = open; i < content.length && i - open < maxLen; i++) {
    const c = content[i];
    if (inStr) {
      if (c === "\\") { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { inStr = c; continue; }
    if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth === 0) return content.slice(index, i + 1);
    }
  }
  return content.slice(index, open + maxLen);
}

// ---------------------------------------------------------------- personal data

const PII_FIELDS: Array<[RegExp, PersonalDataKind]> = [
  [/^(e_?mail|email_?address)$/i, "contact"],
  [/^(phone|phone_?number|mobile|msisdn|whatsapp)$/i, "contact"],
  [/^(full_?name|first_?name|last_?name|surname|display_?name)$/i, "identity"],
  [/^(dob|date_?of_?birth|birth_?date|birthday|age)$/i, "identity"],
  [/^(address|home_?address|street|postcode|zip_?code|state_?of_?origin)$/i, "location"],
  [/^(lat|latitude|lng|longitude|geo_?location|location)$/i, "location"],
  [/^(nin|bvn|ssn|national_?id|passport_?(no|number)|tax_?id|tin|voters?_?card|drivers?_?licen[cs]e)$/i, "government-id"],
  [/^(card_?number|pan|cvv|iban|account_?number|bank_?account|sort_?code)$/i, "financial"],
  [/^(diagnosis|medical_?\w*|health_?\w*|condition|symptoms?|prescription|allergies|blood_?group|genotype|hiv_?status)$/i, "health"],
  [/^(password|password_?hash|pin|otp|secret)$/i, "credentials"],
  [/^(fingerprint|face_?id|biometric\w*)$/i, "biometric"],
  [/^(guardian\w*|parent_?\w*|child_?\w*|school)$/i, "children"],
];

export function classifyField(name: string): PersonalDataKind | null {
  for (const [re, kind] of PII_FIELDS) if (re.test(name)) return kind;
  return null;
}

function detectPersonalData(files: SourceFile[]): PersonalDataField[] {
  const out: PersonalDataField[] = [];
  const seen = new Set<string>();
  const push = (field: string, file: string, line: number) => {
    const kind = classifyField(field);
    if (!kind) return;
    const key = `${field.toLowerCase()}|${file}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ field, kind, file, line });
  };
  for (const f of files) {
    if (f.path.endsWith(".sql")) {
      for (const m of f.content.matchAll(/^\s*["`]?(\w+)["`]?\s+(text|varchar|char|int|integer|bigint|date|timestamp\w*|uuid|boolean|jsonb?|numeric|decimal)/gim)) push(m[1], f.path, lineOf(f.content, m.index!));
    } else if (f.path.endsWith(".prisma")) {
      for (const m of f.content.matchAll(/^\s*(\w+)\s+(String|Int|DateTime|Json|Boolean|Decimal)/gm)) push(m[1], f.path, lineOf(f.content, m.index!));
    } else if (isCode(f.path) && !isTest(f.path)) {
      // form inputs and schema definitions
      for (const m of f.content.matchAll(/name=["'](\w+)["']/g)) push(m[1], f.path, lineOf(f.content, m.index!));
      for (const m of f.content.matchAll(/\b(\w+)\s*:\s*z\./g)) push(m[1], f.path, lineOf(f.content, m.index!));
    }
  }
  return out;
}
