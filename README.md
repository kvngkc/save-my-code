# Save-My-Code

**Build with AI. Ship with confidence.**

An independent assurance layer for AI-generated software. Save-My-Code finds the access-control
holes, leaked secrets, auth flaws and data-protection gaps your coding agent missed, maps them to
the legal requirements that apply where you operate (starting with Nigeria's NDPA 2023 and the EU
GDPR), and gives you a pass / warn / block release decision backed by evidence.

> Status: early MVP (v0.1). Use it as a second pair of eyes, not a certificate. See [Limitations](#limitations).

## Why

AI app builders make it easy to ship a working app in an afternoon. They don't make the
consequences of a broken app go away. The most common serious flaw in vibe-coded apps isn't an
exotic exploit. It's **one user being able to see another user's data**: a Supabase table with Row
Level Security off, an API route that loads `/appointments/:id` without checking who owns it, a
service-role key in browser code. Conventional scanners mostly miss these, because they are logic
problems, not known-bad patterns.

## Quick start

```bash
git clone https://github.com/kvngkc/save-my-code && cd save-my-code
npm install && npm run build

# Try it on the deliberately vulnerable demo app
node dist/cli.js scan examples/naija-clinic-bookings

# Your project
node dist/cli.js init ../my-app      # answer a few questions about jurisdiction and data
node dist/cli.js scan ../my-app      # writes .save-my-code/reports/report.{md,json,html}
```

Sample output on the demo app:

```
8 critical  8 high  3 medium  2 low

  CRITICAL GET /api/appointments/[id] loads records by a client-supplied ID without checking ownership
  CRITICAL Table "profiles" has Row Level Security disabled
  CRITICAL Supabase service-role key used in client-side code
  CRITICAL Password stored without hashing
  ...
Compliance (ndpa-2023): 0 pass  5 fail  5 need evidence  3 manual review
  ✗ NDPA-03 Privacy notice provided to data subjects
  ✗ NDPA-06 Appropriate technical and organisational security measures
  ✗ NDPA-12 Cross-border transfers of personal data
  ...
Release decision: BLOCK
```

## What it checks

| Layer | What | How |
|---|---|---|
| **App model** | Stack, routes, auth checks, DB tables and RLS policies, personal-data fields, AI/payment providers | Static analysis of JS/TS, SQL migrations, Prisma schemas |
| **Access control** | IDOR on ID-based routes, Supabase RLS disabled or `using (true)`, "any logged-in user" policies, service-role key in browser code, admin routes without role checks, roles taken from the request body | Built-in |
| **Secrets** | Provider keys (AWS, Stripe/Paystack live keys, Flutterwave, OpenAI, Anthropic, GitHub...), Supabase service-role JWTs (decoded), committed `.env` files, secrets in `NEXT_PUBLIC_`/`VITE_` variables | Built-in (+ gitleaks for history) |
| **Auth** | Plaintext or MD5/SHA password storage, `jwt.decode` without verify, hardcoded JWT secrets, `Math.random()` tokens/OTPs, no rate limiting on login/OTP | Built-in |
| **Injection & config** | SQL string building, Prisma raw unsafe, eval, shell injection, unsanitised HTML, CORS `*` + credentials, insecure session cookies, leaked error details | Built-in (+ Semgrep) |
| **Data protection** | Personal data sent to AI providers, credentials/PII in logs, NIN/BVN/card numbers stored | Built-in |
| **Dependencies** | Known-vulnerable packages | osv-scanner, if installed |
| **AI review** | Logic, authorization and business-rule flaws pattern checks can't see | Claude, optional (`--ai`). Every finding is **verified against the source**; anything whose quoted code can't be found is discarded |
| **Compliance** | Jurisdiction-aware requirements from a project profile | Versioned YAML rule packs in `rules/` |

Semgrep, gitleaks and osv-scanner are used automatically when installed; the report's coverage
section always says what ran and what didn't.

## Compliance: how it works

1. `save-my-code init` writes `.save-my-code/profile.yml`: where you operate, where users are,
   what data you handle (health, financial, children...), payments, automated decisions.
2. Rule packs whose jurisdiction matches are loaded (`NG` → NDPA 2023, `EU`/EEA countries → GDPR).
3. Requirements that don't apply to your profile are marked N/A (e.g. children's-data rules when you
   don't serve children).
4. Each applicable requirement is evaluated from **signals**: concrete checks against the code
   and findings (privacy notice present? account deletion route? passwords hashed? personal data
   sent abroad to an AI provider?).
5. Results: **pass**, **fail**, **needs evidence** (code looks fine, but you must confirm something
   only you know), or **manual review** (can't be verified from code at all, e.g. registration with
   the NDPC, or a lawful basis).

Every requirement carries its citation, whether that citation has been verified against the
official text, an effective date, and a flag when interpretation needs a lawyer.

```bash
node dist/cli.js rules     # list every requirement in every pack
```

**Important:** both rule packs are `review_status: unreviewed`. They are an engineering
interpretation written to find likely gaps, not legal advice. The NDPA section numbers in
particular are marked `citation_verified: false` until a qualified Nigerian data-protection
lawyer checks them against the official text and current NDPC guidance.

## Use it in CI (GitHub Action)

```yaml
# .github/workflows/save-my-code.yml
on: [pull_request]
permissions:
  contents: read
  security-events: write   # for code-scanning upload
jobs:
  assurance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kvngkc/save-my-code@main
        with:
          fail-on: high
          # ai: "true"
          # anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

Findings appear in the PR's code-scanning tab (SARIF), the full report is attached as an artifact
and the job summary, and the job fails when the release gate blocks.

## Use it from a coding agent

`skills/save-my-code/SKILL.md` is a Claude Code skill. Copy it into `.claude/skills/` in your
project. The agent then runs the deterministic scan, pulls the app map with
`save-my-code context`, does the logic review itself (no API key needed), and offers to fix what it
finds.

## CLI

```
save-my-code init [path] [--yes]
save-my-code scan [path] [--ai] [--profile f] [--format md,json,html,sarif] [--out dir]
                         [--fail-on critical|high|medium|low|none] [--fail-on-compliance]
                         [--min-confidence low|medium|high] [--no-external] [--quiet]
save-my-code context [path]
save-my-code rules
```

Exit codes: `0` pass/warn, `1` block, `2` error.

## Architecture

```
src/
  model/        file walker, stack detection, route extraction, SQL/RLS parser, PII detection
  checks/       deterministic checks → Finding[]
  external/     semgrep / gitleaks / osv-scanner adapters
  ai/           Claude review with structured output + evidence verification
  compliance/   profile, signals, rule-pack engine
  report/       markdown, HTML, JSON, SARIF, agent context
  scan.ts       orchestration + release gate
rules/          versioned jurisdiction rule packs (YAML)
examples/       deliberately vulnerable demo app
test/           detection tests against the demo app and a secure fixture
```

## Limitations

- No automated tool can prove an application is free of vulnerabilities or legally compliant.
  Save-My-Code reports what it verified, what it found, and what it could not check.
- Built-in checks are heuristics tuned for JS/TS web stacks (Next.js, Express, Supabase, Prisma).
  Expect some false positives and false negatives; findings carry a confidence level.
- No runtime or penetration testing yet: findings are not exploited against a running instance.
- Zero-day vulnerabilities in dependencies are out of reach until they are published.
- Compliance packs cover NDPA 2023 and GDPR only, and have not yet had legal review.

## Roadmap

- Runtime verification: spin up the app and prove IDOR/RLS findings with two test users
- More stacks: Firebase rules, Django/FastAPI, Laravel
- More jurisdictions: Ghana, Kenya, South Africa (POPIA), UK GDPR
- Lawyer-reviewed rule packs with change tracking
- Hosted dashboard with history and release assurance reports

## Development

```bash
npm install
npm run build
npm test
```
