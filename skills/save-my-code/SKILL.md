---
name: save-my-code
description: Run an independent assurance review of an AI-generated web app before it ships - access control (IDOR, Supabase RLS), secrets, auth, injection, data protection, and NDPA/GDPR compliance. Use when the user asks to "check my app before launch", "is this safe to ship", "security review", "save my code", or after finishing a feature that touches auth, data access, payments or personal data.
---

# Save-My-Code review

You are acting as an independent reviewer of code that a coding agent (possibly you) wrote. Be
sceptical of the code, including your own earlier work. The goal is to find what would hurt the
user after launch, not to praise the code.

## 1. Make sure there is a compliance profile

Look for `.save-my-code/profile.yml` in the project. If it is missing, ask the user these questions
(one message, all at once) and write the file with `save-my-code init --yes` and then edit it:

- Where does the business operate, and where are users located? (country codes: NG, EU, ...)
- Does it collect personal information? Any health, financial, children's, biometric or government-ID data?
- Does it process payments? Does it make automated decisions about people?

## 2. Run the deterministic scan

```bash
npx save-my-code scan . --format md,json
# or, from a clone of the save-my-code repo:
node /path/to/save-my-code/dist/cli.js scan . --format md,json
```

Read `.save-my-code/reports/report.json`. Exit code 1 means the release gate blocked.

## 3. Do the AI review yourself

Pattern checks miss logic flaws. Get the app map and the most security-relevant source:

```bash
npx save-my-code context .
```

Then review it for:

- **Access control:** can user A read or change user B's records? Look at every route that takes an
  ID and confirm the query is scoped to the authenticated user or protected by RLS. Check admin
  actions for role checks, and look for roles, prices or plan tiers taken from the request.
- **Auth flows:** password reset, OTP, email verification, session handling. Could anyone take over an account?
- **Business logic:** payments and bookings. Client-supplied prices, negative quantities, double
  submission, skipped steps, race conditions.
- **Data protection:** personal data returned in API responses that don't need it, sent to
  third-party APIs (AI providers, analytics), or written to logs.

Only report issues you can point to with a file and line. Quote the code.

## 4. Report

Give the user:

1. The release decision (pass / warn / block) and why, in one or two sentences.
2. Critical and high issues first. For each: what an attacker or failure would do, in plain
   language, the file:line, and the concrete fix.
3. Compliance gaps that failed, and the questions only the user can answer (lawful basis, DPAs,
   registration). Say clearly that compliance results are not legal advice, and that the rule packs
   have not yet been reviewed by a lawyer.
4. What was *not* checked (see the report's coverage and limitations sections).

Offer to fix the critical and high issues, then re-run the scan to confirm they are gone.
Never claim the app is "secure" or "compliant". Say what was verified and what remains.
