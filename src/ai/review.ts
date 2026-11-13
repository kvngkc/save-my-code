import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import { z } from "zod";
import type { AppModel, Finding, ToolRun } from "../types.js";
import { finding } from "../checks/util.js";
import { renderContext } from "../report/context.js";

export const AI_MODEL = "claude-opus-5-5";
const MAX_CONTEXT_CHARS = 400_000;

const AiFindingSchema = z.object({
  title: z.string(),
  severity: z.enum(["critical", "high", "medium", "low"]),
  category: z.enum(["access-control", "auth", "logic", "injection", "data-protection", "config"]),
  file: z.string(),
  line: z.number().int(),
  evidence: z.string().describe("Exact code copied verbatim from the file at that line"),
  description: z.string().describe("What is wrong and the concrete attack or failure scenario"),
  remediation: z.string(),
  confidence: z.enum(["high", "medium", "low"]),
});
const AiReviewSchema = z.object({ findings: z.array(AiFindingSchema) });

const SYSTEM = `You are the independent reviewer inside Save-My-Code, an assurance tool for AI-generated web applications.
You review code that a coding agent wrote, looking for defects that pattern-based scanners miss:
- broken access control: users reaching other users' or tenants' data, missing ownership checks, privilege escalation, admin actions without role checks, trusting client-supplied roles or prices
- authentication and session flaws: account takeover through password reset or OTP, missing verification, session fixation
- business-logic errors: payments or bookings that can be manipulated (negative quantities, client-side prices, double-spend, race conditions), state machines that can be skipped
- data-protection problems: personal data exposed in responses, sent to third parties, or kept without need

Rules:
- Report only issues you can point to in the provided code, with the exact file path and line number as shown in the line-numbered listing.
- "evidence" must be copied verbatim from that line (or the line range starting there), with no paraphrasing.
- Prefer a few real, exploitable issues over many speculative ones. Do not report style, performance or missing tests.
- Do not repeat issues already listed under "Findings from deterministic checks" unless you add a materially different exploit path.
- If you find nothing, return an empty list.`;

export interface AiResult {
  findings: Finding[];
  run: ToolRun;
}

export async function runAiReview(model: AppModel, existing: Finding[]): Promise<AiResult> {
  const context = renderContext(model, existing, { numbered: true, maxChars: MAX_CONTEXT_CHARS });
  const client = new Anthropic();
  let response;
  try {
    // Streamed: large inputs plus high-effort thinking can exceed non-streaming HTTP timeouts.
    response = await client.messages
      .stream({
        model: AI_MODEL,
        max_tokens: 64000,
        thinking: { type: "adaptive" },
        output_config: { effort: "high", format: zodOutputFormat(AiReviewSchema) },
        system: SYSTEM,
        messages: [{ role: "user", content: `Review this application.\n\n${context}` }],
      })
      .finalMessage();
  } catch (err) {
    if (err instanceof Anthropic.AuthenticationError) return skipped("no valid Anthropic credentials (set ANTHROPIC_API_KEY)");
    if (err instanceof Anthropic.RateLimitError) return failed("rate limited by the Anthropic API; try again later");
    if (err instanceof Anthropic.AnthropicError && /authentication|apiKey|authToken/i.test(err.message)) return skipped("no Anthropic credentials found (set ANTHROPIC_API_KEY)");
    if (err instanceof Anthropic.APIError) return failed(`Anthropic API error ${err.status ?? ""}: ${err.message}`.slice(0, 200));
    throw err;
  }

  if (response.stop_reason === "refusal") return failed("the model declined to review this code");
  if (response.stop_reason === "max_tokens") return failed("the review was cut off (output limit reached)");
  const parsed = response.parsed_output;
  if (!parsed) return failed("the model returned output that did not match the findings schema");

  // Verification: drop any finding whose evidence cannot be located in the cited file.
  const verified: Finding[] = [];
  let dropped = 0;
  for (const f of parsed.findings) {
    const file = model.files.find((x) => x.path === f.file);
    const line = file ? locateEvidence(file.lines, f.evidence, f.line) : null;
    if (!file || line === null) {
      dropped++;
      continue;
    }
    verified.push(finding({ ...f, source: "ai", ruleId: `ai/${f.category}`, line, evidence: f.evidence.slice(0, 400) }));
  }
  return {
    findings: verified,
    run: {
      tool: `ai-review (${AI_MODEL})`,
      status: "ran",
      detail: `${parsed.findings.length} proposed, ${verified.length} verified against source, ${dropped} discarded as unverifiable`,
      findings: verified.length,
    },
  };
}

const norm = (s: string) => s.replace(/\s+/g, " ").trim();

/** Find the evidence near the claimed line; returns the corrected 1-based line or null. */
export function locateEvidence(lines: string[], evidence: string, claimed: number): number | null {
  const first = norm(evidence.split("\n").find((l) => l.trim().length > 0) ?? "");
  if (first.length < 4) return null;
  const order = [...Array(lines.length).keys()].sort((a, b) => Math.abs(a + 1 - claimed) - Math.abs(b + 1 - claimed));
  for (const i of order) {
    if (Math.abs(i + 1 - claimed) > 15) break;
    if (norm(lines[i]).includes(first) || (first.length > 20 && first.includes(norm(lines[i])) && norm(lines[i]).length > 15)) return i + 1;
  }
  return null;
}

const skipped = (detail: string): AiResult => ({ findings: [], run: { tool: `ai-review (${AI_MODEL})`, status: "skipped", detail, findings: 0 } });
const failed = (detail: string): AiResult => ({ findings: [], run: { tool: `ai-review (${AI_MODEL})`, status: "failed", detail, findings: 0 } });
