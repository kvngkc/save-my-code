import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { z } from "zod";
import type { ComplianceProfile } from "../types.js";

const ProfileSchema = z.object({
  project: z.string().default("unnamed"),
  jurisdictions: z.array(z.string().toUpperCase()).default([]),
  users_located_in: z.array(z.string().toUpperCase()).default([]),
  industry: z.string().default("other"),
  collects_personal_data: z.boolean().default(true),
  sensitive_data: z
    .array(z.enum(["health", "financial", "children", "biometric", "government-id", "religious", "ethnic", "political", "sexual"]))
    .default([]),
  processes_payments: z.boolean().default(false),
  automated_decisions: z.boolean().default(false),
  children: z.boolean().default(false),
  serves: z.enum(["consumers", "businesses", "both"]).default("consumers"),
  uses_ai_providers: z.union([z.boolean(), z.literal("auto")]).default("auto"),
  hosting_region: z.string().optional(),
});

export const PROFILE_PATHS = [".save-my-code/profile.yml", ".save-my-code/profile.yaml", "save-my-code.yml"];

export function findProfile(root: string): string | null {
  for (const p of PROFILE_PATHS) if (existsSync(join(root, p))) return join(root, p);
  return null;
}

export function loadProfile(path: string): ComplianceProfile {
  const raw = parse(readFileSync(path, "utf8")) ?? {};
  const parsed = ProfileSchema.safeParse(raw);
  if (!parsed.success) {
    throw new Error(`Invalid compliance profile ${path}:\n` + parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n"));
  }
  return parsed.data as ComplianceProfile;
}

export function profileTemplate(p: Partial<ComplianceProfile> = {}): string {
  const v = { ...ProfileSchema.parse({}), ...p };
  return `# Save-My-Code compliance profile
# Describes what the application does and where, so the right legal requirements are checked.
# Codes: NG (Nigeria), EU (European Union / EEA). More jurisdictions are planned.

project: ${JSON.stringify(v.project)}

# Where the business operates / is established
jurisdictions: [${v.jurisdictions.join(", ")}]

# Where the people whose data you process are located
users_located_in: [${v.users_located_in.join(", ")}]

# healthcare | finance | education | ecommerce | marketplace | saas | other
industry: ${v.industry}

collects_personal_data: ${v.collects_personal_data}

# Any of: health, financial, children, biometric, government-id, religious, ethnic, political, sexual
sensitive_data: [${v.sensitive_data.join(", ")}]

processes_payments: ${v.processes_payments}

# Does the app make decisions about people automatically (credit scoring, eligibility, ranking)?
automated_decisions: ${v.automated_decisions}

# Is the service directed at, or likely used by, children?
children: ${v.children}

# consumers | businesses | both
serves: ${v.serves}

# true | false | auto (detect AI SDK usage in the code)
uses_ai_providers: ${v.uses_ai_providers}

# Where the app and database are hosted (e.g. eu-west-1, us-east-1, ng). Optional.
${v.hosting_region ? `hosting_region: ${v.hosting_region}` : "# hosting_region: us-east-1"}
`;
}
