import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import type { SourceFile } from "../types.js";

const IGNORED_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", "out", "coverage",
  ".vercel", ".turbo", ".cache", "vendor", "__pycache__", ".venv", "venv", ".save-my-code",
]);

const SCANNED_EXT = /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|py|sql|json|ya?ml|toml|md|mdx|html|env|prisma|rules)$/i;
const ENV_FILE = /(^|\/)\.env(\.[\w-]+)?$/;
const MAX_FILE_BYTES = 512 * 1024;

export function loadFiles(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  walk(root, root, out);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

function walk(root: string, dir: string, out: SourceFile[]) {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (!IGNORED_DIRS.has(name)) walk(root, full, out);
      continue;
    }
    const rel = relative(root, full).split(sep).join("/");
    if (!SCANNED_EXT.test(name) && !ENV_FILE.test(rel) && name !== ".gitignore") continue;
    if (name === "package-lock.json" || name === "pnpm-lock.yaml" || name === "yarn.lock") continue;
    if (st.size > MAX_FILE_BYTES) continue;
    const content = readFileSync(full, "utf8");
    out.push({ path: rel, content, lines: content.split(/\r?\n/), clientSide: isClientSide(rel, content) });
  }
}

export function isClientSide(path: string, content: string): boolean {
  if (/^\s*["']use client["']/m.test(content.slice(0, 200))) return true;
  if (/\.(vue|svelte)$/.test(path) && !/\+server\.|\+page\.server\./.test(path)) return true;
  if (/(^|\/)(components|hooks|public|client)\//.test(path) && !/\/api\//.test(path)) return true;
  if (/(^|\/)src\/(App|main)\.(t|j)sx?$/.test(path)) return true;
  return false;
}

/** 1-based line number of a character offset */
export function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export function excerpt(file: SourceFile, line: number, context = 0): string {
  const start = Math.max(0, line - 1 - context);
  const end = Math.min(file.lines.length, line + context);
  return file.lines.slice(start, end).join("\n").trim().slice(0, 400);
}

/** Extract a balanced {...} block starting at the first "{" at or after index. */
export function extractBlock(content: string, index: number, maxLen = 8000): string {
  const open = content.indexOf("{", index);
  if (open === -1) return content.slice(index, index + 500);
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
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return content.slice(index, i + 1);
    }
  }
  return content.slice(index, Math.min(content.length, open + maxLen));
}

export const isCode = (p: string) => /\.(ts|tsx|js|jsx|mjs|cjs|vue|svelte|py)$/i.test(p);
export const isTest = (p: string) => /(^|\/)(__tests__|tests?|spec|e2e|fixtures?)\/|\.(test|spec)\.[jt]sx?$/.test(p);
