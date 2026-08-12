import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  status: "added" | "modified" | "repository";
  changedLines: Set<number>;
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const sources: SourceFile[] = [];
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  for (const file of scoped) {
    if (wholeTarget || file.status === "repository") {
      sources.push({
        path: file.path,
        source: file.content,
        status: "repository",
        changedLines: new Set<number>(),
      });
      continue;
    }

    const change = await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      status: change.status,
      changedLines: change.changedLines,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[]): Detection[] {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locateEligible(file, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  if (match.kind === "block-missing-content") {
    return matchingSources.flatMap((file) =>
      extractBlocks(file.source, match.blockStart).flatMap((block) => {
        if (!test(block.source, match.trigger) || test(block.source, match.required)) return [];
        const location = locateEligible(file, match.trigger, block.start, block.source, match.anchors);
        if (location === undefined) return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
      }),
    );
  }

  if (match.kind === "block-content") {
    return matchingSources.flatMap((file) =>
      extractBlocks(file.source, match.blockStart).flatMap((block) => {
        const searchableBlock = maskComments(block.source);
        if (match.excludes?.some((expression) => test(searchableBlock, expression))) return [];
        const location = locateEligible(file, match.pattern, block.start, searchableBlock);
        if (location === undefined) return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
      }),
    );
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locateEligible(file, match.pattern, 0, file.source, match.anchors);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locateEligible(
  file: SourceFile,
  expression: MatchExpression,
  offset = 0,
  source = file.source,
  anchors?: readonly MatchExpression[],
): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  for (const match of source.matchAll(new RegExp(expression.pattern, flags))) {
    if (match.index === undefined) continue;
    const start = offset + match.index;
    const end = start + match[0].length;
    const anchor = anchors === undefined
      ? eligibleAnchor(file, lineAt(file.source, start), lineAt(file.source, Math.max(start, end - 1)))
      : eligibleSemanticAnchor(file, match[0], start, anchors);
    if (anchor === undefined) continue;
    return locationAtLine(file.source, anchor);
  }
  return undefined;
}

function eligibleSemanticAnchor(
  file: SourceFile,
  matchedSource: string,
  offset: number,
  anchors: readonly MatchExpression[],
): number | undefined {
  if (file.status !== "modified") return lineAt(file.source, offset);
  for (const anchor of anchors) {
    const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
    for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
      if (match.index === undefined) continue;
      const start = offset + match.index;
      const end = start + match[0].length;
      const line = eligibleAnchor(
        file,
        lineAt(file.source, start),
        lineAt(file.source, Math.max(start, end - 1)),
      );
      if (line !== undefined) return line;
    }
  }
  return undefined;
}

function eligibleAnchor(file: SourceFile, startLine: number, endLine: number): number | undefined {
  if (file.status !== "modified") return startLine;
  for (let line = startLine; line <= endLine; line += 1) {
    if (file.changedLines.has(line)) return line;
  }
  return undefined;
}

function lineAt(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function locationAtLine(source: string, line: number): { line: number; snippet: string } {
  return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

function extractBlocks(source: string, start: MatchExpression): Array<{ source: string; start: number }> {
  const searchableSource = maskComments(source);
  const flags = start.flags.includes("g") ? start.flags : `${start.flags}g`;
  const expression = new RegExp(start.pattern, flags);
  const blocks: Array<{ source: string; start: number }> = [];
  let match: RegExpExecArray | null;

  while ((match = expression.exec(searchableSource)) !== null) {
    const relativeBrace = match[0].lastIndexOf("{");
    if (relativeBrace < 0) continue;
    const openingBrace = match.index + relativeBrace;
    const end = findClosingBrace(searchableSource, openingBrace);
    if (end === undefined) continue;
    blocks.push({ source: source.slice(match.index, end + 1), start: match.index });
    expression.lastIndex = end + 1;
  }

  return blocks;
}

function maskComments(source: string): string {
  const output = source.split("");
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];

    if (inLineComment) {
      if (character === "\n") inLineComment = false;
      else output[index] = " ";
      continue;
    }
    if (inBlockComment) {
      output[index] = character === "\n" ? "\n" : " ";
      if (character === "*" && next === "/") {
        output[index + 1] = " ";
        inBlockComment = false;
        index += 1;
      }
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") inString = false;
      continue;
    }
    if (character === "\"") { inString = true; continue; }
    if (character === "#") { output[index] = " "; inLineComment = true; continue; }
    if (character === "/" && next === "/") {
      output[index] = " ";
      output[index + 1] = " ";
      inLineComment = true;
      index += 1;
      continue;
    }
    if (character === "/" && next === "*") {
      output[index] = " ";
      output[index + 1] = " ";
      inBlockComment = true;
      index += 1;
    }
  }

  return output.join("");
}

function findClosingBrace(source: string, openingBrace: number): number | undefined {
  let depth = 0;
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;

  for (let index = openingBrace; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1];

    if (inLineComment) {
      if (character === "\n") inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (character === "*" && next === "/") { inBlockComment = false; index += 1; }
      continue;
    }
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === "\"") inString = false;
      continue;
    }
    if (character === "#" || (character === "/" && next === "/")) { inLineComment = true; if (character === "/") index += 1; continue; }
    if (character === "/" && next === "*") { inBlockComment = true; index += 1; continue; }
    if (character === "\"") { inString = true; continue; }
    if (character === "{") depth += 1;
    else if (character === "}" && --depth === 0) return index;
  }

  return undefined;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
