import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const sources = scoped.map((file) => ({ path: file.path, source: file.content }));
    ctx.summary.files_scanned = sources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locate(file.source, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    if (match.kind === "block-missing-content") {
        return matchingSources.flatMap((file) => extractBlocks(file.source, match.blockStart).flatMap((block) => {
            if (!test(block.source, match.trigger) || test(block.source, match.required))
                return [];
            const location = locateFromIndex(file.source, block.start);
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        }));
    }
    if (match.kind === "block-content") {
        return matchingSources.flatMap((file) => extractBlocks(file.source, match.blockStart).flatMap((block) => {
            const searchableBlock = maskComments(block.source);
            if (match.excludes?.some((expression) => test(searchableBlock, expression)))
                return [];
            const blockMatch = new RegExp(match.pattern.pattern, match.pattern.flags).exec(searchableBlock);
            if (blockMatch?.index === undefined)
                return [];
            const location = locateFromIndex(file.source, block.start + blockMatch.index);
            return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
        }));
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locate(file.source, match.pattern);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locate(source, expression) {
    const match = new RegExp(expression.pattern, expression.flags).exec(source);
    if (match?.index === undefined)
        return undefined;
    return locateFromIndex(source, match.index);
}
function locateFromIndex(source, index) {
    const line = source.slice(0, index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
function extractBlocks(source, start) {
    const searchableSource = maskComments(source);
    const flags = start.flags.includes("g") ? start.flags : `${start.flags}g`;
    const expression = new RegExp(start.pattern, flags);
    const blocks = [];
    let match;
    while ((match = expression.exec(searchableSource)) !== null) {
        const relativeBrace = match[0].lastIndexOf("{");
        if (relativeBrace < 0)
            continue;
        const openingBrace = match.index + relativeBrace;
        const end = findClosingBrace(searchableSource, openingBrace);
        if (end === undefined)
            continue;
        blocks.push({ source: source.slice(match.index, end + 1), start: match.index });
        expression.lastIndex = end + 1;
    }
    return blocks;
}
function maskComments(source) {
    const output = source.split("");
    let inString = false;
    let inLineComment = false;
    let inBlockComment = false;
    let escaped = false;
    for (let index = 0; index < source.length; index += 1) {
        const character = source[index];
        const next = source[index + 1];
        if (inLineComment) {
            if (character === "\n")
                inLineComment = false;
            else
                output[index] = " ";
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
            if (escaped)
                escaped = false;
            else if (character === "\\")
                escaped = true;
            else if (character === "\"")
                inString = false;
            continue;
        }
        if (character === "\"") {
            inString = true;
            continue;
        }
        if (character === "#") {
            output[index] = " ";
            inLineComment = true;
            continue;
        }
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
function findClosingBrace(source, openingBrace) {
    let depth = 0;
    let inString = false;
    let inLineComment = false;
    let inBlockComment = false;
    let escaped = false;
    for (let index = openingBrace; index < source.length; index += 1) {
        const character = source[index];
        const next = source[index + 1];
        if (inLineComment) {
            if (character === "\n")
                inLineComment = false;
            continue;
        }
        if (inBlockComment) {
            if (character === "*" && next === "/") {
                inBlockComment = false;
                index += 1;
            }
            continue;
        }
        if (inString) {
            if (escaped)
                escaped = false;
            else if (character === "\\")
                escaped = true;
            else if (character === "\"")
                inString = false;
            continue;
        }
        if (character === "#" || (character === "/" && next === "/")) {
            inLineComment = true;
            if (character === "/")
                index += 1;
            continue;
        }
        if (character === "/" && next === "*") {
            inBlockComment = true;
            index += 1;
            continue;
        }
        if (character === "\"") {
            inString = true;
            continue;
        }
        if (character === "{")
            depth += 1;
        else if (character === "}" && --depth === 0)
            return index;
    }
    return undefined;
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
