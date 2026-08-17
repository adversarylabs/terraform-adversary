import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { spec } from "../src/spec.ts";

test("CHECKS compactly documents every shipped rule", async () => {
  const checks = await readFile(new URL("../CHECKS.md", import.meta.url), "utf8");

  const expectedIds = spec.rules.map((rule) => rule.id).sort();
  const documentedIds = [...checks.matchAll(/^\| `(terraform\.[^`]+)` \| [^|]+ \| [^|]+ \|$/gm)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(documentedIds, expectedIds, "CHECKS table must match the runtime specification");
  assert.doesNotMatch(checks, /^### /m, "CHECKS should remain a compact table rather than per-rule prose");
});
