import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parseAdversaryManifest } from "@adversarylabs/sdk";
import { spec } from "../src/spec.ts";

test("CHECKS documents every shipped rule without stale placeholders", async () => {
  const checks = await readFile(new URL("../CHECKS.md", import.meta.url), "utf8");
  const manifestSource = await readFile(new URL("../adversary.yaml", import.meta.url), "utf8");
  const manifest = parseAdversaryManifest(manifestSource);
  const shipped = checks.match(/^> \*\*Shipped in ([^:]+):\*\* (.+)$/m);

  assert.ok(shipped, "CHECKS must contain a populated shipped-rule summary");
  assert.equal(shipped[1], manifest.version, "shipped-rule summary must name the current version");
  assert.doesNotMatch(shipped[2] ?? "", /^(?:\s*,\s*)+$/, "shipped-rule summary cannot contain blank placeholders");

  const expectedIds = spec.rules.map((rule) => rule.id);
  const summaryIds = [...(shipped[2] ?? "").matchAll(/`(terraform\.[^`]+)`/g)]
    .map((match) => match[1]);
  assert.deepEqual(summaryIds, expectedIds, "shipped-rule summary must match the runtime specification");

  for (const id of expectedIds) {
    assert.match(checks, new RegExp("^### `" + escapeRegExp(id) + "`$", "m"), `${id} needs a CHECKS section`);
  }
});

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
