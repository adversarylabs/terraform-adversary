import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [{"key": "public-ingress", "id": "terraform.public-ingress"}, {"key": "s3-public-acl", "id": "terraform.s3-public-acl"}, {"key": "rds-publicly-accessible", "id": "terraform.rds-publicly-accessible"}, {"key": "sensitive-output", "id": "terraform.sensitive-output"}, {"key": "inline-secret", "id": "terraform.inline-secret"}, {"key": "iam-admin-wildcard", "id": "terraform.iam-admin-wildcard"}, {"key": "storage-unencrypted", "id": "terraform.storage-unencrypted"}, {"key": "cloudtrail-bucket-policy-source-arn", "id": "terraform.cloudtrail-bucket-policy-source-arn"}, {"key": "cloudfront-weak-viewer-tls", "id": "terraform.cloudfront-weak-viewer-tls"}, {"key": "mutable-module", "id": "terraform.mutable-module"}];

test("every shipped rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("weak CloudFront TLS evidence points to each explicit value", async () => {
  const output = await review("rules/cloudfront-weak-viewer-tls/vulnerable", true);
  assert.deepEqual(
    output.rawObservations
      ?.filter((item) => item.ruleId === "terraform.cloudfront-weak-viewer-tls")
      .map((item) => [item.location?.line, item.location?.snippet]),
    [
      [4, 'minimum_protocol_version = "TLSv1"'],
      [10, 'default     = "TLSv1.1_2016"'],
    ],
  );
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "terraform");
});
