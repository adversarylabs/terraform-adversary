import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated edit does not surface a legacy Terraform finding", async () => {
  const repo = await committedRepository({
    "main.tf": databaseSource(true, "old diagnostic"),
  });
  await writeFile(join(repo, "main.tf"), databaseSource(true, "new diagnostic"));

  const output = await changedReview(repo, ["main.tf"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "terraform.rds-publicly-accessible"),
    false,
  );
});

test("a direct finding on a changed line remains eligible", async () => {
  const repo = await committedRepository({
    "main.tf": databaseSource(false, "unchanged"),
  });
  await writeFile(join(repo, "main.tf"), databaseSource(true, "unchanged"));

  const output = await changedReview(repo, ["main.tf"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "terraform.rds-publicly-accessible",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 3);
});

test("a changed occurrence is found after an unchanged legacy occurrence", async () => {
  const original = `${databaseSource(true, "legacy")}
resource "aws_db_instance" "secondary" {
  publicly_accessible = false
}
`;
  const updated = original.replace(
    "resource \"aws_db_instance\" \"secondary\" {\n  publicly_accessible = false",
    "resource \"aws_db_instance\" \"secondary\" {\n  publicly_accessible = true",
  );
  const repo = await committedRepository({ "main.tf": original });
  await writeFile(join(repo, "main.tf"), updated);

  const output = await changedReview(repo, ["main.tf"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "terraform.rds-publicly-accessible",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 8);
});

test("unchanged block context supports a changed missing-field trigger anchor", async () => {
  const original = cloudTrailStatement("s3:GetObject");
  const repo = await committedRepository({ "policy.tf": original });
  await writeFile(join(repo, "policy.tf"), cloudTrailStatement("s3:PutObject"));

  const output = await changedReview(repo, ["policy.tf"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "terraform.cloudtrail-bucket-policy-source-arn",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 5);
});

test("unchanged block context supports a changed block-content anchor", async () => {
  const repo = await committedRepository({
    "cloudfront.tf": viewerCertificate("TLSv1.2_2021"),
  });
  await writeFile(join(repo, "cloudfront.tf"), viewerCertificate("TLSv1"));

  const output = await changedReview(repo, ["cloudfront.tf"]);

  const finding = output.findings.find(
    (item) => item.ruleId === "terraform.cloudfront-weak-viewer-tls",
  );
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.location?.line, 3);
});

test("an unrelated changed line inside a composite span does not reactivate a legacy finding", async () => {
  const original = ingressSource("legacy");
  const repo = await committedRepository({ "network.tf": original });
  await writeFile(join(repo, "network.tf"), ingressSource("updated"));

  const output = await changedReview(repo, ["network.tf"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "terraform.public-ingress"),
    false,
  );
});

test("an added Terraform file remains eligible in full", async () => {
  const repo = await committedRepository({ "main.tf": "locals { name = \"fixture\" }\n" });
  await writeRepositoryFile(repo, "database.tf", databaseSource(true, "added"));

  const output = await changedReview(repo, ["database.tf"]);

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "terraform.rds-publicly-accessible"),
    true,
  );
});

test("an all-files review remains eligible in full", async () => {
  const repo = await committedRepository({
    "main.tf": databaseSource(true, "old diagnostic"),
  });
  await writeFile(join(repo, "main.tf"), databaseSource(true, "new diagnostic"));

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "all",
        changed_files: ["main.tf"],
      },
    },
  });

  assert.equal(
    output.findings.some((finding) => finding.ruleId === "terraform.rds-publicly-accessible"),
    true,
  );
});

async function committedRepository(files: Record<string, string>): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "terraform-adversary-scope-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  for (const [path, source] of Object.entries(files)) {
    await writeRepositoryFile(repo, path, source);
  }
  await execute("git", ["add", "."], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function writeRepositoryFile(repo: string, path: string, source: string): Promise<void> {
  await mkdir(join(repo, dirname(path)), { recursive: true });
  await writeFile(join(repo, path), source);
}

async function changedReview(repoPath: string, changedFiles: string[]) {
  return createApp().run({
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}

function databaseSource(publiclyAccessible: boolean, diagnostic: string): string {
  return `resource "aws_db_instance" "primary" {
  identifier          = "primary"
  publicly_accessible = ${publiclyAccessible}
  tags = { Diagnostic = "${diagnostic}" }
}
`;
}

function cloudTrailStatement(action: string): string {
  return `data "aws_iam_policy_document" "trail" {
  statement {
    principals { identifiers = ["cloudtrail.amazonaws.com"] }
    actions = [
      "${action}"
    ]
    resources = ["arn:aws:s3:::logs/*"]
  }
}
`;
}

function ingressSource(description: string): string {
  return `resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]
  description = "${description}"
  from_port  = 22
  to_port    = 22
  protocol   = "tcp"
}
`;
}

function viewerCertificate(protocol: string): string {
  return `viewer_certificate {
  acm_certificate_arn      = aws_acm_certificate.site.arn
  minimum_protocol_version = "${protocol}"
  ssl_support_method       = "sni-only"
}
`;
}
