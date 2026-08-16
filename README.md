# Terraform adversary

Reviews Terraform for public exposure, secrets in HCL, encryption, and module pinning.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Terraform configuration for public exposure, IAM authority, secrets, encryption, state safety, dependency pinning, TLS policy, and service-specific access controls.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It stays within this domain, does not execute target code, and leaves unrelated concerns to the corresponding specialist adversaries.
