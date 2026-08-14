> **Shipped in 0.0.11:** `terraform.public-ingress`, `terraform.s3-public-acl`, `terraform.rds-publicly-accessible`, `terraform.sensitive-output`, `terraform.inline-secret`, `terraform.iam-admin-wildcard`, `terraform.storage-unencrypted`, `terraform.cloudtrail-bucket-policy-source-arn`, `terraform.cloudfront-weak-viewer-tls`, `terraform.mutable-module`
>
> Rules documented below that are not in that list are deferred (not yet in `src/spec.ts`).

# Checks — what terraform detects

This file is the **public audit list** of detectors for the **terraform** adversary. If a rule id appears here, it is part of the product surface: it should fire on a high-confidence misconfiguration, stay quiet on intentional private networking and pinned modules, and produce file:line evidence in Terraform HCL.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `*.tf`, `*.tf.json`, and common Terraform variable/backend files. Prefer AWS/GCP/Azure resources only when provider blocks or resource type prefixes make the cloud unambiguous. Do not flag “style” (formatting, naming) without a security/reproducibility impact.

**Precision stance:** High confidence only. Open-to-world network and public object storage are reportable; private CIDRs and explicitly documented break-glass rules are not. Mutable module sources fire; commit SHAs and exact registry versions do not. (Note: `.terraform.lock.hcl` pins providers, not modules — module pinning must come from `ref=`/`version`.)

Public grounding includes common Terraform risk classes documented by HashiCorp AWS provider docs, Checkov/TFSec rule catalogs, and cloud provider guidance on unintended public exposure (e.g. [Spacelift Terraform security risks](https://spacelift.io/blog/terraform-security), [AWS security group resource docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)).

---

## Critical

### `terraform.public-ingress`

| | |
| --- | --- |
| **What** | Security group / firewall ingress allows `0.0.0.0/0` or `::/0` on admin or sensitive ports |
| **Why** | Internet-wide SSH/RDP/DB access is a primary cloud breach path |
| **Looks for** | `aws_security_group`, `aws_security_group_rule`, `google_compute_firewall`, `azurerm_network_security_rule` with `cidr_blocks` / `source_ranges` containing world CIDRs **and** ports in sensitive sets (22, 3389, 3306, 5432, 6379, 27017, 9200, 11211) or `protocol = "-1"` / all ports |
| **Stays quiet when** | World CIDR is only on 80/443 for intentional public HTTP, or source is a private range (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`); also quiet when port is not admin/data-plane |
| **Public examples** | Widespread tutorials still show `cidr_blocks = ["0.0.0.0/0"]` on port 22; real incidents repeatedly start from open management ports (see cloud provider “publicly accessible” guidance and [AWS SG docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group)) |
| **Remediation** | Restrict ingress to bastion/VPN/private subnets; use SSM/IAP instead of world SSH |

### `terraform.s3-public-acl`

| | |
| --- | --- |
| **What** | S3 bucket ACL or public-access-block configuration makes objects world-readable/writable |
| **Why** | Public buckets leak data at scale (Capital One class of incident patterns; continuous “open bucket” findings in cloud audits) |
| **Looks for** | `aws_s3_bucket_acl` with `public-read` / `public-read-write`; `aws_s3_bucket_public_access_block` with any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` set `false`; legacy `acl = "public-read"` on `aws_s3_bucket`; cloud parity: `google_storage_bucket_iam_member/binding` granting `allUsers`/`allAuthenticatedUsers`, `azurerm_storage_container` with `container_access_type = "blob"` or `"container"` |
| **Stays quiet when** | All public-access-block flags are true; website buckets are **not** auto-flagged without ACL/public-block evidence (websites may be intentional) |
| **Public examples** | Checkov `CKV_AWS_20` / `CKV_AWS_53–57` families; countless open-bucket writeups on mis-set ACLs |
| **Remediation** | Enable all four public access block settings; never use public ACLs for private data |

### `terraform.rds-publicly-accessible`

| | |
| --- | --- |
| **What** | Managed database instance set `publicly_accessible = true` |
| **Why** | Internet-facing databases with password auth are high-value targets |
| **Looks for** | `aws_db_instance`, `aws_rds_cluster_instance`, similar with `publicly_accessible = true` |
| **Stays quiet when** | Attribute absent or false |
| **Public examples** | AWS RDS docs warn against public accessibility; recurring audit findings in CIS AWS Foundations |
| **Remediation** | Keep DBs private; access via VPN/bastion/SSM; use private subnets |

---

## High

### `terraform.sensitive-output`

| | |
| --- | --- |
| **What** | Outputs export password, secret, token, private key, or connection string without `sensitive = true` |
| **Why** | Terraform state and CLI plan/apply logs retain outputs; non-sensitive secrets leak to CI logs |
| **Looks for** | `output` blocks whose name or `value` references password/secret/token/private_key/connection_string **without** `sensitive = true` |
| **Stays quiet when** | `sensitive = true` is set; outputs are non-secret identifiers (ARNs, names, public DNS) |
| **Public examples** | HashiCorp docs on sensitive values; CI log leaks of `terraform output` in shared pipelines |
| **Remediation** | Mark secret outputs `sensitive = true`; prefer secret managers over TF outputs for credentials |

### `terraform.inline-secret`

| | |
| --- | --- |
| **What** | Hardcoded credential literals in resources or variable defaults — HCL-context detection (provider blocks, resource attributes, `default =` on sensitive variables); generic pattern/entropy scanning is owned by `security/secrets` |
| **Why** | Secrets in HCL land in git and state |
| **Looks for** | `password = "…"`, `secret_key = "…"`, `access_key = "AKIA…"`, private key PEM blocks in `.tf` |
| **Stays quiet when** | Value is `var.*`, `sensitive` variable without default, or `random_password` / data source from a secrets manager |
| **Public examples** | Recurring `git-secrets` / trufflehog hits on Terraform repos; AWS key patterns in `.tf` |
| **Remediation** | Use `random_password`, SSM/Secrets Manager data sources, or CI-injected env—never commit literals |

### `terraform.iam-admin-wildcard`

| | |
| --- | --- |
| **What** | IAM policy document grants `Action = "*"` and `Resource = "*"` (or AdministratorAccess-equivalent) on human/app roles |
| **Why** | Full-admin blast radius on any credential theft |
| **Looks for** | `aws_iam_policy_document` / inline `policy` JSON with Action `*` and Resource `*`; attachment of `arn:aws:iam::aws:policy/AdministratorAccess` via `policy_arn` / `managed_policy_arns` |
| **Stays quiet when** | Actions are scoped (Resource `*` alone is acceptable for list/read APIs that require it). Action `*` + Resource `*` always fires — break-glass belongs in separate, documented accounts |
| **Public examples** | CIS AWS, IAM “full admin” findings; AWS managed `AdministratorAccess` attached via TF |
| **Remediation** | Least-privilege actions and resources; separate break-glass accounts |

### `terraform.storage-unencrypted`

| | |
| --- | --- |
| **What** | Persistent storage without encryption at rest where the resource supports it |
| **Why** | Disk snapshots and volume theft expose data |
| **Looks for** | Explicit `encrypted = false` / `storage_encrypted = false` on `aws_ebs_volume` / `aws_db_instance` / `aws_rds_cluster` / `aws_elasticache_replication_group` (high confidence). A merely *missing* encryption attribute is low confidence — account-level default encryption is common — report low severity or defer to LLM context |
| **Stays quiet when** | `encrypted = true`; attribute absent (downgrade to low — never fire high on absence alone) |
| **Public examples** | CIS AWS storage encryption controls; Checkov `CKV_AWS_3` / `CKV_AWS_16` families |
| **Remediation** | Enable encryption with CMK/account default |

### `terraform.cloudtrail-bucket-policy-source-arn`

| | |
| --- | --- |
| **What** | A CloudTrail service-principal bucket-policy statement allows `s3:PutObject` without binding the write to an intended trail ARN |
| **Why** | Without an `aws:SourceArn` condition, the service-principal grant lacks the recommended confused-deputy protection and may accept writes from an unintended trail |
| **Looks for** | An HCL `statement` block in a `*.tf` file that contains both `cloudtrail.amazonaws.com` and `s3:PutObject` but no `aws:SourceArn` |
| **Evidence** | Anchors the finding to the CloudTrail service principal or `s3:PutObject` action in that same statement; the missing `aws:SourceArn` condition is the required contract |
| **Stays quiet when** | The same statement contains `aws:SourceArn`; either the CloudTrail principal or `s3:PutObject` action is absent; the principal and action occur only in separate statement blocks; or the policy is expressed outside the supported HCL `statement` shape |
| **Public examples** | [AWS CloudTrail bucket-policy guidance](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html) recommends scoping service writes with `aws:SourceArn` |
| **Remediation** | Add an `aws:SourceArn` condition to the CloudTrail `s3:PutObject` statement and bind it to the intended trail ARN or a deliberately scoped trail pattern |

---

## Medium

### `terraform.cloudfront-weak-viewer-tls`

| | |
| --- | --- |
| **What** | CloudFront explicitly permits viewer connections below TLS 1.2 |
| **Why** | TLS 1.0 and 1.1 are deprecated; retaining a weak viewer policy lets clients negotiate legacy protocol versions |
| **Looks for** | `SSLv3`, `TLSv1`, `TLSv1_2016`, or `TLSv1.1_2016` in a `viewer_certificate` block, or as the default of a module's `minimum_protocol_version` variable |
| **Stays quiet when** | The floor is a TLS 1.2 policy; a weak value appears only in a comment; another unrelated variable contains a TLS-looking string; the CloudFront default certificate makes the setting inapplicable |
| **Public examples** | [Cloud Posse module migration and member approval](https://github.com/cloudposse/terraform-aws-cloudfront-cdn/pull/117); [AWS Labs Terraform module](https://github.com/awslabs/nx-plugin-for-aws/pull/948) |
| **Remediation** | Set `minimum_protocol_version = "TLSv1.2_2021"` and treat loss of TLS 1.0/1.1 clients as an intentional compatibility change |

### `terraform.mutable-module`

| | |
| --- | --- |
| **What** | Module source tracks a mutable branch or floating tag |
| **Why** | Two applies can resolve different module code with unchanged root config |
| **Looks for** | `module` blocks with `source` git URLs using `ref=main|master|HEAD` or unpinned branch; registry sources without version |
| **Stays quiet when** | `ref=` is a full commit SHA or version tag; registry module has `version = "x.y.z"` |
| **Public examples** | Terraform module source docs recommend pinning; supply-chain discussions on mutable git modules |
| **Remediation** | Pin to commit SHA or immutable version; review upgrades deliberately |

### `terraform.state-no-backend-encryption`

| | |
| --- | --- |
| **What** | Remote state backend without locking |
| **Why** | State contains secrets; concurrent applies corrupt state. (AWS S3 applies SSE by default since 2023, so a missing `encrypt` flag is low-value — locking is the real gap) |
| **Looks for** | `backend "s3"` with neither `dynamodb_table` nor `use_lockfile = true` (TF ≥ 1.10 native S3 locking); explicit `encrypt = false` |
| **Stays quiet when** | Locking configured via `dynamodb_table` or `use_lockfile`; local backend for throwaway sandboxes |
| **Public examples** | HashiCorp S3 backend docs; state-leak incidents when state is world-readable |
| **Remediation** | Encrypt state, enable locking, restrict bucket ACLs |

### `terraform.open-egress-all`

| | |
| --- | --- |
| **What** | Security group egress allows all protocols to `0.0.0.0/0` **combined with** unrestricted ingress (amplifies C2) |
| **Why** | Compromised hosts exfiltrate freely; often paired with open ingress in tutorial code |
| **Looks for** | Egress `0.0.0.0/0` with protocol `-1` **and** the same SG has reportable public ingress (rule co-occurrence) |
| **Stays quiet when** | Egress is open but ingress is private-only (common AWS default; alone too noisy) |
| **Public examples** | AWS default SG egress is open; high-value when co-located with public admin ingress |
| **Remediation** | Restrict egress where possible; never pair with public admin ingress |

### `terraform.provider-unpinned`

| | |
| --- | --- |
| **What** | Provider requirements have no version constraint and no committed dependency lock file |
| **Why** | Provider upgrades change resource behavior (and occasionally security defaults) silently between applies |
| **Looks for** | `required_providers` entries without `version`, or providers used with no `required_providers` block at all, **and** no `.terraform.lock.hcl` committed |
| **Stays quiet when** | Version constraints present; or `.terraform.lock.hcl` is committed (the lock pins providers even without constraints — downgrade to low) |
| **Public examples** | HashiCorp provider requirements + dependency lock docs recommend constraint and lock together |
| **Remediation** | Add `~>` constraints in `required_providers` and commit `.terraform.lock.hcl` |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Generic secret patterns/entropy (any file type) | `security/secrets` — this adversary keeps only HCL-context findings (`terraform.inline-secret`) |
| Dockerfile / image build | `container/dockerfile` |
| Kubernetes workload YAML (non-TF) | `kubernetes` |
| Helm chart templates | `helm` |
