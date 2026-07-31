# terraform

**terraform** reviews Terraform HCL for **public exposure, secrets in configuration, encryption at rest, and supply-chain pinning** across cloud resources.

It is an **IaC security reviewer**, not a general Terraform style linter. When it reports, infrastructure is likely exposed, non-reproducible, or shipping credentials in state.

## What it does

1. **Discovers** `*.tf` / `*.tf.json` files.
2. **Runs deterministic detectors** for network exposure, public storage, DB accessibility, secrets, IAM, and module pinning.
3. **Synthesizes a review** with file:line evidence.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)**.

Highlights:

| Area | Examples |
| --- | --- |
| Network | World CIDR on admin ports |
| Storage | Public S3 ACL / public access block disabled |
| Data | RDS publicly_accessible; unencrypted volumes |
| Secrets | Unmarked sensitive outputs; password literals |
| IAM / modules | Action=* Resource=*; mutable module ref=main |

### Ownership boundaries

| Concern | Owned by |
| --- | --- |
| Generic secret entropy in any file | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |
| Kubernetes YAML (non-TF) | [`kubernetes`](https://github.com/adversarylabs/kubernetes-adversary) |
| Helm charts | [`helm`](https://github.com/adversarylabs/helm-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire.
- Prefer missing a weak signal over a false positive on normal production code.
