# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `terraform.cloudfront-weak-viewer-tls` | Medium | CloudFront explicitly permits viewer connections below TLS 1.2 |
| `terraform.cloudtrail-bucket-policy-source-arn` | High | A CloudTrail service-principal bucket-policy statement allows `s3:PutObject` without binding the write to an intended trail ARN |
| `terraform.iam-admin-wildcard` | High | IAM policy document grants `Action = "*"` and `Resource = "*"` (or AdministratorAccess-equivalent) on human/app roles |
| `terraform.inline-secret` | High | Hardcoded credential literals in resources or variable defaults — HCL-context detection (provider blocks, resource attributes, `default =` on sensitive variables); generic pattern/entropy scanning is owned by `security/secrets` |
| `terraform.mutable-module` | Medium | Module source tracks a mutable branch or floating tag |
| `terraform.public-ingress` | Critical | Security group / firewall ingress allows `0.0.0.0/0` or `::/0` on admin or sensitive ports |
| `terraform.rds-publicly-accessible` | Critical | Managed database instance set `publicly_accessible = true` |
| `terraform.s3-public-acl` | Critical | S3 bucket ACL or public-access-block configuration makes objects world-readable/writable |
| `terraform.sensitive-output` | High | Outputs export password, secret, token, private key, or connection string without `sensitive = true` |
| `terraform.storage-unencrypted` | High | Persistent storage without encryption at rest where the resource supports it |
