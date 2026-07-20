# Initial checks

## terraform.public-ingress

- Severity: high
- Category: security
- Recommendation: Restrict ingress to trusted networks and required ports.

## terraform.mutable-module

- Severity: medium
- Category: supply-chain
- Recommendation: Pin VCS modules to immutable commits.

## terraform.sensitive-output

- Severity: high
- Category: secrets
- Recommendation: Mark credential outputs sensitive or avoid exporting them.

