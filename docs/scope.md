# infra/terraform — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `terraform`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Terraform

## Mission

Review Terraform for public exposure, secrets in HCL, encryption, and module pinning.

## In scope (fair miss if humans raised it and we did not)

- Public exposure of private resources
- Secrets in HCL
- Missing encryption
- Unpinned modules
- Explicitly weak CloudFront viewer TLS policies

## Out of scope (not a miss for this adversary)

- App language logic
- Pure CI

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
