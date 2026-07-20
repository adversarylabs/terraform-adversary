# Terraform adversary

Reviews Terraform for public exposure, mutable modules, and output leaks.

## Checks

- **Security rule exposes a service globally:** Restrict ingress to trusted networks and required ports.
- **VCS module tracks a mutable branch:** Pin VCS modules to immutable commits.
- **Credential output is not marked sensitive:** Mark credential outputs sensitive or avoid exporting them.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
