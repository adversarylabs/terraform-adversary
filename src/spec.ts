import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; anchors?: MatchExpression[]; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface BlockContentMatch { kind: "block-content"; files: string[]; blockStart: MatchExpression; pattern: MatchExpression; excludes?: MatchExpression[] }
interface BlockMissingContentMatch { kind: "block-missing-content"; files: string[]; blockStart: MatchExpression; trigger: MatchExpression; anchors?: MatchExpression[]; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | BlockContentMatch | BlockMissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "terraform",
  "displayName": "Terraform",
  "description": "Reviews Terraform for public exposure, secrets in HCL, encryption, and supply-chain pinning.",
  "files": [
    "**/*.tf",
    "**/*.tf.json"
  ],
  "rules": [
    {
      "id": "terraform.public-ingress",
      "title": "Security rule exposes a sensitive port to the world",
      "summary": "Security rule exposes a sensitive port to the world",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Internet-wide SSH/RDP/DB access is a primary cloud breach path.",
      "impact": "Attackers can scan and brute-force management and data-plane ports.",
      "recommendation": "Restrict ingress to trusted networks; use SSM/IAP instead of world SSH.",
      "complexity": "small",
      "tags": [
        "security",
        "public-ingress"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\\\"']0\\.0\\.0\\.0/0[\\\"'][^\\]]*\\][\\s\\S]{0,80}from_port\\s*=\\s*(?:22|3389|3306|5432|6379|27017|9200|11211)\\b",
          "flags": "i"
        },
        "anchors": [
          {
            "pattern": "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\\\"']0\\.0\\.0\\.0/0[\\\"'][^\\]]*\\]",
            "flags": "i"
          },
          {
            "pattern": "from_port\\s*=\\s*(?:22|3389|3306|5432|6379|27017|9200|11211)\\b",
            "flags": "i"
          }
        ],
        "requires": []
      }
    },
    {
      "id": "terraform.s3-public-acl",
      "title": "Object storage is configured for public access",
      "summary": "Object storage is configured for public access",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Public buckets and containers leak data at scale.",
      "impact": "World-readable object storage exposes private data.",
      "recommendation": "Enable public access blocks; never use public ACLs for private data.",
      "complexity": "small",
      "tags": [
        "security",
        "s3-public"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "(?:acl\\s*=\\s*[\\\"']public-read(?:-write)?[\\\"']|block_public_(?:acls|policy)\\s*=\\s*false|ignore_public_acls\\s*=\\s*false|restrict_public_buckets\\s*=\\s*false|container_access_type\\s*=\\s*[\\\"'](?:blob|container)[\\\"']|allUsers|allAuthenticatedUsers)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.rds-publicly-accessible",
      "title": "Managed database is publicly accessible",
      "summary": "Managed database is publicly accessible",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "whyItMatters": "Internet-facing databases are high-value targets.",
      "impact": "Credential stuffing and SQLi face the public internet.",
      "recommendation": "Set publicly_accessible = false; use private subnets.",
      "complexity": "small",
      "tags": [
        "security",
        "rds"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "publicly_accessible\\s*=\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.sensitive-output",
      "title": "Credential output is not marked sensitive",
      "summary": "Credential output is not marked sensitive",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Terraform outputs and logs retain secrets when not marked sensitive.",
      "impact": "CI logs and state consumers can leak credentials.",
      "recommendation": "Mark secret outputs sensitive = true.",
      "complexity": "small",
      "tags": [
        "secrets",
        "sensitive-output"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "output\\s+[\\\"'][^\\\"']*(?:password|token|secret|private_key|connection_string)[^\\\"']*[\\\"']\\s*\\{(?![\\s\\S]{0,200}sensitive\\s*=\\s*true)",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.inline-secret",
      "title": "Hardcoded credential literal in Terraform",
      "summary": "Hardcoded credential literal in Terraform",
      "category": "secrets",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Secrets in HCL land in git and state.",
      "impact": "Committed credentials enable account takeover.",
      "recommendation": "Use random_password, secret managers, or CI-injected variables.",
      "complexity": "small",
      "tags": [
        "secrets",
        "inline"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "(?:password|secret_key|access_key|private_key)\\s*=\\s*[\\\"'][^\\\"'$\\n]{8,}[\\\"']",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.iam-admin-wildcard",
      "title": "IAM policy grants full admin Action and Resource",
      "summary": "IAM policy grants full admin Action and Resource",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Full-admin blast radius on any credential theft.",
      "impact": "Compromised principal can control the account.",
      "recommendation": "Use least-privilege actions and resources.",
      "complexity": "small",
      "tags": [
        "security",
        "iam"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "actions\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\][\\s\\S]{0,80}resources\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]|arn:aws:iam::aws:policy/AdministratorAccess",
          "flags": "i"
        },
        "anchors": [
          {
            "pattern": "actions\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]",
            "flags": "i"
          },
          {
            "pattern": "resources\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]",
            "flags": "i"
          },
          {
            "pattern": "arn:aws:iam::aws:policy/AdministratorAccess",
            "flags": "i"
          }
        ],
        "requires": []
      }
    },
    {
      "id": "terraform.storage-unencrypted",
      "title": "Persistent storage explicitly disables encryption",
      "summary": "Persistent storage explicitly disables encryption",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Disk snapshots without encryption expose data at rest.",
      "impact": "Unencrypted volumes and databases increase breach impact.",
      "recommendation": "Set encrypted = true (or storage_encrypted = true).",
      "complexity": "small",
      "tags": [
        "security",
        "encryption"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf",
          "**/*.tf.json"
        ],
        "pattern": {
          "pattern": "(?:encrypted|storage_encrypted)\\s*=\\s*false",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.cloudtrail-bucket-policy-source-arn",
      "title": "CloudTrail bucket writes are not scoped to a trail ARN",
      "summary": "CloudTrail bucket writes are not scoped to a trail ARN",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "A CloudTrail service principal without an aws:SourceArn condition is not bound to an intended trail and weakens confused-deputy protection.",
      "impact": "An unintended CloudTrail trail may be able to write objects through the bucket policy's service-principal grant.",
      "recommendation": "Add an aws:SourceArn condition to the CloudTrail PutObject statement and bind it to the intended trail ARN or a deliberately scoped trail pattern.",
      "complexity": "small",
      "tags": [
        "security",
        "cloudtrail",
        "bucket-policy"
      ],
      "match": {
        "kind": "block-missing-content",
        "files": [
          "**/*.tf"
        ],
        "blockStart": {
          "pattern": "\\bstatement\\s*\\{",
          "flags": "i"
        },
        "trigger": {
          "pattern": "(?:cloudtrail\\.amazonaws\\.com[\\s\\S]*s3:PutObject|s3:PutObject[\\s\\S]*cloudtrail\\.amazonaws\\.com)",
          "flags": "i"
        },
        "anchors": [
          {
            "pattern": "cloudtrail\\.amazonaws\\.com",
            "flags": "i"
          },
          {
            "pattern": "s3:PutObject",
            "flags": "i"
          }
        ],
        "required": {
          "pattern": "aws:SourceArn",
          "flags": "i"
        }
      }
    },
    {
      "id": "terraform.cloudfront-weak-viewer-tls",
      "title": "CloudFront viewer TLS floor permits deprecated protocols",
      "summary": "CloudFront viewer TLS floor permits deprecated protocols",
      "category": "security",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "An explicit TLS 1.0 or 1.1 CloudFront viewer policy keeps deprecated protocol versions available to clients.",
      "impact": "Viewer connections may negotiate legacy TLS instead of the current TLS 1.2 security policy.",
      "recommendation": "Set the CloudFront viewer minimum protocol version to TLSv1.2_2021 and account for intentionally dropping TLS 1.0/1.1 clients.",
      "complexity": "small",
      "tags": [
        "security",
        "cloudfront",
        "tls"
      ],
      "match": {
        "kind": "block-content",
        "files": [
          "**/*.tf"
        ],
        "blockStart": {
          "pattern": "^[ \\t]*(?:viewer_certificate|variable\\s+[\\\"']minimum_protocol_version[\\\"'])\\s*\\{",
          "flags": "im"
        },
        "pattern": {
          "pattern": "^[ \\t]*(?:minimum_protocol_version|default)\\s*=\\s*[\\\"'](?:SSLv3|TLSv1|TLSv1_2016|TLSv1\\.1_2016)[\\\"']",
          "flags": "im"
        },
        "excludes": [
          {
            "pattern": "^[ \\t]*cloudfront_default_certificate\\s*=\\s*true",
            "flags": "im"
          }
        ]
      }
    },
    {
      "id": "terraform.mutable-module",
      "title": "VCS module tracks a mutable branch",
      "summary": "VCS module tracks a mutable branch",
      "category": "supply-chain",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Mutable module refs make applies non-reproducible.",
      "impact": "Two applies can resolve different module code.",
      "recommendation": "Pin modules to commit SHAs or immutable versions.",
      "complexity": "small",
      "tags": [
        "supply-chain",
        "mutable-module"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf"
        ],
        "pattern": {
          "pattern": "source\\s*=\\s*[\\\"'][^\\\"']+\\?ref=(?:main|master|HEAD)[\\\"']",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
