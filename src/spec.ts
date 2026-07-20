import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "terraform",
  "displayName": "Terraform",
  "description": "Reviews Terraform for public exposure, mutable modules, and output leaks.",
  "files": [
    "**/*.tf",
    "**/*.tf.json"
  ],
  "rules": [
    {
      "id": "terraform.public-ingress",
      "title": "Security rule exposes a service globally",
      "summary": "Security rule exposes a service globally",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Security rule exposes a service globally weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Restrict ingress to trusted networks and required ports.",
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
          "pattern": "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\"']0\\.0\\.0\\.0\\/0",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "terraform.mutable-module",
      "title": "VCS module tracks a mutable branch",
      "summary": "VCS module tracks a mutable branch",
      "category": "supply-chain",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "VCS module tracks a mutable branch weakens an important supply-chain boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Pin VCS modules to immutable commits.",
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
          "pattern": "source\\s*=\\s*[\"'][^\"']+\\?ref=(?:main|master|HEAD)[\"']",
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
      "whyItMatters": "Credential output is not marked sensitive weakens an important secrets boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Mark credential outputs sensitive or avoid exporting them.",
      "complexity": "small",
      "tags": [
        "secrets",
        "sensitive-output"
      ],
      "match": {
        "kind": "content",
        "files": [
          "**/*.tf"
        ],
        "pattern": {
          "pattern": "output\\s+[\"'][^\"']*(?:password|token|secret)[^\"']*[\"']\\s*\\{(?![\\s\\S]{0,160}sensitive\\s*=\\s*true)",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
