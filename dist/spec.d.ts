import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    anchors?: MatchExpression[];
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface BlockContentMatch {
    kind: "block-content";
    files: string[];
    blockStart: MatchExpression;
    pattern: MatchExpression;
    excludes?: MatchExpression[];
}
interface BlockMissingContentMatch {
    kind: "block-missing-content";
    files: string[];
    blockStart: MatchExpression;
    trigger: MatchExpression;
    anchors?: MatchExpression[];
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | BlockContentMatch | BlockMissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "terraform";
    readonly displayName: "Terraform";
    readonly description: "Reviews Terraform for public exposure, secrets in HCL, encryption, and supply-chain pinning.";
    readonly files: ["**/*.tf", "**/*.tf.json"];
    readonly rules: [{
        readonly id: "terraform.public-ingress";
        readonly title: "Security rule exposes a sensitive port to the world";
        readonly summary: "Security rule exposes a sensitive port to the world";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Internet-wide SSH/RDP/DB access is a primary cloud breach path.";
        readonly impact: "Attackers can scan and brute-force management and data-plane ports.";
        readonly recommendation: "Restrict ingress to trusted networks; use SSM/IAP instead of world SSH.";
        readonly complexity: "small";
        readonly tags: ["security", "public-ingress"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\\\"']0\\.0\\.0\\.0/0[\\\"'][^\\]]*\\][\\s\\S]{0,80}from_port\\s*=\\s*(?:22|3389|3306|5432|6379|27017|9200|11211)\\b";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\\\"']0\\.0\\.0\\.0/0[\\\"'][^\\]]*\\]";
                readonly flags: "i";
            }, {
                readonly pattern: "from_port\\s*=\\s*(?:22|3389|3306|5432|6379|27017|9200|11211)\\b";
                readonly flags: "i";
            }];
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.s3-public-acl";
        readonly title: "Object storage is configured for public access";
        readonly summary: "Object storage is configured for public access";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Public buckets and containers leak data at scale.";
        readonly impact: "World-readable object storage exposes private data.";
        readonly recommendation: "Enable public access blocks; never use public ACLs for private data.";
        readonly complexity: "small";
        readonly tags: ["security", "s3-public"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "(?:acl\\s*=\\s*[\\\"']public-read(?:-write)?[\\\"']|block_public_(?:acls|policy)\\s*=\\s*false|ignore_public_acls\\s*=\\s*false|restrict_public_buckets\\s*=\\s*false|container_access_type\\s*=\\s*[\\\"'](?:blob|container)[\\\"']|allUsers|allAuthenticatedUsers)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.rds-publicly-accessible";
        readonly title: "Managed database is publicly accessible";
        readonly summary: "Managed database is publicly accessible";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "high";
        readonly whyItMatters: "Internet-facing databases are high-value targets.";
        readonly impact: "Credential stuffing and SQLi face the public internet.";
        readonly recommendation: "Set publicly_accessible = false; use private subnets.";
        readonly complexity: "small";
        readonly tags: ["security", "rds"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "publicly_accessible\\s*=\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.sensitive-output";
        readonly title: "Credential output is not marked sensitive";
        readonly summary: "Credential output is not marked sensitive";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Terraform outputs and logs retain secrets when not marked sensitive.";
        readonly impact: "CI logs and state consumers can leak credentials.";
        readonly recommendation: "Mark secret outputs sensitive = true.";
        readonly complexity: "small";
        readonly tags: ["secrets", "sensitive-output"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "output\\s+[\\\"'][^\\\"']*(?:password|token|secret|private_key|connection_string)[^\\\"']*[\\\"']\\s*\\{(?![\\s\\S]{0,200}sensitive\\s*=\\s*true)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.inline-secret";
        readonly title: "Hardcoded credential literal in Terraform";
        readonly summary: "Hardcoded credential literal in Terraform";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Secrets in HCL land in git and state.";
        readonly impact: "Committed credentials enable account takeover.";
        readonly recommendation: "Use random_password, secret managers, or CI-injected variables.";
        readonly complexity: "small";
        readonly tags: ["secrets", "inline"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "(?:password|secret_key|access_key|private_key)\\s*=\\s*[\\\"'][^\\\"'$\\n]{8,}[\\\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.iam-admin-wildcard";
        readonly title: "IAM policy grants full admin Action and Resource";
        readonly summary: "IAM policy grants full admin Action and Resource";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Full-admin blast radius on any credential theft.";
        readonly impact: "Compromised principal can control the account.";
        readonly recommendation: "Use least-privilege actions and resources.";
        readonly complexity: "small";
        readonly tags: ["security", "iam"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "actions\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\][\\s\\S]{0,80}resources\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]|arn:aws:iam::aws:policy/AdministratorAccess";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "actions\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]";
                readonly flags: "i";
            }, {
                readonly pattern: "resources\\s*=\\s*\\[\\s*[\\\"']\\*[\\\"']\\s*\\]";
                readonly flags: "i";
            }, {
                readonly pattern: "arn:aws:iam::aws:policy/AdministratorAccess";
                readonly flags: "i";
            }];
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.storage-unencrypted";
        readonly title: "Persistent storage explicitly disables encryption";
        readonly summary: "Persistent storage explicitly disables encryption";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Disk snapshots without encryption expose data at rest.";
        readonly impact: "Unencrypted volumes and databases increase breach impact.";
        readonly recommendation: "Set encrypted = true (or storage_encrypted = true).";
        readonly complexity: "small";
        readonly tags: ["security", "encryption"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "(?:encrypted|storage_encrypted)\\s*=\\s*false";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.cloudtrail-bucket-policy-source-arn";
        readonly title: "CloudTrail bucket writes are not scoped to a trail ARN";
        readonly summary: "CloudTrail bucket writes are not scoped to a trail ARN";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "A CloudTrail service principal without an aws:SourceArn condition is not bound to an intended trail and weakens confused-deputy protection.";
        readonly impact: "An unintended CloudTrail trail may be able to write objects through the bucket policy's service-principal grant.";
        readonly recommendation: "Add an aws:SourceArn condition to the CloudTrail PutObject statement and bind it to the intended trail ARN or a deliberately scoped trail pattern.";
        readonly complexity: "small";
        readonly tags: ["security", "cloudtrail", "bucket-policy"];
        readonly match: {
            readonly kind: "block-missing-content";
            readonly files: ["**/*.tf"];
            readonly blockStart: {
                readonly pattern: "\\bstatement\\s*\\{";
                readonly flags: "i";
            };
            readonly trigger: {
                readonly pattern: "(?:cloudtrail\\.amazonaws\\.com[\\s\\S]*s3:PutObject|s3:PutObject[\\s\\S]*cloudtrail\\.amazonaws\\.com)";
                readonly flags: "i";
            };
            readonly anchors: [{
                readonly pattern: "cloudtrail\\.amazonaws\\.com";
                readonly flags: "i";
            }, {
                readonly pattern: "s3:PutObject";
                readonly flags: "i";
            }];
            readonly required: {
                readonly pattern: "aws:SourceArn";
                readonly flags: "i";
            };
        };
    }, {
        readonly id: "terraform.cloudfront-weak-viewer-tls";
        readonly title: "CloudFront viewer TLS floor permits deprecated protocols";
        readonly summary: "CloudFront viewer TLS floor permits deprecated protocols";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "An explicit TLS 1.0 or 1.1 CloudFront viewer policy keeps deprecated protocol versions available to clients.";
        readonly impact: "Viewer connections may negotiate legacy TLS instead of the current TLS 1.2 security policy.";
        readonly recommendation: "Set the CloudFront viewer minimum protocol version to TLSv1.2_2021 and account for intentionally dropping TLS 1.0/1.1 clients.";
        readonly complexity: "small";
        readonly tags: ["security", "cloudfront", "tls"];
        readonly match: {
            readonly kind: "block-content";
            readonly files: ["**/*.tf"];
            readonly blockStart: {
                readonly pattern: "^[ \\t]*(?:viewer_certificate|variable\\s+[\\\"']minimum_protocol_version[\\\"'])\\s*\\{";
                readonly flags: "im";
            };
            readonly pattern: {
                readonly pattern: "^[ \\t]*(?:minimum_protocol_version|default)\\s*=\\s*[\\\"'](?:SSLv3|TLSv1|TLSv1_2016|TLSv1\\.1_2016)[\\\"']";
                readonly flags: "im";
            };
            readonly excludes: [{
                readonly pattern: "^[ \\t]*cloudfront_default_certificate\\s*=\\s*true";
                readonly flags: "im";
            }];
        };
    }, {
        readonly id: "terraform.mutable-module";
        readonly title: "VCS module tracks a mutable branch";
        readonly summary: "VCS module tracks a mutable branch";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Mutable module refs make applies non-reproducible.";
        readonly impact: "Two applies can resolve different module code.";
        readonly recommendation: "Pin modules to commit SHAs or immutable versions.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-module"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf"];
            readonly pattern: {
                readonly pattern: "source\\s*=\\s*[\\\"'][^\\\"']+\\?ref=(?:main|master|HEAD)[\\\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
