import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
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
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
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
    readonly description: "Reviews Terraform for public exposure, mutable modules, and output leaks.";
    readonly files: ["**/*.tf", "**/*.tf.json"];
    readonly rules: [{
        readonly id: "terraform.public-ingress";
        readonly title: "Security rule exposes a service globally";
        readonly summary: "Security rule exposes a service globally";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Security rule exposes a service globally weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Restrict ingress to trusted networks and required ports.";
        readonly complexity: "small";
        readonly tags: ["security", "public-ingress"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf", "**/*.tf.json"];
            readonly pattern: {
                readonly pattern: "(?:cidr_blocks|source_ranges)\\s*=\\s*\\[[^\\]]*[\"']0\\.0\\.0\\.0\\/0";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "terraform.mutable-module";
        readonly title: "VCS module tracks a mutable branch";
        readonly summary: "VCS module tracks a mutable branch";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "VCS module tracks a mutable branch weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin VCS modules to immutable commits.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-module"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf"];
            readonly pattern: {
                readonly pattern: "source\\s*=\\s*[\"'][^\"']+\\?ref=(?:main|master|HEAD)[\"']";
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
        readonly whyItMatters: "Credential output is not marked sensitive weakens an important secrets boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Mark credential outputs sensitive or avoid exporting them.";
        readonly complexity: "small";
        readonly tags: ["secrets", "sensitive-output"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.tf"];
            readonly pattern: {
                readonly pattern: "output\\s+[\"'][^\"']*(?:password|token|secret)[^\"']*[\"']\\s*\\{(?![\\s\\S]{0,160}sensitive\\s*=\\s*true)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
