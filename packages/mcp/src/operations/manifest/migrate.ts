import type { PolicyManifest } from "./manifest.js";
import {
  validateManifest,
  type ManifestValidationIssue
} from "./schema.js";

export class InvalidPolicyManifestError extends TypeError {
  readonly issues: ManifestValidationIssue[];

  constructor(issues: ManifestValidationIssue[]) {
    super(`Invalid policy manifest: ${issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")}`);
    this.name = "InvalidPolicyManifestError";
    this.issues = issues;
  }
}

export function migrateManifest(value: unknown): PolicyManifest {
  const candidate = isRecord(value) && value.schemaVersion === undefined
    ? {
        ...value,
        schemaVersion: "1.0",
        tools: Array.isArray(value.tools)
          ? value.tools.map((tool) => isRecord(tool) && tool.redact === undefined
            ? { ...tool, redact: false }
            : tool)
          : value.tools
      }
    : value;
  const result = validateManifest(candidate);
  if (!result.valid) {
    throw new InvalidPolicyManifestError(result.issues);
  }
  return candidate as PolicyManifest;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
