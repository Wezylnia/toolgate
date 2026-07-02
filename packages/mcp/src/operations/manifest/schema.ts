import type { PolicyManifest } from "./manifest.js";

export interface ManifestValidationIssue {
  path: string;
  message: string;
}

export interface ManifestValidationResult {
  valid: boolean;
  issues: ManifestValidationIssue[];
}

export const policyManifestSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://toolgatekit.dev/schemas/v1/policy-manifest.schema.json",
  title: "ToolGateKit Policy Manifest",
  type: "object",
  additionalProperties: false,
  properties: {
    schemaVersion: { const: "1.0" },
    name: { type: "string" },
    tools: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "risk", "requiresApproval", "audit", "redact"],
        properties: {
          name: { type: "string", minLength: 1 },
          description: { type: "string" },
          profile: { type: "string", minLength: 1 },
          profileDefaults: { type: "object" },
          policyVersion: { type: "string", minLength: 1 },
          toolVersion: { type: "string", minLength: 1 },
          risk: {
            type: "string",
            enum: ["read", "write", "external", "destructive"]
          },
          requiresApproval: { type: "boolean" },
          allowedPaths: stringArraySchema(),
          deniedPaths: stringArraySchema(),
          pathRoot: { type: "string", minLength: 1 },
          allowedDomains: stringArraySchema(),
          deniedDomains: stringArraySchema(),
          allowedCommands: stringArraySchema(),
          deniedCommands: stringArraySchema(),
          customRules: stringArraySchema(),
          rateLimit: {
            type: "object",
            additionalProperties: false,
            required: ["max", "windowMs"],
            properties: {
              max: { type: "integer", minimum: 1 },
              windowMs: { type: "number", minimum: 1 },
              keyed: { type: "boolean" },
              namespace: { type: "string", minLength: 1 }
            }
          },
          audit: { type: "boolean" },
          redact: { type: "boolean" },
          exposesPolicyDenialDetails: { type: "boolean" },
          exposesRuleDenialDetails: { type: "boolean" },
          timeoutMs: { type: "number", minimum: 1 },
          metadata: { type: "object" }
        }
      }
    }
  },
  required: ["schemaVersion", "tools"]
} as const;

export function validateManifest(manifest: unknown): ManifestValidationResult {
  const issues: ManifestValidationIssue[] = [];

  if (!isRecord(manifest)) {
    return invalid("$", "Manifest must be an object.");
  }

  for (const key of Object.keys(manifest)) {
    if (!["schemaVersion", "name", "tools"].includes(key)) {
      issues.push({ path: `$.${key}`, message: "Unknown manifest field." });
    }
  }

  if (manifest.schemaVersion !== "1.0") {
    issues.push({ path: "$.schemaVersion", message: "schemaVersion must be '1.0'." });
  }

  if ("name" in manifest && typeof manifest.name !== "string") {
    issues.push({ path: "$.name", message: "Name must be a string." });
  }

  if (!Array.isArray(manifest.tools)) {
    issues.push({ path: "$.tools", message: "Tools must be an array." });
    return { valid: issues.length === 0, issues };
  }

  const names = new Map<string, number>();
  manifest.tools.forEach((tool, index) => {
    validateManifestTool(tool, `$.tools[${index}]`, issues);
    if (isRecord(tool) && typeof tool.name === "string" && tool.name.length > 0) {
      const previous = names.get(tool.name);
      if (previous !== undefined) {
        issues.push({ path: `$.tools[${index}].name`, message: `Tool name duplicates $.tools[${previous}].name.` });
      } else {
        names.set(tool.name, index);
      }
    }
  });

  return {
    valid: issues.length === 0,
    issues
  };
}

function validateManifestTool(
  tool: unknown,
  path: string,
  issues: ManifestValidationIssue[]
): void {
  if (!isRecord(tool)) {
    issues.push({ path, message: "Tool must be an object." });
    return;
  }

  const knownKeys = new Set([
    "name", "description", "profile", "profileDefaults", "policyVersion", "toolVersion", "risk", "requiresApproval", "allowedPaths", "deniedPaths", "pathRoot",
    "allowedDomains", "deniedDomains", "allowedCommands", "deniedCommands", "customRules",
    "rateLimit", "audit", "redact", "exposesPolicyDenialDetails", "exposesRuleDenialDetails", "timeoutMs", "metadata"
  ]);
  for (const key of Object.keys(tool)) {
    if (!knownKeys.has(key)) issues.push({ path: `${path}.${key}`, message: "Unknown manifest tool field." });
  }

  if (typeof tool.name !== "string" || tool.name.length === 0) {
    issues.push({ path: `${path}.name`, message: "Tool name must be a non-empty string." });
  }
  if (tool.description !== undefined && typeof tool.description !== "string") {
    issues.push({ path: `${path}.description`, message: "Description must be a string." });
  }
  validateOptionalString(tool, "profile", path, issues);
  if (tool.profileDefaults !== undefined && !isRecord(tool.profileDefaults)) {
    issues.push({ path: `${path}.profileDefaults`, message: "profileDefaults must be an object." });
  }
  validateOptionalString(tool, "policyVersion", path, issues);
  validateOptionalString(tool, "toolVersion", path, issues);
  validateOptionalString(tool, "pathRoot", path, issues);

  if (!["read", "write", "external", "destructive"].includes(String(tool.risk))) {
    issues.push({ path: `${path}.risk`, message: "Tool risk is invalid." });
  }

  if (typeof tool.requiresApproval !== "boolean") {
    issues.push({ path: `${path}.requiresApproval`, message: "requiresApproval must be a boolean." });
  }

  if (typeof tool.audit !== "boolean") {
    issues.push({ path: `${path}.audit`, message: "audit must be a boolean." });
  }
  if (typeof tool.redact !== "boolean") {
    issues.push({ path: `${path}.redact`, message: "redact must be a boolean." });
  }
  validateOptionalBoolean(tool, "exposesPolicyDenialDetails", path, issues);
  validateOptionalBoolean(tool, "exposesRuleDenialDetails", path, issues);

  validateOptionalStringArray(tool, "allowedPaths", path, issues);
  validateOptionalStringArray(tool, "deniedPaths", path, issues);
  validateOptionalStringArray(tool, "allowedDomains", path, issues);
  validateOptionalStringArray(tool, "deniedDomains", path, issues);
  validateOptionalStringArray(tool, "allowedCommands", path, issues);
  validateOptionalStringArray(tool, "deniedCommands", path, issues);
  validateOptionalStringArray(tool, "customRules", path, issues);

  if (tool.timeoutMs !== undefined && !isPositiveNumber(tool.timeoutMs)) {
    issues.push({ path: `${path}.timeoutMs`, message: "timeoutMs must be a positive number." });
  }

  if (tool.rateLimit !== undefined) {
    validateRateLimit(tool.rateLimit, `${path}.rateLimit`, issues);
  }
  if (tool.metadata !== undefined && !isRecord(tool.metadata)) {
    issues.push({ path: `${path}.metadata`, message: "metadata must be an object." });
  }
}

function validateOptionalBoolean(
  object: Record<string, unknown>,
  key: string,
  path: string,
  issues: ManifestValidationIssue[]
): void {
  if (object[key] !== undefined && typeof object[key] !== "boolean") {
    issues.push({ path: `${path}.${key}`, message: `${key} must be a boolean.` });
  }
}

function validateOptionalString(
  object: Record<string, unknown>,
  key: string,
  path: string,
  issues: ManifestValidationIssue[]
): void {
  if (object[key] !== undefined && (typeof object[key] !== "string" || object[key].length === 0)) {
    issues.push({ path: `${path}.${key}`, message: `${key} must be a non-empty string.` });
  }
}

function validateOptionalStringArray(
  object: Record<string, unknown>,
  key: keyof PolicyManifest["tools"][number],
  path: string,
  issues: ManifestValidationIssue[]
): void {
  if (object[key] === undefined) {
    return;
  }

  const value = object[key];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    issues.push({ path: `${path}.${key}`, message: `${key} must be an array of non-empty strings.` });
  }
}

function validateRateLimit(
  value: unknown,
  path: string,
  issues: ManifestValidationIssue[]
): void {
  if (!isRecord(value)) {
    issues.push({ path, message: "rateLimit must be an object." });
    return;
  }

  for (const key of Object.keys(value)) {
    if (!["max", "windowMs", "keyed", "namespace"].includes(key)) {
      issues.push({ path: `${path}.${key}`, message: "Unknown rate-limit field." });
    }
  }

  if (!Number.isInteger(value.max) || !isPositiveNumber(value.max)) {
    issues.push({ path: `${path}.max`, message: "rateLimit.max must be a positive number." });
  }

  if (!isPositiveNumber(value.windowMs)) {
    issues.push({ path: `${path}.windowMs`, message: "rateLimit.windowMs must be a positive number." });
  }
  if (value.keyed !== undefined && typeof value.keyed !== "boolean") {
    issues.push({ path: `${path}.keyed`, message: "rateLimit.keyed must be a boolean." });
  }
  if (value.namespace !== undefined && (typeof value.namespace !== "string" || value.namespace.length === 0)) {
    issues.push({ path: `${path}.namespace`, message: "rateLimit.namespace must be a non-empty string." });
  }
}

function stringArraySchema(): { type: "array"; items: { type: "string"; minLength: 1 } } {
  return {
    type: "array",
    items: { type: "string", minLength: 1 }
  };
}

function invalid(path: string, message: string): ManifestValidationResult {
  return {
    valid: false,
    issues: [{ path, message }]
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isPositiveNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

export { policyConfigSchema } from "../../policies/config/configSchema.js";
