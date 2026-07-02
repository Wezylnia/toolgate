import type { ToolRisk } from "../gate/types.js";
import type { PolicyManifest, PolicyManifestTool } from "../manifest/manifest.js";
import type { PolicyValidationIssue, PolicyValidationResult } from "./validatePolicy.js";

export interface PolicyConfig {
  schemaVersion: "1.0";
  name?: string;
  tools: PolicyConfigTool[];
}

export interface PolicyConfigTool {
  name: string;
  description?: string;
  policyVersion?: string;
  toolVersion?: string;
  risk?: ToolRisk;
  requireApproval?: boolean;
  allowedPaths?: string[];
  deniedPaths?: string[];
  pathRoot?: string;
  allowedDomains?: string[];
  deniedDomains?: string[];
  allowedCommands?: string[];
  deniedCommands?: string[];
  customRules?: string[];
  rateLimit?: { max: number; windowMs: number; keyed?: boolean; namespace?: string };
  timeoutMs?: number;
  redact?: boolean;
  audit?: boolean;
  metadata?: Record<string, unknown>;
}

const stringArray = { type: "array", items: { type: "string", minLength: 1 } } as const;

export const policyConfigSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://toolgatekit.dev/schemas/v1/policy-config.schema.json",
  title: "ToolGateKit Policy Config",
  type: "object",
  additionalProperties: false,
  required: ["schemaVersion", "tools"],
  properties: {
    schemaVersion: { const: "1.0" },
    name: { type: "string" },
    tools: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name"],
        properties: {
          name: { type: "string", minLength: 1 },
          description: { type: "string" },
          policyVersion: { type: "string", minLength: 1 },
          toolVersion: { type: "string", minLength: 1 },
          risk: { enum: ["read", "write", "external", "destructive"] },
          requireApproval: { type: "boolean" },
          allowedPaths: stringArray,
          deniedPaths: stringArray,
          pathRoot: { type: "string", minLength: 1 },
          allowedDomains: stringArray,
          deniedDomains: stringArray,
          allowedCommands: stringArray,
          deniedCommands: stringArray,
          customRules: stringArray,
          rateLimit: {
            type: "object",
            additionalProperties: false,
            required: ["max", "windowMs"],
            properties: {
              max: { type: "integer", minimum: 1 },
              windowMs: { type: "number", exclusiveMinimum: 0 },
              keyed: { type: "boolean" },
              namespace: { type: "string", minLength: 1 }
            }
          },
          timeoutMs: { type: "number", exclusiveMinimum: 0 },
          redact: { type: "boolean" },
          audit: { type: "boolean" },
          metadata: { type: "object" }
        }
      }
    }
  }
} as const;

const toolKeys = new Set([
  "name", "description", "policyVersion", "toolVersion", "risk", "requireApproval", "allowedPaths", "deniedPaths", "pathRoot",
  "allowedDomains", "deniedDomains", "allowedCommands", "deniedCommands", "customRules",
  "rateLimit", "timeoutMs", "redact", "audit", "metadata"
]);
const listKeys = [
  "allowedPaths", "deniedPaths", "allowedDomains", "deniedDomains",
  "allowedCommands", "deniedCommands", "customRules"
] as const;

export function validatePolicyConfig(value: unknown): PolicyValidationResult {
  const issues: PolicyValidationIssue[] = [];
  if (!isRecord(value)) return invalid("$", "Config must be an object.");
  for (const key of Object.keys(value)) {
    if (!["schemaVersion", "name", "tools"].includes(key)) {
      issues.push({ path: `$.${key}`, message: "Unknown config field." });
    }
  }
  if (value.schemaVersion !== "1.0") {
    issues.push({ path: "$.schemaVersion", message: "schemaVersion must be '1.0'." });
  }
  if (value.name !== undefined && typeof value.name !== "string") {
    issues.push({ path: "$.name", message: "Name must be a string." });
  }
  if (!Array.isArray(value.tools)) {
    issues.push({ path: "$.tools", message: "Tools must be an array." });
    return { valid: false, issues };
  }

  const names = new Map<string, number>();
  value.tools.forEach((tool, index) => validateConfigTool(tool, index, issues, names));
  return { valid: issues.length === 0, issues };
}

export function createManifestFromConfig(config: PolicyConfig): PolicyManifest {
  return {
    schemaVersion: "1.0",
    name: config.name,
    tools: config.tools.map((tool): PolicyManifestTool => ({
      name: tool.name,
      description: tool.description,
      policyVersion: tool.policyVersion,
      toolVersion: tool.toolVersion,
      risk: tool.risk ?? "read",
      requiresApproval: tool.requireApproval ?? false,
      allowedPaths: tool.allowedPaths,
      deniedPaths: tool.deniedPaths,
      pathRoot: tool.pathRoot,
      allowedDomains: tool.allowedDomains,
      deniedDomains: tool.deniedDomains,
      allowedCommands: tool.allowedCommands,
      deniedCommands: tool.deniedCommands,
      customRules: tool.customRules,
      rateLimit: tool.rateLimit,
      audit: tool.audit ?? false,
      redact: tool.redact ?? false,
      timeoutMs: tool.timeoutMs,
      metadata: tool.metadata
    }))
  };
}

function validateConfigTool(
  value: unknown,
  index: number,
  issues: PolicyValidationIssue[],
  names: Map<string, number>
): void {
  const path = `$.tools[${index}]`;
  if (!isRecord(value)) {
    issues.push({ path, message: "Tool must be an object." });
    return;
  }
  for (const key of Object.keys(value)) {
    if (!toolKeys.has(key)) issues.push({ path: `${path}.${key}`, message: "Unknown policy field." });
  }
  if (typeof value.name !== "string" || value.name.trim().length === 0) {
    issues.push({ path: `${path}.name`, message: "Name must be a non-empty string." });
  } else if (names.has(value.name)) {
    issues.push({ path: `${path}.name`, message: `Tool name duplicates $.tools[${names.get(value.name)}].name.` });
  } else {
    names.set(value.name, index);
  }
  if (value.risk !== undefined && !["read", "write", "external", "destructive"].includes(String(value.risk))) {
    issues.push({ path: `${path}.risk`, message: "Risk is invalid." });
  }
  for (const key of ["policyVersion", "toolVersion", "pathRoot"] as const) {
    if (value[key] !== undefined && (typeof value[key] !== "string" || value[key].length === 0)) {
      issues.push({ path: `${path}.${key}`, message: `${key} must be a non-empty string.` });
    }
  }
  for (const key of listKeys) validateStringList(value, key, path, issues);
  for (const key of ["requireApproval", "redact", "audit"] as const) {
    if (value[key] !== undefined && typeof value[key] !== "boolean") {
      issues.push({ path: `${path}.${key}`, message: `${key} must be a boolean.` });
    }
  }
  if (value.timeoutMs !== undefined && !isPositive(value.timeoutMs)) {
    issues.push({ path: `${path}.timeoutMs`, message: "timeoutMs must be a positive number." });
  }
  if (value.rateLimit !== undefined) validateRateLimit(value.rateLimit, `${path}.rateLimit`, issues);
  if (value.metadata !== undefined && !isRecord(value.metadata)) {
    issues.push({ path: `${path}.metadata`, message: "metadata must be an object." });
  }
}

function validateStringList(value: Record<string, unknown>, key: string, path: string, issues: PolicyValidationIssue[]): void {
  if (value[key] === undefined) return;
  if (!Array.isArray(value[key]) || value[key].some((item) => typeof item !== "string" || item.length === 0)) {
    issues.push({ path: `${path}.${key}`, message: `${key} must contain non-empty strings.` });
  }
}

function validateRateLimit(value: unknown, path: string, issues: PolicyValidationIssue[]): void {
  if (!isRecord(value)) {
    issues.push({ path, message: "rateLimit must be an object." });
    return;
  }
  for (const key of Object.keys(value)) {
    if (!["max", "windowMs", "keyed", "namespace"].includes(key)) issues.push({ path: `${path}.${key}`, message: "Unknown rate-limit field." });
  }
  if (!Number.isInteger(value.max) || !isPositive(value.max)) issues.push({ path: `${path}.max`, message: "max must be a positive integer." });
  if (!isPositive(value.windowMs)) issues.push({ path: `${path}.windowMs`, message: "windowMs must be a positive number." });
  if (value.keyed !== undefined && typeof value.keyed !== "boolean") issues.push({ path: `${path}.keyed`, message: "keyed must be a boolean." });
  if (value.namespace !== undefined && (typeof value.namespace !== "string" || value.namespace.length === 0)) issues.push({ path: `${path}.namespace`, message: "namespace must be a non-empty string." });
}

function invalid(path: string, message: string): PolicyValidationResult {
  return { valid: false, issues: [{ path, message }] };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isPositive(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}
