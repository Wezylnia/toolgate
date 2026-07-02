import type { ToolPolicy, ToolRisk } from "../gate/types.js";

export interface PolicyValidationIssue {
  path: string;
  message: string;
}

export interface PolicyValidationResult {
  valid: boolean;
  issues: PolicyValidationIssue[];
}

export class InvalidToolPolicyError extends TypeError {
  readonly issues: PolicyValidationIssue[];

  constructor(issues: PolicyValidationIssue[]) {
    super(`Invalid tool policy: ${issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ")}`);
    this.name = "InvalidToolPolicyError";
    this.issues = issues;
  }
}

const risks: ToolRisk[] = ["read", "write", "external", "destructive"];
const listKeys = [
  "allowedPaths",
  "deniedPaths",
  "allowedDomains",
  "deniedDomains",
  "allowedCommands",
  "deniedCommands"
] as const;
const extractorKeys = ["extractPaths", "extractUrls", "extractCommands"] as const;

export function validatePolicy(policy: unknown, path = "$"): PolicyValidationResult {
  const issues: PolicyValidationIssue[] = [];
  if (!isRecord(policy)) {
    return { valid: false, issues: [{ path, message: "Policy must be an object." }] };
  }

  if (typeof policy.name !== "string" || policy.name.trim().length === 0) {
    issues.push({ path: `${path}.name`, message: "Name must be a non-empty string." });
  }
  if (policy.risk !== undefined && !risks.includes(policy.risk as ToolRisk)) {
    issues.push({ path: `${path}.risk`, message: "Risk must be read, write, external, or destructive." });
  }
  if (policy.requireApproval !== undefined && typeof policy.requireApproval !== "boolean") {
    issues.push({ path: `${path}.requireApproval`, message: "requireApproval must be a boolean." });
  }
  if (policy.approval !== undefined && typeof policy.approval !== "function") {
    issues.push({ path: `${path}.approval`, message: "Approval must be a function." });
  }
  if (policy.approval !== undefined && policy.requireApproval === true && policy.approvalSubject === undefined) {
    issues.push({ path: `${path}.approvalSubject`, message: "approvalSubject is required when approval is configured for an approval-required tool." });
  }
  if (
    policy.approvalSubject !== undefined &&
    typeof policy.approvalSubject !== "string" &&
    typeof policy.approvalSubject !== "function"
  ) {
    issues.push({ path: `${path}.approvalSubject`, message: "approvalSubject must be a non-empty string or function." });
  }
  if (typeof policy.approvalSubject === "string" && policy.approvalSubject.trim().length === 0) {
    issues.push({ path: `${path}.approvalSubject`, message: "approvalSubject must be a non-empty string or function." });
  }
  if (policy.approvalExpiresInMs !== undefined && !isPositiveNumber(policy.approvalExpiresInMs)) {
    issues.push({ path: `${path}.approvalExpiresInMs`, message: "approvalExpiresInMs must be a positive number." });
  }
  if (
    policy.approvalNonceStore !== undefined &&
    (!isRecord(policy.approvalNonceStore) || typeof policy.approvalNonceStore.consume !== "function")
  ) {
    issues.push({ path: `${path}.approvalNonceStore`, message: "approvalNonceStore must provide a consume function." });
  }
  if (policy.policyVersion !== undefined && (typeof policy.policyVersion !== "string" || policy.policyVersion.length === 0)) {
    issues.push({ path: `${path}.policyVersion`, message: "policyVersion must be a non-empty string." });
  }
  if (policy.toolVersion !== undefined && (typeof policy.toolVersion !== "string" || policy.toolVersion.length === 0)) {
    issues.push({ path: `${path}.toolVersion`, message: "toolVersion must be a non-empty string." });
  }
  if (policy.pathRoot !== undefined && (typeof policy.pathRoot !== "string" || policy.pathRoot.length === 0)) {
    issues.push({ path: `${path}.pathRoot`, message: "pathRoot must be a non-empty string." });
  }
  if (policy.exposeRuleDenialDetails !== undefined && typeof policy.exposeRuleDenialDetails !== "boolean") {
    issues.push({ path: `${path}.exposeRuleDenialDetails`, message: "exposeRuleDenialDetails must be a boolean." });
  }
  if (policy.observe !== undefined && typeof policy.observe !== "function") {
    issues.push({ path: `${path}.observe`, message: "Observe must be a function." });
  }
  if (policy.rules !== undefined) {
    if (!Array.isArray(policy.rules)) {
      issues.push({ path: `${path}.rules`, message: "Rules must be an array." });
    } else {
      policy.rules.forEach((rule, index) => {
        const rulePath = `${path}.rules[${index}]`;
        if (!isRecord(rule)) {
          issues.push({ path: rulePath, message: "Rule must be an object." });
          return;
        }
        if (typeof rule.name !== "string" || rule.name.trim().length === 0) {
          issues.push({ path: `${rulePath}.name`, message: "Rule name must be a non-empty string." });
        }
        if (typeof rule.evaluate !== "function") {
          issues.push({ path: `${rulePath}.evaluate`, message: "Rule evaluate must be a function." });
        }
      });
    }
  }

  for (const key of listKeys) {
    validateStringList(policy, key, path, issues);
  }
  for (const key of extractorKeys) {
    if (policy[key] !== undefined && typeof policy[key] !== "function") {
      issues.push({ path: `${path}.${key}`, message: `${key} must be a function.` });
    }
  }

  if (policy.timeoutMs !== undefined && !isPositiveNumber(policy.timeoutMs)) {
    issues.push({ path: `${path}.timeoutMs`, message: "timeoutMs must be a positive number." });
  }
  if (policy.rateLimit !== undefined) {
    validateRateLimit(policy.rateLimit, `${path}.rateLimit`, issues);
  }
  if (policy.audit !== undefined && typeof policy.audit !== "boolean") {
    if (!isRecord(policy.audit) || typeof policy.audit.log !== "function") {
      issues.push({ path: `${path}.audit`, message: "Audit must be a boolean or logger with a log function." });
    }
  }

  return { valid: issues.length === 0, issues };
}

export function validatePolicies(policies: unknown): PolicyValidationResult {
  if (!Array.isArray(policies)) {
    return { valid: false, issues: [{ path: "$.tools", message: "Tools must be an array." }] };
  }

  const issues = policies.flatMap((policy, index) => validatePolicy(policy, `$.tools[${index}]`).issues);
  const names = new Map<string, number>();
  policies.forEach((policy, index) => {
    if (!isRecord(policy) || typeof policy.name !== "string" || policy.name.trim().length === 0) {
      return;
    }
    const previous = names.get(policy.name);
    if (previous !== undefined) {
      issues.push({
        path: `$.tools[${index}].name`,
        message: `Tool name duplicates $.tools[${previous}].name.`
      });
    } else {
      names.set(policy.name, index);
    }
  });
  return { valid: issues.length === 0, issues };
}

export function assertPolicy(policy: unknown): asserts policy is ToolPolicy {
  const result = validatePolicy(policy);
  if (!result.valid) {
    throw new InvalidToolPolicyError(result.issues);
  }
}

function validateStringList(
  policy: Record<string, unknown>,
  key: string,
  path: string,
  issues: PolicyValidationIssue[]
): void {
  const value = policy[key];
  if (value === undefined) {
    return;
  }
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    issues.push({ path: `${path}.${key}`, message: `${key} must contain non-empty strings.` });
  }
}

function validateRateLimit(value: unknown, path: string, issues: PolicyValidationIssue[]): void {
  if (!isRecord(value)) {
    issues.push({ path, message: "rateLimit must be an object." });
    return;
  }
  if (!Number.isInteger(value.max) || !isPositiveNumber(value.max)) {
    issues.push({ path: `${path}.max`, message: "max must be a positive integer." });
  }
  if (!isPositiveNumber(value.windowMs)) {
    issues.push({ path: `${path}.windowMs`, message: "windowMs must be a positive number." });
  }
  if (value.key !== undefined && typeof value.key !== "function") {
    issues.push({ path: `${path}.key`, message: "key must be a function." });
  }
  if (value.namespace !== undefined && (typeof value.namespace !== "string" || value.namespace.length === 0)) {
    issues.push({ path: `${path}.namespace`, message: "namespace must be a non-empty string." });
  }
  if (value.store !== undefined && (!isRecord(value.store) || typeof value.store.consume !== "function")) {
    issues.push({ path: `${path}.store`, message: "store must provide a consume function." });
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isPositiveNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}
