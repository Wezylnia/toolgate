import type { PolicyConfig } from "./configSchema.js";
import { validatePolicyConfig } from "./configSchema.js";
import { InvalidToolPolicyError } from "../validation/validatePolicy.js";

export function migratePolicyConfig(value: unknown): PolicyConfig {
  const candidate = isRecord(value) && value.schemaVersion === undefined
    ? { ...value, schemaVersion: "1.0" }
    : value;
  const result = validatePolicyConfig(candidate);
  if (!result.valid) throw new InvalidToolPolicyError(result.issues);
  return candidate as PolicyConfig;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
