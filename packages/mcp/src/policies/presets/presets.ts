import type { ToolPolicy } from "../../core/gate/types.js";

export function readOnlyFilesystemPolicy(
  policy: Omit<ToolPolicy, "risk" | "requireApproval">
): ToolPolicy {
  return {
    risk: "read",
    deniedPaths: [".env", "secrets/**", "node_modules/**", ...(policy.deniedPaths ?? [])],
    redact: true,
    ...policy
  };
}

export function destructiveFilesystemPolicy(
  policy: Omit<ToolPolicy, "risk" | "requireApproval">
): ToolPolicy {
  return {
    risk: "destructive",
    requireApproval: true,
    deniedPaths: [".env", "secrets/**", "node_modules/**", ...(policy.deniedPaths ?? [])],
    redact: true,
    ...policy
  };
}

export function externalApiPolicy(policy: Omit<ToolPolicy, "risk">): ToolPolicy {
  return {
    risk: "external",
    timeoutMs: 10_000,
    redact: true,
    ...policy
  };
}
