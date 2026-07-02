import type { ToolPolicy } from "../gate/types.js";

export interface PolicyManifest {
  schemaVersion: "1.0";
  name?: string;
  tools: PolicyManifestTool[];
}

export interface PolicyManifestTool {
  name: string;
  description?: string;
  risk: string;
  policyVersion?: string;
  toolVersion?: string;
  requiresApproval: boolean;
  allowedPaths?: string[];
  deniedPaths?: string[];
  pathRoot?: string;
  allowedDomains?: string[];
  deniedDomains?: string[];
  allowedCommands?: string[];
  deniedCommands?: string[];
  customRules?: string[];
  rateLimit?: {
    max: number;
    windowMs: number;
    keyed?: boolean;
    namespace?: string;
  };
  audit: boolean;
  redact: boolean;
  exposesPolicyDenialDetails?: boolean;
  exposesRuleDenialDetails?: boolean;
  timeoutMs?: number;
  metadata?: Record<string, unknown>;
}

export function createManifest(
  policies: ToolPolicy[],
  options: { name?: string } = {}
): PolicyManifest {
  return {
    schemaVersion: "1.0",
    name: options.name,
    tools: policies.map((policy) => ({
      name: policy.name,
      description: policy.description,
      risk: policy.risk ?? "read",
      policyVersion: policy.policyVersion,
      toolVersion: policy.toolVersion,
      requiresApproval: policy.requireApproval ?? false,
      allowedPaths: policy.allowedPaths,
      deniedPaths: policy.deniedPaths,
      pathRoot: policy.pathRoot,
      allowedDomains: policy.allowedDomains,
      deniedDomains: policy.deniedDomains,
      allowedCommands: policy.allowedCommands,
      deniedCommands: policy.deniedCommands,
      customRules: policy.rules?.map((rule) => rule.name),
      rateLimit: policy.rateLimit ? {
        max: policy.rateLimit.max,
        windowMs: policy.rateLimit.windowMs,
        keyed: Boolean(policy.rateLimit.key),
        namespace: policy.rateLimit.namespace
      } : undefined,
      audit: Boolean(policy.audit),
      redact: Boolean(policy.redact),
      exposesPolicyDenialDetails: policy.exposePolicyDenialDetails,
      exposesRuleDenialDetails: policy.exposeRuleDenialDetails,
      timeoutMs: policy.timeoutMs,
      metadata: policy.metadata
    }))
  };
}
