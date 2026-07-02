import type { ToolPolicy, ToolRisk } from "../../core/gate/types.js";

export type ProfileOverrideField =
  | "risk"
  | "requireApproval"
  | "audit"
  | "redact"
  | "pathRoot"
  | "timeoutMs"
  | "rateLimit";

export type PolicyProfileDefaults = Partial<Omit<ToolPolicy, "name" | "profile">>;

export interface PolicyProfile {
  name: string;
  defaults: PolicyProfileDefaults;
  allowToolOverrides?: ProfileOverrideField[];
  metadata?: Record<string, unknown>;
}

export class PolicyProfileError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "PolicyProfileError";
  }
}

export function definePolicyProfile(
  name: string,
  defaults: PolicyProfileDefaults,
  options: { allowToolOverrides?: ProfileOverrideField[]; metadata?: Record<string, unknown> } = {}
): PolicyProfile {
  if (name.trim().length === 0) throw new PolicyProfileError("Policy profile name must be non-empty.");
  return {
    name,
    defaults: cloneDefaults(defaults),
    allowToolOverrides: options.allowToolOverrides ? [...options.allowToolOverrides] : undefined,
    metadata: options.metadata ? { ...options.metadata } : undefined
  };
}

export function applyPolicyProfile(profile: PolicyProfile, policy: ToolPolicy): ToolPolicy {
  assertNoSilentWeakening(profile, policy);
  return {
    ...cloneDefaults(profile.defaults),
    ...policy,
    profile: profile.name,
    deniedPaths: mergeUnique(profile.defaults.deniedPaths, policy.deniedPaths),
    deniedDomains: mergeUnique(profile.defaults.deniedDomains, policy.deniedDomains),
    deniedCommands: mergeUnique(profile.defaults.deniedCommands, policy.deniedCommands),
    rules: [...(profile.defaults.rules ?? []), ...(policy.rules ?? [])],
    metadata: {
      ...profile.defaults.metadata,
      ...policy.metadata,
      toolgateProfile: {
        name: profile.name,
        defaults: manifestSafeDefaults(profile.defaults),
        metadata: profile.metadata
      }
    }
  };
}

export const readOnlyWorkspaceProfile = definePolicyProfile("readOnlyWorkspace", {
  risk: "read",
  requireApproval: false,
  audit: true,
  redact: true,
  allowedPaths: ["**/*"],
  deniedPaths: ["**/.env*", "**/node_modules/**", "**/.git/**"],
  allowedCommands: [],
  deniedCommands: ["*"],
  timeoutMs: 10_000
});

export const writeWorkspaceProfile = definePolicyProfile("writeWorkspace", {
  risk: "write",
  requireApproval: false,
  audit: true,
  redact: true,
  deniedPaths: ["**/.env*", "**/.git/**"],
  deniedCommands: ["*"],
  timeoutMs: 15_000
});

export const externalApiProfile = definePolicyProfile("externalApi", {
  risk: "external",
  requireApproval: false,
  audit: true,
  redact: true,
  timeoutMs: 15_000,
  rateLimit: { max: 60, windowMs: 60_000, namespace: "external-api" }
});

export const destructiveWithApprovalProfile = definePolicyProfile("destructiveWithApproval", {
  risk: "destructive",
  requireApproval: true,
  audit: true,
  redact: true,
  timeoutMs: 10_000,
  rateLimit: { max: 10, windowMs: 60_000, namespace: "destructive" }
});

export const builtInPolicyProfiles = [
  readOnlyWorkspaceProfile,
  writeWorkspaceProfile,
  externalApiProfile,
  destructiveWithApprovalProfile
] as const;

function assertNoSilentWeakening(profile: PolicyProfile, policy: ToolPolicy): void {
  const allowed = new Set(profile.allowToolOverrides ?? []);
  const defaults = profile.defaults;

  if (!allowed.has("risk") && policy.risk && riskRank(policy.risk) < riskRank(defaults.risk)) {
    throw new PolicyProfileError(`Tool policy '${policy.name}' cannot weaken profile '${profile.name}' risk.`);
  }
  for (const field of ["requireApproval", "audit", "redact"] as const) {
    if (!allowed.has(field) && defaults[field] === true && policy[field] === false) {
      throw new PolicyProfileError(`Tool policy '${policy.name}' cannot disable profile '${profile.name}' ${field}.`);
    }
  }
  if (!allowed.has("pathRoot") && defaults.pathRoot && policy.pathRoot === undefined) {
    throw new PolicyProfileError(`Tool policy '${policy.name}' cannot remove profile '${profile.name}' pathRoot.`);
  }
  if (!allowed.has("timeoutMs") && defaults.timeoutMs && policy.timeoutMs && policy.timeoutMs > defaults.timeoutMs) {
    throw new PolicyProfileError(`Tool policy '${policy.name}' cannot loosen profile '${profile.name}' timeoutMs.`);
  }
  if (!allowed.has("rateLimit") && defaults.rateLimit && policy.rateLimit) {
    if (policy.rateLimit.max > defaults.rateLimit.max || policy.rateLimit.windowMs < defaults.rateLimit.windowMs) {
      throw new PolicyProfileError(`Tool policy '${policy.name}' cannot loosen profile '${profile.name}' rateLimit.`);
    }
  }
}

function riskRank(risk: ToolRisk | undefined): number {
  return { read: 0, write: 1, external: 1, destructive: 2 }[risk ?? "read"];
}

function mergeUnique(base: string[] | undefined, current: string[] | undefined): string[] | undefined {
  if (!base && !current) return undefined;
  return [...new Set([...(base ?? []), ...(current ?? [])])];
}

function cloneDefaults(defaults: PolicyProfileDefaults): PolicyProfileDefaults {
  return {
    ...defaults,
    allowedPaths: copy(defaults.allowedPaths),
    deniedPaths: copy(defaults.deniedPaths),
    allowedDomains: copy(defaults.allowedDomains),
    deniedDomains: copy(defaults.deniedDomains),
    allowedCommands: copy(defaults.allowedCommands),
    deniedCommands: copy(defaults.deniedCommands),
    rules: defaults.rules ? [...defaults.rules] : undefined,
    rateLimit: defaults.rateLimit ? { ...defaults.rateLimit } : undefined,
    metadata: defaults.metadata ? { ...defaults.metadata } : undefined
  };
}

function manifestSafeDefaults(defaults: PolicyProfileDefaults): Record<string, unknown> {
  const safe = cloneDefaults(defaults) as Record<string, unknown>;
  delete safe.approval;
  delete safe.approvalNonceStore;
  delete safe.approvalSubject;
  delete safe.extractPaths;
  delete safe.extractUrls;
  delete safe.extractCommands;
  delete safe.observe;
  delete safe.rules;
  return safe;
}

function copy(value: string[] | undefined): string[] | undefined {
  return value ? [...value] : undefined;
}
