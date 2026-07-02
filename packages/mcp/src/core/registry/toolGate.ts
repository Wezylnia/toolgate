import { gate } from "../gate/gate.js";
import type {
  ProtectedToolHandler,
  ToolGateObserver,
  ToolGateResult,
  ToolHandler,
  ToolPolicy
} from "../gate/types.js";
import { createManifest, type PolicyManifest } from "../../operations/manifest/manifest.js";
import {
  gateMcp,
  gateMcpHandler,
  type McpAdapterOptions,
  type McpSdkToolHandler,
  type McpToolResult
} from "../../integrations/mcp/adapter.js";
import { assertPolicy } from "../../policies/validation/validatePolicy.js";
import {
  applyPolicyProfile,
  builtInPolicyProfiles,
  type PolicyProfile
} from "../../policies/profiles/profiles.js";

export type ToolPolicyDefaults = Partial<Omit<ToolPolicy, "name">>;

export interface CreateToolGateOptions {
  name?: string;
  defaults?: ToolPolicyDefaults;
  profiles?: PolicyProfile[];
}

export interface ToolGateRegistry {
  protect<TInput, TOutput>(
    policy: ToolPolicy,
    handler: ToolHandler<TInput, TOutput>
  ): ProtectedToolHandler<TInput, ToolGateResult<TOutput>>;
  protectMcp<TInput, TOutput>(
    policy: ToolPolicy,
    handler: ToolHandler<TInput, TOutput>,
    options?: McpAdapterOptions
  ): (input: TInput) => Promise<McpToolResult>;
  protectMcpHandler<TInput, TExtra, TOutput>(
    policy: ToolPolicy,
    handler: McpSdkToolHandler<TInput, TExtra, TOutput>,
    options?: McpAdapterOptions
  ): (input: TInput, extra: TExtra) => Promise<McpToolResult>;
  getPolicy(name: string): ToolPolicy | undefined;
  policies(): ToolPolicy[];
  manifest(options?: { name?: string }): PolicyManifest;
}

export class DuplicateToolPolicyError extends TypeError {
  readonly toolName: string;

  constructor(toolName: string) {
    super(`Tool policy '${toolName}' is already registered.`);
    this.name = "DuplicateToolPolicyError";
    this.toolName = toolName;
  }
}

export function createToolGate(options: CreateToolGateOptions = {}): ToolGateRegistry {
  const registered = new Map<string, ToolPolicy>();
  const profiles = new Map(
    [...builtInPolicyProfiles, ...(options.profiles ?? [])].map((profile) => [profile.name, profile])
  );

  function register(policy: ToolPolicy): ToolPolicy {
    if (registered.has(policy.name)) throw new DuplicateToolPolicyError(policy.name);
    const profiled = resolveProfile(policy, profiles);
    const resolved = mergePolicy(options.defaults, profiled);
    assertPolicy(resolved);
    registered.set(resolved.name, resolved);
    return resolved;
  }

  return {
    protect<TInput, TOutput>(policy: ToolPolicy, handler: ToolHandler<TInput, TOutput>) {
      return gate(register(policy), handler);
    },
    protectMcp<TInput, TOutput>(
      policy: ToolPolicy,
      handler: ToolHandler<TInput, TOutput>,
      adapterOptions: McpAdapterOptions = {}
    ) {
      return gateMcp(register(policy), handler, adapterOptions);
    },
    protectMcpHandler<TInput, TExtra, TOutput>(
      policy: ToolPolicy,
      handler: McpSdkToolHandler<TInput, TExtra, TOutput>,
      adapterOptions: McpAdapterOptions = {}
    ) {
      return gateMcpHandler(register(policy), handler, adapterOptions);
    },
    getPolicy(name: string): ToolPolicy | undefined {
      const policy = registered.get(name);
      return policy ? clonePolicy(policy) : undefined;
    },
    policies(): ToolPolicy[] {
      return [...registered.values()].map(clonePolicy);
    },
    manifest(manifestOptions: { name?: string } = {}): PolicyManifest {
      return createManifest([...registered.values()], {
        name: manifestOptions.name ?? options.name
      });
    }
  };
}

function resolveProfile(policy: ToolPolicy, profiles: Map<string, PolicyProfile>): ToolPolicy {
  if (!policy.profile) return clonePolicy(policy);
  const profile = profiles.get(policy.profile);
  if (!profile) throw new TypeError(`Unknown policy profile '${policy.profile}' for tool '${policy.name}'.`);
  return applyPolicyProfile(profile, policy);
}

function mergePolicy(defaults: ToolPolicyDefaults | undefined, policy: ToolPolicy): ToolPolicy {
  if (!defaults) return clonePolicy(policy);
  return {
    ...defaults,
    ...policy,
    deniedPaths: mergeUnique(defaults.deniedPaths, policy.deniedPaths),
    deniedDomains: mergeUnique(defaults.deniedDomains, policy.deniedDomains),
    deniedCommands: mergeUnique(defaults.deniedCommands, policy.deniedCommands),
    rules: [...(defaults.rules ?? []), ...(policy.rules ?? [])],
    metadata: defaults.metadata || policy.metadata
      ? { ...defaults.metadata, ...policy.metadata }
      : undefined,
    observe: combineObservers(defaults.observe, policy.observe)
  };
}

function clonePolicy(policy: ToolPolicy): ToolPolicy {
  return {
    ...policy,
    allowedPaths: copy(policy.allowedPaths),
    deniedPaths: copy(policy.deniedPaths),
    allowedDomains: copy(policy.allowedDomains),
    deniedDomains: copy(policy.deniedDomains),
    allowedCommands: copy(policy.allowedCommands),
    deniedCommands: copy(policy.deniedCommands),
    rules: policy.rules ? [...policy.rules] : undefined,
    rateLimit: policy.rateLimit ? { ...policy.rateLimit } : undefined,
    metadata: policy.metadata ? { ...policy.metadata } : undefined
  };
}

function mergeUnique(base: string[] | undefined, current: string[] | undefined): string[] | undefined {
  if (!base && !current) return undefined;
  return [...new Set([...(base ?? []), ...(current ?? [])])];
}

function copy(value: string[] | undefined): string[] | undefined {
  return value ? [...value] : undefined;
}

function combineObservers(
  base: ToolGateObserver | undefined,
  current: ToolGateObserver | undefined
): ToolGateObserver | undefined {
  if (!base) return current;
  if (!current || current === base) return base;
  return async (event) => {
    try { await base(event); } catch { /* Observer isolation is part of the registry contract. */ }
    try { await current(event); } catch { /* Observer isolation is part of the registry contract. */ }
  };
}
