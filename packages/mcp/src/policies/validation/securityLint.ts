import type { ToolPolicy } from "../../core/gate/types.js";
import type { PolicyManifest, PolicyManifestTool } from "../../operations/manifest/manifest.js";
import type { PolicyConfig, PolicyConfigTool } from "../config/configSchema.js";

export type PolicySecuritySeverity = "info" | "warning" | "danger";

export interface PolicySecurityFinding {
  severity: PolicySecuritySeverity;
  code: string;
  tool: string;
  path: string;
  message: string;
  recommendation: string;
}

export interface PolicySecurityLintOptions {
  strictPathMode?: boolean;
}

export interface PolicySecurityLintResult {
  passed: boolean;
  failOn: PolicySecuritySeverity;
  findings: PolicySecurityFinding[];
}

interface NormalizedSecurityTool {
  name: string;
  risk: string;
  requiresApproval: boolean;
  audit: boolean;
  redact: boolean;
  allowedPaths?: string[];
  deniedPaths?: string[];
  pathRoot?: string;
  allowedDomains?: string[];
  allowedCommands?: string[];
  rateLimit?: { keyed?: boolean };
  exposesPolicyDenialDetails?: boolean;
  exposesRuleDenialDetails?: boolean;
  path: string;
}

export function validatePolicySecurity(
  policy: ToolPolicy,
  options: PolicySecurityLintOptions = {}
): PolicySecurityFinding[] {
  return lintSecurityTool({
    name: policy.name,
    risk: policy.risk ?? "read",
    requiresApproval: Boolean(policy.requireApproval),
    audit: Boolean(policy.audit),
    redact: Boolean(policy.redact),
    allowedPaths: policy.allowedPaths,
    deniedPaths: policy.deniedPaths,
    pathRoot: policy.pathRoot,
    allowedDomains: policy.allowedDomains,
    allowedCommands: policy.allowedCommands,
    rateLimit: policy.rateLimit ? { keyed: Boolean(policy.rateLimit.key) } : undefined,
    exposesPolicyDenialDetails: policy.exposePolicyDenialDetails,
    exposesRuleDenialDetails: policy.exposeRuleDenialDetails,
    path: "$"
  }, options);
}

export function validatePolicyConfigSecurity(
  config: PolicyConfig,
  options: PolicySecurityLintOptions = {}
): PolicySecurityFinding[] {
  return config.tools.flatMap((tool, index) => lintSecurityTool(fromConfigTool(tool, index), options));
}

export function validateManifestSecurity(
  manifest: PolicyManifest,
  options: PolicySecurityLintOptions = {}
): PolicySecurityFinding[] {
  return manifest.tools.flatMap((tool, index) => lintSecurityTool(fromManifestTool(tool, index), options));
}

export function summarizePolicySecurity(
  findings: PolicySecurityFinding[],
  failOn: PolicySecuritySeverity = "danger"
): PolicySecurityLintResult {
  return {
    passed: !findings.some((finding) => severityRank(finding.severity) >= severityRank(failOn)),
    failOn,
    findings
  };
}

export function strictPathPolicy<T extends ToolPolicy>(policy: T): T {
  const hasPathPolicy = Boolean(policy.allowedPaths?.length || policy.deniedPaths?.length);
  if (hasPathPolicy && !policy.pathRoot) {
    throw new TypeError(`Tool policy '${policy.name}' uses path rules without pathRoot.`);
  }
  return policy;
}

function lintSecurityTool(
  tool: NormalizedSecurityTool,
  options: PolicySecurityLintOptions
): PolicySecurityFinding[] {
  const findings: PolicySecurityFinding[] = [];
  const hasPathPolicy = Boolean(tool.allowedPaths?.length || tool.deniedPaths?.length);

  if (tool.risk === "destructive" && !tool.requiresApproval) {
    findings.push(finding("danger", "DESTRUCTIVE_WITHOUT_APPROVAL", tool, "requiresApproval", "Destructive tools should require approval.", "Set requireApproval/requiresApproval to true and bind approvals to an authenticated subject."));
  }

  if (tool.risk === "destructive" && !tool.audit) {
    findings.push(finding("warning", "DESTRUCTIVE_WITHOUT_AUDIT", tool, "audit", "Destructive tools should write audit logs.", "Enable audit logging or provide a custom audit sink."));
  }

  if (hasPathPolicy && !tool.pathRoot) {
    findings.push(finding(
      options.strictPathMode ? "danger" : "warning",
      "PATH_POLICY_WITHOUT_ROOT",
      tool,
      "pathRoot",
      "Path rules without pathRoot rely on string normalization and cannot enforce canonical filesystem containment.",
      "Set pathRoot to the authenticated workspace or project root."
    ));
  }

  if ((tool.risk === "read" || tool.risk === "external") && !tool.redact) {
    findings.push(finding("warning", "REDACTION_DISABLED_FOR_DATA_TOOL", tool, "redact", "Read and external tools often return sensitive data.", "Enable redaction unless the output is already guaranteed safe."));
  }

  if (tool.allowedCommands?.some(isBroadCommandPattern)) {
    findings.push(finding("danger", "BROAD_COMMAND_ALLOWLIST", tool, "allowedCommands", "Command allowlists should not use broad wildcard patterns.", "Replace broad command patterns with exact commands or narrow prefixes."));
  }

  if (tool.allowedDomains?.some(isBroadDomainPattern)) {
    findings.push(finding("danger", "BROAD_DOMAIN_ALLOWLIST", tool, "allowedDomains", "Domain allowlists should not allow every host or broad public suffixes.", "Use explicit hostnames or narrow organization-controlled wildcard domains."));
  }

  if ((tool.risk === "external" || tool.risk === "destructive") && tool.rateLimit && !tool.rateLimit.keyed) {
    findings.push(finding("warning", "UNKEYED_RATE_LIMIT", tool, "rateLimit.keyed", "External and destructive tools usually need tenant or subject keyed rate limits.", "Add a rate limit key extractor or keyed config metadata."));
  }

  if (tool.exposesPolicyDenialDetails) {
    findings.push(finding("warning", "POLICY_DENIAL_DETAILS_EXPOSED", tool, "exposesPolicyDenialDetails", "Policy denial detail exposure can reveal requested paths, URLs, or commands.", "Keep denial details hidden unless the caller is trusted."));
  }

  if (tool.exposesRuleDenialDetails) {
    findings.push(finding("warning", "RULE_DENIAL_DETAILS_EXPOSED", tool, "exposesRuleDenialDetails", "Rule denial detail exposure can reveal internal rule names or failure details.", "Keep rule details hidden unless the caller is trusted."));
  }

  return findings;
}

function fromConfigTool(tool: PolicyConfigTool, index: number): NormalizedSecurityTool {
  return {
    name: tool.name,
    risk: tool.risk ?? "read",
    requiresApproval: Boolean(tool.requireApproval),
    audit: Boolean(tool.audit),
    redact: Boolean(tool.redact),
    allowedPaths: tool.allowedPaths,
    deniedPaths: tool.deniedPaths,
    pathRoot: tool.pathRoot,
    allowedDomains: tool.allowedDomains,
    allowedCommands: tool.allowedCommands,
    rateLimit: tool.rateLimit ? { keyed: Boolean(tool.rateLimit.keyed) } : undefined,
    exposesPolicyDenialDetails: tool.exposePolicyDenialDetails,
    exposesRuleDenialDetails: tool.exposeRuleDenialDetails,
    path: `$.tools[${index}]`
  };
}

function fromManifestTool(tool: PolicyManifestTool, index: number): NormalizedSecurityTool {
  return {
    name: tool.name,
    risk: tool.risk,
    requiresApproval: tool.requiresApproval,
    audit: tool.audit,
    redact: tool.redact,
    allowedPaths: tool.allowedPaths,
    deniedPaths: tool.deniedPaths,
    pathRoot: tool.pathRoot,
    allowedDomains: tool.allowedDomains,
    allowedCommands: tool.allowedCommands,
    rateLimit: tool.rateLimit ? { keyed: Boolean(tool.rateLimit.keyed) } : undefined,
    exposesPolicyDenialDetails: tool.exposesPolicyDenialDetails,
    exposesRuleDenialDetails: tool.exposesRuleDenialDetails,
    path: `$.tools[${index}]`
  };
}

function finding(
  severity: PolicySecuritySeverity,
  code: string,
  tool: NormalizedSecurityTool,
  field: string,
  message: string,
  recommendation: string
): PolicySecurityFinding {
  return {
    severity,
    code,
    tool: tool.name,
    path: `${tool.path}.${field}`,
    message,
    recommendation
  };
}

function isBroadCommandPattern(pattern: string): boolean {
  const normalized = pattern.trim();
  return normalized === "*" || normalized === "**" || normalized === "* *" || normalized.endsWith(" *");
}

function isBroadDomainPattern(pattern: string): boolean {
  const normalized = pattern.trim().toLowerCase();
  return normalized === "*" || normalized === "*.*" || normalized === "*.com" || normalized === "*.net" || normalized === "*.org";
}

function severityRank(value: PolicySecuritySeverity): number {
  return { info: 0, warning: 1, danger: 2 }[value];
}
