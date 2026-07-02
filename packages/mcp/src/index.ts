export { gate } from "./core/gate/gate.js";
export { createAuditLogger } from "./operations/audit/jsonlAuditLogger.js";
export { readAuditLog, summarizeAudit } from "./operations/audit/readAuditLog.js";
export { createManifest } from "./operations/manifest/manifest.js";
export { migrateManifest, InvalidPolicyManifestError } from "./operations/manifest/migrate.js";
export { compareManifests } from "./operations/manifest/compare.js";
export { gateMcp, gateMcpHandler, isMcpToolResult, toMcpToolResult } from "./integrations/mcp/adapter.js";
export { policyManifestSchema, validateManifest } from "./operations/manifest/schema.js";
export {
  createManifestFromConfig,
  policyConfigSchema,
  validatePolicyConfig
} from "./policies/config/configSchema.js";
export { migratePolicyConfig } from "./policies/config/migrateConfig.js";
export {
  destructiveFilesystemPolicy,
  externalApiPolicy,
  readOnlyFilesystemPolicy
} from "./policies/presets/presets.js";
export { redact } from "./core/redaction/redact.js";
export { evaluatePolicy } from "./policies/enforcement/evaluatePolicy.js";
export { evaluateCustomRules, PolicyRuleExecutionError } from "./policies/enforcement/customPolicy.js";
export { emitToolGateEvent } from "./integrations/observability/observer.js";
export { createOpenTelemetryObserver } from "./integrations/observability/openTelemetry.js";
export { createToolGate, DuplicateToolPolicyError } from "./core/registry/toolGate.js";
export {
  createMemoryRateLimitStore,
  createRateLimiter,
  createRateLimitKey
} from "./core/rateLimit/rateLimiter.js";
export {
  approve,
  createApprovalBinding,
  createMemoryApprovalNonceStore,
  denyApproval,
  validateApprovalDecision
} from "./core/approval/approvalBinding.js";
export {
  assertPolicy,
  InvalidToolPolicyError,
  validatePolicies,
  validatePolicy
} from "./policies/validation/validatePolicy.js";
export {
  strictPathPolicy,
  summarizePolicySecurity,
  validateManifestSecurity,
  validatePolicyConfigSecurity,
  validatePolicySecurity
} from "./policies/validation/securityLint.js";

export type {
  ApprovalDecision,
  ApprovalBinding,
  ApprovalNonceStore,
  ApprovalProvider,
  ApprovalRequest,
  ApprovalSubjectResolver,
  PolicyRuleDecision,
  ToolGateContext,
  ToolGateEvent,
  ToolGateEventBase,
  ToolGateError,
  ToolGateErrorType,
  ToolGateMeta,
  ToolGateResult,
  ToolInputExtractor,
  ProtectedToolHandler,
  RateLimitOptions,
  ToolHandler,
  ToolGateObserver,
  ToolPolicy,
  ToolPolicyRule,
  ToolRisk
} from "./core/gate/types.js";
export type { AuditEntry, AuditLogger, CreateAuditLoggerOptions } from "./operations/audit/auditLogger.js";
export type {
  AuditQuery,
  AuditReadIssue,
  AuditReadResult,
  AuditSummary
} from "./operations/audit/readAuditLog.js";
export type {
  ManifestValidationIssue,
  ManifestValidationResult
} from "./operations/manifest/schema.js";
export type {
  ManifestChange,
  ManifestChangeSeverity,
  ManifestComparison
} from "./operations/manifest/compare.js";
export type { PolicyConfig, PolicyConfigTool } from "./policies/config/configSchema.js";
export type {
  CreateToolGateOptions,
  ToolGateRegistry,
  ToolPolicyDefaults
} from "./core/registry/toolGate.js";
export type {
  PolicyValidationIssue,
  PolicyValidationResult
} from "./policies/validation/validatePolicy.js";
export type {
  PolicySecurityFinding,
  PolicySecurityLintOptions,
  PolicySecurityLintResult,
  PolicySecuritySeverity
} from "./policies/validation/securityLint.js";
export type {
  McpAdapterOptions,
  McpContentBlock,
  McpSdkToolHandler,
  McpToolResult
} from "./integrations/mcp/adapter.js";
export type { RedactionOptions } from "./core/redaction/redact.js";
export type {
  MemoryRateLimitStore,
  RateLimitDecision,
  RateLimiter,
  RateLimitStore
} from "./core/rateLimit/rateLimiter.js";
export type {
  OpenTelemetryObserverOptions,
  OpenTelemetrySpanLike,
  OpenTelemetryTracerLike,
  TelemetryAttribute
} from "./integrations/observability/openTelemetry.js";
