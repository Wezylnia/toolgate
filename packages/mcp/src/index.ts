export { gate } from "./gate/gate.js";
export { createAuditLogger } from "./audit/jsonlAuditLogger.js";
export { readAuditLog, summarizeAudit } from "./audit/readAuditLog.js";
export { createManifest } from "./manifest/manifest.js";
export { migrateManifest, InvalidPolicyManifestError } from "./manifest/migrate.js";
export { compareManifests } from "./manifest/compare.js";
export { gateMcp, gateMcpHandler, isMcpToolResult, toMcpToolResult } from "./mcp/adapter.js";
export { policyManifestSchema, validateManifest } from "./manifest/schema.js";
export {
  createManifestFromConfig,
  policyConfigSchema,
  validatePolicyConfig
} from "./policy/configSchema.js";
export { migratePolicyConfig } from "./policy/migrateConfig.js";
export {
  destructiveFilesystemPolicy,
  externalApiPolicy,
  readOnlyFilesystemPolicy
} from "./presets/presets.js";
export { redact } from "./redaction/redact.js";
export { evaluatePolicy } from "./policy/evaluatePolicy.js";
export { evaluateCustomRules, PolicyRuleExecutionError } from "./policy/customPolicy.js";
export { emitToolGateEvent } from "./observability/observer.js";
export { createOpenTelemetryObserver } from "./observability/openTelemetry.js";
export { createToolGate, DuplicateToolPolicyError } from "./registry/toolGate.js";
export {
  createMemoryRateLimitStore,
  createRateLimiter,
  createRateLimitKey
} from "./rateLimit/rateLimiter.js";
export {
  approve,
  createApprovalBinding,
  createMemoryApprovalNonceStore,
  denyApproval,
  validateApprovalDecision
} from "./approval/approvalBinding.js";
export {
  assertPolicy,
  InvalidToolPolicyError,
  validatePolicies,
  validatePolicy
} from "./policy/validatePolicy.js";

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
} from "./gate/types.js";
export type { AuditEntry, AuditLogger, CreateAuditLoggerOptions } from "./audit/auditLogger.js";
export type {
  AuditQuery,
  AuditReadIssue,
  AuditReadResult,
  AuditSummary
} from "./audit/readAuditLog.js";
export type {
  ManifestValidationIssue,
  ManifestValidationResult
} from "./manifest/schema.js";
export type {
  ManifestChange,
  ManifestChangeSeverity,
  ManifestComparison
} from "./manifest/compare.js";
export type { PolicyConfig, PolicyConfigTool } from "./policy/configSchema.js";
export type {
  CreateToolGateOptions,
  ToolGateRegistry,
  ToolPolicyDefaults
} from "./registry/toolGate.js";
export type {
  PolicyValidationIssue,
  PolicyValidationResult
} from "./policy/validatePolicy.js";
export type {
  McpAdapterOptions,
  McpContentBlock,
  McpSdkToolHandler,
  McpToolResult
} from "./mcp/adapter.js";
export type { RedactionOptions } from "./redaction/redact.js";
export type {
  MemoryRateLimitStore,
  RateLimitDecision,
  RateLimiter,
  RateLimitStore
} from "./rateLimit/rateLimiter.js";
export type {
  OpenTelemetryObserverOptions,
  OpenTelemetrySpanLike,
  OpenTelemetryTracerLike,
  TelemetryAttribute
} from "./observability/openTelemetry.js";
