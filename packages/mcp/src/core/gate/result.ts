import type { ToolGateContext, ToolGateError, ToolGateMeta, ToolPolicy } from "./types.js";
import type { PolicyDecision } from "../../policies/enforcement/evaluatePolicy.js";

export function createMeta(ctx: ToolGateContext): ToolGateMeta {
  return {
    requestId: ctx.requestId,
    toolName: ctx.toolName,
    risk: ctx.risk,
    durationMs: Date.now() - ctx.startedAt.getTime()
  };
}

export function approvalRequiredError(policy: ToolPolicy): ToolGateError {
  return {
    type: "approval_required",
    code: "APPROVAL_REQUIRED",
    message: `Tool '${policy.name}' requires user approval before execution.`,
    details: {
      risk: policy.risk ?? "read"
    }
  };
}

export function approvalDeniedError(policy: ToolPolicy, reason?: string): ToolGateError {
  return {
    type: "approval_denied",
    code: "APPROVAL_DENIED",
    message: `Tool '${policy.name}' approval was denied.`,
    details: reason ? { reason } : undefined
  };
}

export function approvalError(policy: ToolPolicy, error: unknown): ToolGateError {
  return {
    type: "approval_error",
    code: "APPROVAL_ERROR",
    message: `Tool '${policy.name}' approval provider failed.`,
    details: {
      message: error instanceof Error ? error.message : String(error)
    }
  };
}

export function invalidApprovalError(policy: ToolPolicy, code: string, message: string): ToolGateError {
  return {
    type: "approval_error",
    code,
    message: `Tool '${policy.name}' approval decision is invalid.`,
    details: { message }
  };
}

export function policyViolationError(policy: ToolPolicy, decision: PolicyDecision): ToolGateError {
  return {
    type: "policy_violation",
    code: decision.code ?? "POLICY_VIOLATION",
    message:
      decision.message ??
      `Tool '${policy.name}' is blocked by policy.`,
    details: decision.details
  };
}

export function policyRuleError(policy: ToolPolicy, rule: string, error: unknown): ToolGateError {
  return {
    type: "policy_error",
    code: "POLICY_RULE_ERROR",
    message: `Tool '${policy.name}' policy rule evaluation failed.`,
    details: policy.exposeRuleDenialDetails
      ? {
          rule,
          message: error instanceof Error ? error.message : String(error)
        }
      : undefined
  };
}

export function timeoutError(policy: ToolPolicy, timeoutMs: number): ToolGateError {
  return {
    type: "timeout",
    code: "TOOL_TIMEOUT",
    message: `Tool '${policy.name}' exceeded timeout of ${timeoutMs}ms.`
  };
}

export function rateLimitedError(policy: ToolPolicy, retryAfterMs: number): ToolGateError {
  return {
    type: "rate_limited",
    code: "RATE_LIMITED",
    message: `Tool '${policy.name}' exceeded rate limit.`,
    details: {
      retryAfterMs
    }
  };
}

export function rateLimitError(policy: ToolPolicy, error: unknown): ToolGateError {
  return {
    type: "rate_limit_error",
    code: "RATE_LIMIT_ERROR",
    message: `Tool '${policy.name}' rate limit evaluation failed.`,
    details: { message: error instanceof Error ? error.message : String(error) }
  };
}

export function handlerError(policy: ToolPolicy, error: unknown): ToolGateError {
  return {
    type: "handler_error",
    code: "HANDLER_ERROR",
    message: `Tool '${policy.name}' handler failed.`,
    details: {
      message: error instanceof Error ? error.message : String(error)
    }
  };
}

export function redactionError(policy: ToolPolicy, error: unknown): ToolGateError {
  return {
    type: "redaction_error",
    code: "REDACTION_ERROR",
    message: `Tool '${policy.name}' output redaction failed.`,
    details: {
      message: error instanceof Error ? error.message : String(error)
    }
  };
}
