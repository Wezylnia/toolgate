import type { AuditLogger } from "../audit/auditLogger.js";
import {
  createApprovalBinding,
  createMemoryApprovalNonceStore,
  validateApprovalDecision
} from "../approval/approvalBinding.js";
import { createAuditLogger } from "../audit/jsonlAuditLogger.js";
import { noopAuditLogger } from "../audit/noopAuditLogger.js";
import { evaluatePolicy } from "../policy/evaluatePolicy.js";
import { evaluateCustomRules, PolicyRuleExecutionError } from "../policy/customPolicy.js";
import { emitToolGateEvent } from "../observability/observer.js";
import { assertPolicy } from "../policy/validatePolicy.js";
import { createRateLimiter, createRateLimitKey } from "../rateLimit/rateLimiter.js";
import { redact } from "../redaction/redact.js";
import { ToolTimeoutError, withTimeout } from "../timeout/withTimeout.js";
import { createRequestId } from "../utils/createRequestId.js";
import { safeJsonClone, summarizeOutput } from "../utils/safeJson.js";
import {
  approvalDeniedError,
  approvalError,
  approvalRequiredError,
  createMeta,
  handlerError,
  invalidApprovalError,
  policyViolationError,
  policyRuleError,
  rateLimitedError,
  rateLimitError,
  redactionError,
  timeoutError
} from "./result.js";
import type {
  ProtectedToolHandler,
  ToolGateContext,
  ToolGateResult,
  ToolHandler,
  ToolPolicy
} from "./types.js";

export function gate<TInput, TOutput>(
  policy: ToolPolicy,
  handler: ToolHandler<TInput, TOutput>
): ProtectedToolHandler<TInput, ToolGateResult<TOutput>> {
  return createGateExecutor(policy, handler);
}

export function createGateExecutor<TInput, TOutput, TArgs extends unknown[] = []>(
  policy: ToolPolicy,
  handler: (input: TInput, context: ToolGateContext, ...args: TArgs) => TOutput | Promise<TOutput>
): (input: TInput, ...args: TArgs) => Promise<ToolGateResult<TOutput>> {
  assertPolicy(policy);
  const rateLimiter = createRateLimiter(policy.rateLimit);
  const approvalNonceStore = policy.approvalNonceStore ?? createMemoryApprovalNonceStore();

  return async (input: TInput, ...args: TArgs) => {
    const controller = new AbortController();
    const ctx: ToolGateContext = {
      toolName: policy.name,
      risk: policy.risk ?? "read",
      signal: controller.signal,
      startedAt: new Date(),
      requestId: createRequestId(),
      policy
    };
    const audit = resolveAuditLogger(policy);
    const auditInput = redactForLogs(input, policy);
    let approvalMetadata: Record<string, unknown> | undefined;
    await emitToolGateEvent(policy, ctx, { type: "started" });

    const decision = evaluatePolicy(policy, input);
    if (!decision.allowed) {
      const error = policyViolationError(policy, decision);
      await safeAudit(audit, {
        timestamp: new Date().toISOString(),
        tool: policy.name,
        risk: ctx.risk,
        decision: "blocked",
        requestId: ctx.requestId,
        durationMs: createMeta(ctx).durationMs,
        reason: error.code,
        input: auditInput,
        metadata: policy.metadata
      });
      await emitToolGateEvent(policy, ctx, { type: "blocked", code: error.code });
      return { ok: false, error, meta: createMeta(ctx) };
    }

    try {
      const customDecision = await evaluateCustomRules(policy.rules, input, ctx);
      if (!customDecision.allowed) {
        const error = policyViolationError(policy, customDecision);
        await auditBlocked(audit, policy, ctx, auditInput, error.code);
        await emitToolGateEvent(policy, ctx, { type: "blocked", code: error.code });
        return { ok: false, error, meta: createMeta(ctx) };
      }
    } catch (error) {
      const normalizedError = error instanceof PolicyRuleExecutionError
        ? policyRuleError(policy, error.rule, error.cause)
        : policyRuleError(policy, "unknown", error);
      await auditFailure(audit, policy, ctx, auditInput, normalizedError);
      await emitToolGateEvent(policy, ctx, { type: "failed", code: normalizedError.code });
      return { ok: false, error: normalizedError, meta: createMeta(ctx) };
    }

    if (policy.requireApproval) {
      if (!policy.approval) {
        const error = approvalRequiredError(policy);
        await auditBlocked(audit, policy, ctx, auditInput, error.code);
        await emitToolGateEvent(policy, ctx, { type: "blocked", code: error.code });
        return { ok: false, error, meta: createMeta(ctx) };
      }

      try {
        const binding = await createApprovalBinding(policy, input, ctx);
        const rawDecision = await policy.approval({
          input,
          requestId: ctx.requestId,
          toolName: ctx.toolName,
          risk: ctx.risk,
          policy,
          binding
        });
        const decision = rawDecision;
        const validation = await validateApprovalDecision(
          decision,
          binding,
          approvalNonceStore
        );
        if (!validation.valid) {
          const error = invalidApprovalError(
            policy,
            validation.code ?? "APPROVAL_DECISION_INVALID",
            validation.message ?? "Approval decision was invalid."
          );
          await auditFailure(audit, policy, ctx, auditInput, error);
          await emitToolGateEvent(policy, ctx, { type: "failed", code: error.code });
          return { ok: false, error, meta: createMeta(ctx) };
        }

        if (!decision.approved) {
          const error = approvalDeniedError(policy, decision.reason);
          await auditBlocked(audit, policy, ctx, auditInput, error.code, decision.metadata);
          await emitToolGateEvent(policy, ctx, { type: "blocked", code: error.code });
          return { ok: false, error, meta: createMeta(ctx) };
        }

        approvalMetadata = decision.metadata;
        await emitToolGateEvent(policy, ctx, { type: "approved" });
      } catch (error) {
        const normalizedError = approvalError(policy, error);
        await auditFailure(audit, policy, ctx, auditInput, normalizedError);
        await emitToolGateEvent(policy, ctx, { type: "failed", code: normalizedError.code });
        return { ok: false, error: normalizedError, meta: createMeta(ctx) };
      }
    }

    let rateLimitDecision;
    try {
      rateLimitDecision = policy.rateLimit && rateLimiter
        ? await rateLimiter.check(createRateLimitKey(policy.rateLimit, input, policy.name))
        : undefined;
    } catch (error) {
      const normalizedError = rateLimitError(policy, error);
      await auditFailure(audit, policy, ctx, auditInput, normalizedError);
      await emitToolGateEvent(policy, ctx, { type: "failed", code: normalizedError.code });
      return { ok: false, error: normalizedError, meta: createMeta(ctx) };
    }
    if (rateLimitDecision && !rateLimitDecision.allowed) {
      const error = rateLimitedError(policy, rateLimitDecision.retryAfterMs ?? 0);
      await safeAudit(audit, {
        timestamp: new Date().toISOString(),
        tool: policy.name,
        risk: ctx.risk,
        decision: "blocked",
        requestId: ctx.requestId,
        durationMs: createMeta(ctx).durationMs,
        reason: error.code,
        input: auditInput,
        metadata: policy.metadata
      });
      await emitToolGateEvent(policy, ctx, { type: "blocked", code: error.code });
      return { ok: false, error, meta: createMeta(ctx) };
    }

    try {
      const output = await withTimeout(handler(input, ctx, ...args), policy.timeoutMs, controller, policy);
      let redactedOutput: TOutput;
      try {
        redactedOutput = policy.redact ? redact(output, policy.redact) : output;
      } catch (error) {
        const normalizedError = redactionError(policy, error);
        await auditFailure(audit, policy, ctx, auditInput, normalizedError);
        await emitToolGateEvent(policy, ctx, { type: "failed", code: normalizedError.code });
        return { ok: false, error: normalizedError, meta: createMeta(ctx) };
      }

      const outputSummary = summarizeOutput(redactedOutput);

      await safeAudit(audit, {
        timestamp: new Date().toISOString(),
        tool: policy.name,
        risk: ctx.risk,
        decision: "allowed",
        requestId: ctx.requestId,
        durationMs: createMeta(ctx).durationMs,
        reason: policy.requireApproval ? "APPROVED" : undefined,
        input: auditInput,
        outputSummary,
        metadata: mergeMetadata(policy.metadata, approvalMetadata)
      });

      await emitToolGateEvent(policy, ctx, { type: "completed", outputSummary });

      return { ok: true, data: redactedOutput, meta: createMeta(ctx) };
    } catch (error) {
      const normalizedError =
        error instanceof ToolTimeoutError
          ? timeoutError(policy, error.timeoutMs)
          : handlerError(policy, error);

      await auditFailure(audit, policy, ctx, auditInput, normalizedError);
      await emitToolGateEvent(policy, ctx, { type: "failed", code: normalizedError.code });
      return { ok: false, error: normalizedError, meta: createMeta(ctx) };
    }
  };
}

async function auditBlocked(
  audit: AuditLogger,
  policy: ToolPolicy,
  ctx: ToolGateContext,
  input: unknown,
  reason: string,
  approvalMetadata?: Record<string, unknown>
): Promise<void> {
  await safeAudit(audit, {
    timestamp: new Date().toISOString(),
    tool: policy.name,
    risk: ctx.risk,
    decision: "blocked",
    requestId: ctx.requestId,
    durationMs: createMeta(ctx).durationMs,
    reason,
    input,
    metadata: mergeMetadata(policy.metadata, approvalMetadata)
  });
}

function mergeMetadata(
  policyMetadata?: Record<string, unknown>,
  approvalMetadata?: Record<string, unknown>
): Record<string, unknown> | undefined {
  if (!policyMetadata && !approvalMetadata) {
    return undefined;
  }
  return { ...policyMetadata, ...approvalMetadata };
}

function resolveAuditLogger(policy: ToolPolicy): AuditLogger {
  if (policy.audit && typeof policy.audit === "object") {
    return policy.audit;
  }
  if (policy.audit === true) {
    return createAuditLogger({ file: ".toolgate/audit.jsonl" });
  }
  return noopAuditLogger;
}

function redactForLogs(input: unknown, policy: ToolPolicy): unknown {
  if (policy.redact === false) {
    return safeJsonClone(input);
  }
  return redact(safeJsonClone(input), policy.redact || true);
}

async function auditFailure(
  audit: AuditLogger,
  policy: ToolPolicy,
  ctx: ToolGateContext,
  input: unknown,
  error: unknown
): Promise<void> {
  await safeAudit(audit, {
    timestamp: new Date().toISOString(),
    tool: policy.name,
    risk: ctx.risk,
    decision: "failed",
    requestId: ctx.requestId,
    durationMs: createMeta(ctx).durationMs,
    reason: typeof error === "object" && error && "code" in error ? String(error.code) : "ERROR",
    input,
    error,
    metadata: policy.metadata
  });
}

async function safeAudit(audit: AuditLogger, entry: Parameters<AuditLogger["log"]>[0]): Promise<void> {
  try {
    await audit.log(entry);
  } catch {
    // Audit logging should not crash tool calls by default. Custom loggers can record their own failures.
  }
}
