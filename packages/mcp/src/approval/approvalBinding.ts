import { createHash, randomUUID } from "node:crypto";
import type {
  ApprovalBinding,
  ApprovalDecision,
  ApprovalNonceStore,
  ToolGateContext,
  ToolPolicy
} from "../gate/types.js";

const defaultApprovalExpiryMs = 5 * 60 * 1000;

export interface ApprovalValidationResult {
  valid: boolean;
  code?: string;
  message?: string;
}

export function createMemoryApprovalNonceStore(): ApprovalNonceStore {
  const consumed = new Map<string, number>();
  return {
    consume(nonce, expiresAt) {
      const now = Date.now();
      for (const [storedNonce, expiry] of consumed) {
        if (expiry <= now) consumed.delete(storedNonce);
      }
      if (consumed.has(nonce)) return false;
      consumed.set(nonce, expiresAt.getTime());
      return true;
    }
  };
}

export async function createApprovalBinding(
  policy: ToolPolicy,
  input: unknown,
  context: ToolGateContext,
  now = Date.now()
): Promise<ApprovalBinding> {
  const subject = await resolveSubject(policy, input, context);
  return {
    subject,
    toolName: policy.name,
    inputHash: hashStable(input),
    policyVersion: policy.policyVersion ?? hashPolicy(policy),
    toolVersion: policy.toolVersion ?? "unversioned",
    expiresAt: new Date(now + (policy.approvalExpiresInMs ?? defaultApprovalExpiryMs)).toISOString(),
    nonce: randomUUID()
  };
}

export function approve(request: { binding: ApprovalBinding }, metadata?: Record<string, unknown>): ApprovalDecision {
  return { approved: true, binding: request.binding, metadata };
}

export function denyApproval(reason?: string, metadata?: Record<string, unknown>): ApprovalDecision {
  return { approved: false, reason, metadata };
}

export async function validateApprovalDecision(
  decision: unknown,
  expected: ApprovalBinding,
  nonceStore: ApprovalNonceStore,
  now = Date.now()
): Promise<ApprovalValidationResult> {
  if (!decision || typeof decision !== "object") {
    return { valid: false, code: "APPROVAL_DECISION_INVALID", message: "Approval provider returned an invalid decision." };
  }

  const approvalDecision = decision as Partial<ApprovalDecision>;
  if (typeof approvalDecision.approved !== "boolean") {
    return { valid: false, code: "APPROVAL_DECISION_INVALID", message: "Approval provider returned an invalid decision." };
  }

  if (!approvalDecision.approved) return { valid: true };

  if (!approvalDecision.binding) {
    return { valid: false, code: "APPROVAL_BINDING_MISSING", message: "Approved decisions must include the request binding." };
  }

  for (const key of ["subject", "toolName", "inputHash", "policyVersion", "toolVersion", "expiresAt", "nonce"] as const) {
    if (approvalDecision.binding[key] !== expected[key]) {
      return { valid: false, code: "APPROVAL_BINDING_MISMATCH", message: "Approval binding did not match the protected call." };
    }
  }

  const expiresAt = new Date(approvalDecision.binding.expiresAt);
  if (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= now) {
    return { valid: false, code: "APPROVAL_EXPIRED", message: "Approval binding has expired." };
  }

  const consumed = await nonceStore.consume(approvalDecision.binding.nonce, expiresAt);
  if (!consumed) {
    return { valid: false, code: "APPROVAL_NONCE_REPLAYED", message: "Approval nonce has already been used." };
  }

  return { valid: true };
}

async function resolveSubject(
  policy: ToolPolicy,
  input: unknown,
  context: ToolGateContext
): Promise<string> {
  const resolver = policy.approvalSubject;
  const subject = typeof resolver === "function" ? await resolver(input, context) : resolver;
  if (typeof subject !== "string" || subject.trim().length === 0) {
    throw new TypeError("approvalSubject must resolve to a non-empty authenticated subject.");
  }
  return subject;
}

function hashPolicy(policy: ToolPolicy): string {
  return hashStable({
    name: policy.name,
    description: policy.description,
    risk: policy.risk ?? "read",
    requireApproval: policy.requireApproval ?? false,
    allowedPaths: policy.allowedPaths,
    deniedPaths: policy.deniedPaths,
    pathRoot: policy.pathRoot,
    allowedDomains: policy.allowedDomains,
    deniedDomains: policy.deniedDomains,
    allowedCommands: policy.allowedCommands,
    deniedCommands: policy.deniedCommands,
    rules: policy.rules?.map((rule) => rule.name),
    rateLimit: policy.rateLimit ? {
      max: policy.rateLimit.max,
      windowMs: policy.rateLimit.windowMs,
      keyed: Boolean(policy.rateLimit.key),
      namespace: policy.rateLimit.namespace
    } : undefined,
    timeoutMs: policy.timeoutMs,
    redact: Boolean(policy.redact)
  });
}

function hashStable(value: unknown): string {
  return createHash("sha256").update(stableStringify(value, new WeakSet<object>())).digest("hex");
}

function stableStringify(value: unknown, seen: WeakSet<object>): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "bigint") return JSON.stringify(value.toString());
    if (typeof value === "function") return JSON.stringify("[Function]");
    if (typeof value === "symbol") return JSON.stringify(value.toString());
    return JSON.stringify(value);
  }

  if (seen.has(value)) return JSON.stringify("[Circular]");
  seen.add(value);

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item, seen)).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key], seen)}`)
    .join(",")}}`;
}
