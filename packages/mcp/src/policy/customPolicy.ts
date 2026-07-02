import type {
  PolicyRuleDecision,
  ToolGateContext,
  ToolPolicyRule
} from "../gate/types.js";
import type { PolicyDecision } from "./evaluatePolicy.js";

export class PolicyRuleExecutionError extends Error {
  readonly rule: string;
  readonly cause: unknown;

  constructor(rule: string, cause: unknown) {
    super(`Policy rule '${rule}' failed.`);
    this.name = "PolicyRuleExecutionError";
    this.rule = rule;
    this.cause = cause;
  }
}

export async function evaluateCustomRules(
  rules: ToolPolicyRule[] | undefined,
  input: unknown,
  context: ToolGateContext
): Promise<PolicyDecision> {
  for (const rule of rules ?? []) {
    let rawDecision: boolean | PolicyRuleDecision;
    try {
      rawDecision = await rule.evaluate(input, context);
    } catch (error) {
      throw new PolicyRuleExecutionError(rule.name, error);
    }

    if (
      typeof rawDecision !== "boolean" &&
      (!rawDecision || typeof rawDecision !== "object" || typeof rawDecision.allowed !== "boolean")
    ) {
      throw new PolicyRuleExecutionError(
        rule.name,
        new TypeError("Policy rule must return a boolean or a decision with a boolean allowed field.")
      );
    }
    const decision = typeof rawDecision === "boolean" ? { allowed: rawDecision } : rawDecision;
    if (!decision.allowed) {
      return {
        allowed: false,
        code: decision.code ?? "CUSTOM_RULE_DENIED",
        message: decision.message ?? `Tool '${context.toolName}' was denied by policy.`,
        details: context.policy.exposeRuleDenialDetails
          ? { ...decision.details, rule: rule.name }
          : undefined
      };
    }
  }
  return { allowed: true };
}
