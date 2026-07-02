import { describe, expect, it } from "vitest";
import * as api from "../src/index.js";

describe("v1 public API", () => {
  it("exports the documented stable entry points", () => {
    const expected = [
      "gate", "createToolGate", "gateMcp", "gateMcpHandler", "toMcpToolResult",
      "createAuditLogger", "readAuditLog", "summarizeAudit",
      "createManifest", "migrateManifest", "compareManifests",
      "policyManifestSchema", "validateManifest",
      "policyConfigSchema", "validatePolicyConfig", "migratePolicyConfig",
      "validatePolicy", "validatePolicies", "assertPolicy",
      "createMemoryRateLimitStore", "createRateLimiter", "createRateLimitKey",
      "approve", "denyApproval", "createApprovalBinding", "createMemoryApprovalNonceStore",
      "validateApprovalDecision",
      "validatePolicySecurity", "validatePolicyConfigSecurity", "validateManifestSecurity",
      "summarizePolicySecurity", "strictPathPolicy",
      "createOpenTelemetryObserver", "redact", "evaluatePolicy", "evaluateCustomRules"
    ];

    for (const name of expected) {
      expect(api, `missing public export ${name}`).toHaveProperty(name);
    }
  });
});
