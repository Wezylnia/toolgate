import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";
import {
  InvalidToolPolicyError,
  validatePolicies,
  validatePolicy
} from "../src/policies/validation/validatePolicy.js";

describe("policy validation", () => {
  it("accepts a complete policy", () => {
    expect(
      validatePolicy({
        name: "read_file",
        risk: "read",
        allowedPaths: ["src/**"],
        timeoutMs: 1000,
        rateLimit: { max: 5, windowMs: 60_000 }
      })
    ).toEqual({ valid: true, issues: [] });
  });

  it("reports invalid fields and duplicate tool names", () => {
    const result = validatePolicies([
      { name: "read_file", timeoutMs: 0 },
      { name: "read_file", rateLimit: { max: 1.5, windowMs: -1 } }
    ]);

    expect(result.valid).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(
      expect.arrayContaining([
        "$.tools[0].timeoutMs",
        "$.tools[1].rateLimit.max",
        "$.tools[1].rateLimit.windowMs",
        "$.tools[1].name"
      ])
    );
  });

  it("makes gate fail fast for invalid policy configuration", () => {
    expect(() => gate({ name: "", timeoutMs: 0 }, async () => "never")).toThrow(
      InvalidToolPolicyError
    );
  });
});
