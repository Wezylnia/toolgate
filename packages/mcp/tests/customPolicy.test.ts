import { describe, expect, it, vi } from "vitest";
import { gate } from "../src/core/gate/gate.js";
import { createManifest } from "../src/operations/manifest/manifest.js";

describe("custom policy rules", () => {
  it("runs sync and async rules in order before the handler", async () => {
    const calls: string[] = [];
    const protectedHandler = gate(
      {
        name: "create_ticket",
        rules: [
          { name: "tenant", evaluate: () => { calls.push("tenant"); return true; } },
          { name: "quota", evaluate: async () => { calls.push("quota"); return { allowed: true }; } }
        ]
      },
      async () => { calls.push("handler"); return "created"; }
    );

    const result = await protectedHandler({ tenantId: "t1" });

    expect(result.ok).toBe(true);
    expect(calls).toEqual(["tenant", "quota", "handler"]);
  });

  it("blocks on the first denied rule without revealing rule details by default", async () => {
    const handler = vi.fn();
    const laterRule = vi.fn(() => true);
    const protectedHandler = gate(
      {
        name: "transfer",
        rules: [
          {
            name: "amount_limit",
            evaluate: (input) => ({
              allowed: Number((input as { amount: number }).amount) <= 100,
              code: "AMOUNT_LIMIT",
              details: { maximum: 100 }
            })
          },
          { name: "later", evaluate: laterRule }
        ]
      },
      handler
    );

    const result = await protectedHandler({ amount: 500 });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("AMOUNT_LIMIT");
      expect(result.error.details).toBeUndefined();
    }
    expect(laterRule).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();
  });

  it("can expose custom rule denial details when explicitly configured", async () => {
    const protectedHandler = gate(
      {
        name: "transfer",
        exposeRuleDenialDetails: true,
        rules: [
          {
            name: "amount_limit",
            evaluate: () => ({
              allowed: false,
              code: "AMOUNT_LIMIT",
              details: { maximum: 100 }
            })
          }
        ]
      },
      async () => "never"
    );

    const result = await protectedHandler({ amount: 500 });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({ rule: "amount_limit", maximum: 100 });
    }
  });

  it("fails closed when a rule throws", async () => {
    const handler = vi.fn();
    const protectedHandler = gate(
      {
        name: "transfer",
        rules: [{ name: "entitlement", evaluate: async () => { throw new Error("offline"); } }]
      },
      handler
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.type).toBe("policy_error");
      expect(result.error.code).toBe("POLICY_RULE_ERROR");
      expect(result.error.details).toBeUndefined();
    }
    expect(handler).not.toHaveBeenCalled();
  });

  it("can expose rule execution failure details when explicitly configured", async () => {
    const protectedHandler = gate(
      {
        name: "transfer",
        exposeRuleDenialDetails: true,
        rules: [{ name: "entitlement", evaluate: async () => { throw new Error("offline"); } }]
      },
      async () => "never"
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toMatchObject({ rule: "entitlement", message: "offline" });
    }
  });

  it("fails closed on malformed JavaScript rule decisions", async () => {
    const protectedHandler = gate(
      {
        name: "unsafe",
        rules: [{ name: "malformed", evaluate: (() => null) as never }]
      },
      async () => "never"
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("POLICY_RULE_ERROR");
      expect(result.error.details).toBeUndefined();
    }
  });

  it("includes rule names in manifests", () => {
    const manifest = createManifest([
      { name: "tool", rules: [{ name: "tenant", evaluate: () => true }] }
    ]);
    expect(manifest.tools[0].customRules).toEqual(["tenant"]);
  });
});
