import { describe, expect, it, vi } from "vitest";
import { createToolGate, DuplicateToolPolicyError } from "../src/core/registry/toolGate.js";

describe("ToolGate registry", () => {
  it("applies defaults and conservatively merges deny lists, rules, and metadata", async () => {
    const baseRule = vi.fn(() => true);
    const registry = createToolGate({
      name: "filesystem-server",
      defaults: {
        timeoutMs: 5000,
        deniedPaths: [".env", "secrets/**"],
        rules: [{ name: "tenant", evaluate: baseRule }],
        metadata: { team: "platform" }
      }
    });
    const protectedHandler = registry.protect(
      {
        name: "read_file",
        deniedPaths: ["node_modules/**", ".env"],
        metadata: { owner: "docs" }
      },
      async () => "ok"
    );

    const result = await protectedHandler({ path: "src/index.ts" });
    const policy = registry.getPolicy("read_file");

    expect(result.ok).toBe(true);
    expect(baseRule).toHaveBeenCalledOnce();
    expect(policy).toMatchObject({
      timeoutMs: 5000,
      deniedPaths: [".env", "secrets/**", "node_modules/**"],
      metadata: { team: "platform", owner: "docs" }
    });
    expect(registry.manifest()).toMatchObject({
      schemaVersion: "1.0",
      name: "filesystem-server",
      tools: [{ name: "read_file", customRules: ["tenant"] }]
    });
  });

  it("rejects duplicate tool registration", () => {
    const registry = createToolGate();
    registry.protect({ name: "echo" }, async () => "one");

    expect(() => registry.protect({ name: "echo" }, async () => "two")).toThrow(
      DuplicateToolPolicyError
    );
  });

  it("protects MCP-compatible handlers and returns defensive policy copies", async () => {
    const registry = createToolGate();
    const handler = registry.protectMcp(
      { name: "hello", deniedPaths: [".env"] },
      async () => ({ content: [{ type: "text", text: "hello" }] })
    );
    const policies = registry.policies();
    policies[0].deniedPaths?.push("changed/**");

    await expect(handler({})).resolves.toMatchObject({ content: [{ text: "hello" }] });
    expect(registry.getPolicy("hello")?.deniedPaths).toEqual([".env"]);
  });
});
