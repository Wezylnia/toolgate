import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";

describe("gate", () => {
  it("allows safe calls and returns metadata", async () => {
    const protectedHandler = gate(
      { name: "echo", risk: "read" },
      async (input: { message: string }, ctx) => ({
        message: input.message,
        requestId: ctx.requestId
      })
    );

    const result = await protectedHandler({ message: "hello" });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.message).toBe("hello");
      expect(result.data.requestId).toBe(result.meta.requestId);
    }
  });

  it("blocks approval-required tools", async () => {
    let called = false;
    const protectedHandler = gate(
      { name: "delete_file", risk: "destructive", requireApproval: true },
      async () => {
        called = true;
        return { ok: true };
      }
    );

    const result = await protectedHandler({});

    expect(called).toBe(false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("APPROVAL_REQUIRED");
      expect(result.error.type).toBe("approval_required");
    }
  });

  it("returns handler errors as structured results", async () => {
    const protectedHandler = gate({ name: "fail" }, async () => {
      throw new Error("boom");
    });

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.type).toBe("handler_error");
      expect(result.error.details?.message).toBe("boom");
    }
  });
});
