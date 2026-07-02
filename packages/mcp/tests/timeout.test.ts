import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";

describe("timeout", () => {
  it("returns a structured timeout error", async () => {
    const protectedHandler = gate(
      { name: "slow_tool", timeoutMs: 10 },
      async (_input, ctx) => {
        await new Promise((resolve) => {
          ctx.signal.addEventListener("abort", resolve, { once: true });
          setTimeout(resolve, 50);
        });
        return "late";
      }
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.type).toBe("timeout");
      expect(result.error.code).toBe("TOOL_TIMEOUT");
    }
  });
});
