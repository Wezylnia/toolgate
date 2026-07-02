import { describe, expect, it, vi } from "vitest";
import { gate } from "../src/core/gate/gate.js";
import { createOpenTelemetryObserver } from "../src/integrations/observability/openTelemetry.js";

describe("OpenTelemetry observer", () => {
  it("creates and completes a span without exposing input or output", async () => {
    const span = createSpan();
    const tracer = { startSpan: vi.fn(() => span) };
    const observe = createOpenTelemetryObserver({ tracer, attributes: { service: "mcp" } });

    const result = await gate(
      { name: "read_file", risk: "read", observe },
      async () => ({ secret: "must-not-enter-span" })
    )({ token: "also-secret" });

    expect(result.ok).toBe(true);
    expect(tracer.startSpan).toHaveBeenCalledWith(
      "toolgate.read_file",
      { attributes: expect.objectContaining({ service: "mcp", "toolgate.tool": "read_file" }) }
    );
    expect(span.setStatus).toHaveBeenCalledWith({ code: 1 });
    expect(span.end).toHaveBeenCalledOnce();
    expect(JSON.stringify(tracer.startSpan.mock.calls)).not.toContain("must-not-enter-span");
    expect(JSON.stringify(tracer.startSpan.mock.calls)).not.toContain("also-secret");
  });

  it("marks blocked calls as error spans with decision codes", async () => {
    const span = createSpan();
    const observe = createOpenTelemetryObserver({ tracer: { startSpan: () => span } });

    const result = await gate({ name: "delete", requireApproval: true, observe }, async () => "never")({});

    expect(result.ok).toBe(false);
    expect(span.setAttribute).toHaveBeenCalledWith("toolgate.code", "APPROVAL_REQUIRED");
    expect(span.setStatus).toHaveBeenCalledWith({ code: 2, message: "APPROVAL_REQUIRED" });
    expect(span.end).toHaveBeenCalledOnce();
  });
});

function createSpan() {
  return {
    setAttribute: vi.fn(),
    addEvent: vi.fn(),
    setStatus: vi.fn(),
    end: vi.fn()
  };
}
