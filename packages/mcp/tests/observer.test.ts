import { describe, expect, it, vi } from "vitest";
import type { ToolGateEvent } from "../src/core/gate/types.js";
import { gate } from "../src/core/gate/gate.js";
import { approve } from "../src/index.js";

describe("lifecycle observer", () => {
  it("emits started, approved, and completed events", async () => {
    const events: ToolGateEvent[] = [];
    const protectedHandler = gate(
      {
        name: "delete_file",
        risk: "destructive",
        requireApproval: true,
        approvalSubject: "user:1",
        approval: (request) => approve(request),
        observe: (event) => { events.push(event); }
      },
      async () => ({ deleted: true })
    );

    const result = await protectedHandler({ path: "tmp/file" });

    expect(result.ok).toBe(true);
    expect(events.map((event) => event.type)).toEqual(["started", "approved", "completed"]);
    expect(new Set(events.map((event) => event.requestId)).size).toBe(1);
    expect(events[2]).toMatchObject({
      toolName: "delete_file",
      risk: "destructive",
      outputSummary: { type: "object" }
    });
  });

  it("emits blocked and failed outcomes", async () => {
    const blocked: ToolGateEvent[] = [];
    const failed: ToolGateEvent[] = [];
    await gate(
      { name: "blocked", requireApproval: true, observe: (event) => { blocked.push(event); } },
      async () => "never"
    )({});
    await gate(
      { name: "failed", observe: (event) => { failed.push(event); } },
      async () => { throw new Error("boom"); }
    )({});

    expect(blocked.map((event) => event.type)).toEqual(["started", "blocked"]);
    expect(blocked[1]).toMatchObject({ code: "APPROVAL_REQUIRED" });
    expect(failed.map((event) => event.type)).toEqual(["started", "failed"]);
    expect(failed[1]).toMatchObject({ code: "HANDLER_ERROR" });
  });

  it("isolates observer failures from the tool result", async () => {
    const observe = vi.fn(async () => { throw new Error("telemetry offline"); });
    const result = await gate({ name: "echo", observe }, async () => "ok")({});

    expect(result.ok).toBe(true);
    expect(observe).toHaveBeenCalledTimes(2);
  });
});
