import { describe, expect, it, vi } from "vitest";
import type { AuditEntry } from "../src/audit/auditLogger.js";
import { gate } from "../src/gate/gate.js";
import { approve, createMemoryApprovalNonceStore } from "../src/index.js";

describe("approval providers", () => {
  it("executes a handler after explicit approval", async () => {
    const handler = vi.fn(async () => "deleted");
    const approval = vi.fn(async (request) =>
      request.input.path === "tmp/file.txt"
        ? approve(request, { approver: "host" })
        : { approved: false }
    );
    const protectedHandler = gate(
      {
        name: "delete_file",
        risk: "destructive",
        requireApproval: true,
        approvalSubject: "user:1",
        approval,
        policyVersion: "policy@1",
        toolVersion: "delete_file@1"
      },
      handler
    );

    const result = await protectedHandler({ path: "tmp/file.txt" });

    expect(result.ok).toBe(true);
    expect(handler).toHaveBeenCalledOnce();
    expect(approval).toHaveBeenCalledWith(
      expect.objectContaining({
        toolName: "delete_file",
        risk: "destructive",
        binding: expect.objectContaining({
          subject: "user:1",
          toolName: "delete_file",
          policyVersion: "policy@1",
          toolVersion: "delete_file@1",
          nonce: expect.any(String)
        })
      })
    );
  });

  it("returns a structured denial and audits the decision", async () => {
    const entries: AuditEntry[] = [];
    const handler = vi.fn();
    const protectedHandler = gate(
      {
        name: "send_email",
        requireApproval: true,
        approvalSubject: "user:1",
        approval: async () => ({ approved: false, reason: "User rejected", metadata: { actor: "u1" } }),
        audit: {
          log: (entry) => {
            entries.push(entry);
          }
        }
      },
      handler
    );

    const result = await protectedHandler({ to: "person@example.com" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.type).toBe("approval_denied");
      expect(result.error.code).toBe("APPROVAL_DENIED");
      expect(result.error.details?.reason).toBe("User rejected");
    }
    expect(handler).not.toHaveBeenCalled();
    expect(entries[0]).toMatchObject({ decision: "blocked", reason: "APPROVAL_DENIED" });
    expect(entries[0].metadata).toEqual({ actor: "u1" });
  });

  it("rejects approvals that are not bound to the current normalized input", async () => {
    const protectedHandler = gate(
      {
        name: "delete_file",
        requireApproval: true,
        approvalSubject: "user:1",
        approval: async (request) => approve({
          binding: { ...request.binding, inputHash: "old-input" }
        })
      },
      async () => "never"
    );

    const result = await protectedHandler({ path: "tmp/file.txt" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("APPROVAL_BINDING_MISMATCH");
    }
  });

  it("rejects replayed approval nonces", async () => {
    const store = createMemoryApprovalNonceStore();
    let firstBinding: Parameters<typeof approve>[0] | undefined;
    const protectedHandler = gate(
      {
        name: "delete_file",
        requireApproval: true,
        approvalSubject: "user:1",
        approvalNonceStore: store,
        approval: async (request) => {
          firstBinding ??= { binding: request.binding };
          return approve(firstBinding);
        }
      },
      async () => "deleted"
    );

    const first = await protectedHandler({ path: "tmp/file.txt" });
    const second = await protectedHandler({ path: "tmp/file.txt" });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.error.code).toBe("APPROVAL_BINDING_MISMATCH");
    }
  });

  it("normalizes approval provider failures", async () => {
    const protectedHandler = gate(
      {
        name: "dangerous_tool",
        requireApproval: true,
        approvalSubject: "user:1",
        approval: async () => {
          throw new Error("approval service unavailable");
        }
      },
      async () => "never"
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.type).toBe("approval_error");
      expect(result.error.details?.message).toBe("approval service unavailable");
    }
  });
});
