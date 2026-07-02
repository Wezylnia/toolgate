# Approvals

`requireApproval: true` blocks a tool unless the host supplies an approval provider and the
provider explicitly approves that call. ToolGateKit does not render an approval interface.

```ts
import { gate } from "toolgate-mcp";

const deleteFile = gate(
  {
    name: "delete_file",
    risk: "destructive",
    requireApproval: true,
    approvalSubject: () => currentSession.userId,
    policyVersion: "filesystem-policy@2026-07-02",
    toolVersion: "delete_file@1.3.0",
    approval: async (request) => {
      const decision = await approvalService.request({
        input: request.input,
        requestId: request.requestId,
        binding: request.binding
      });
      return {
        approved: decision.approved,
        binding: decision.approved ? request.binding : undefined,
        reason: decision.reason,
        metadata: { approverId: decision.approverId }
      };
    }
  },
  async ({ path }) => {
    await fs.rm(path);
    return { deleted: path };
  }
);
```

Approved decisions must return the same `binding` that ToolGateKit sent in the approval request.
The binding includes the authenticated subject, exact tool name, stable input hash, policy version,
tool version, expiry, and one-time nonce. Boolean approvals and unbound `{ approved: true }`
decisions fail closed as `APPROVAL_BINDING_MISSING` or `APPROVAL_BINDING_MISMATCH`.

- No provider returns `APPROVAL_REQUIRED`.
- A rejected decision returns `APPROVAL_DENIED` and does not call the handler.
- A provider failure returns `APPROVAL_ERROR` and does not call the handler.
- A malformed, expired, mismatched, or replayed approval returns a machine-readable approval error
  and does not call the handler.
- Approval metadata is merged into the final audit entry.

Use `approve(request)` and `denyApproval(reason)` for the common provider shape:

```ts
approval: async (request) => {
  const allowed = await approvalService.confirm(request.binding);
  return allowed ? approve(request, { approverId: "u1" }) : denyApproval("Rejected");
}
```

The host still owns authentication and the approval UI. ToolGateKit enforces that the returned
decision is bound to the current protected call and consumes each approval nonce once.
