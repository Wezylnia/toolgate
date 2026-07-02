import type { ToolGateContext, ToolGateEvent, ToolPolicy } from "../../core/gate/types.js";

export async function emitToolGateEvent(
  policy: ToolPolicy,
  context: ToolGateContext,
  event: ToolGateEventPayload
): Promise<void> {
  if (!policy.observe) {
    return;
  }
  const value = {
    ...event,
    requestId: context.requestId,
    toolName: context.toolName,
    risk: context.risk,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - context.startedAt.getTime()
  } as ToolGateEvent;
  try {
    await policy.observe(value);
  } catch {
    // Observability must not change the tool result.
  }
}

type ToolGateEventPayload =
  | { type: "started" }
  | { type: "approved" }
  | { type: "blocked"; code: string }
  | { type: "completed"; outputSummary: Record<string, unknown> }
  | { type: "failed"; code: string };
