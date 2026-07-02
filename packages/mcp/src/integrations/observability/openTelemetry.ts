import type { ToolGateEvent, ToolGateObserver } from "../../core/gate/types.js";

export type TelemetryAttribute = string | number | boolean | string[] | number[] | boolean[];

export interface OpenTelemetrySpanLike {
  setAttribute(name: string, value: TelemetryAttribute): unknown;
  addEvent(name: string, attributes?: Record<string, TelemetryAttribute>): unknown;
  setStatus(status: { code: 1 | 2; message?: string }): unknown;
  end(endTime?: unknown): unknown;
}

export interface OpenTelemetryTracerLike {
  startSpan(
    name: string,
    options?: { attributes?: Record<string, TelemetryAttribute> }
  ): OpenTelemetrySpanLike;
}

export interface OpenTelemetryObserverOptions {
  tracer: OpenTelemetryTracerLike;
  spanName?: string | ((event: Extract<ToolGateEvent, { type: "started" }>) => string);
  attributes?: Record<string, TelemetryAttribute>;
}

export function createOpenTelemetryObserver(
  options: OpenTelemetryObserverOptions
): ToolGateObserver {
  const spans = new Map<string, OpenTelemetrySpanLike>();

  return async (event) => {
    if (event.type === "started") {
      const name = typeof options.spanName === "function"
        ? options.spanName(event)
        : options.spanName ?? `toolgate.${event.toolName}`;
      const span = options.tracer.startSpan(name, {
        attributes: {
          ...options.attributes,
          "toolgate.request_id": event.requestId,
          "toolgate.tool": event.toolName,
          "toolgate.risk": event.risk
        }
      });
      spans.set(event.requestId, span);
      return;
    }

    const span = spans.get(event.requestId);
    if (!span) return;
    if (event.type === "approved") {
      span.addEvent("toolgate.approved");
      return;
    }

    try {
      span.setAttribute("toolgate.duration_ms", event.durationMs);
      if (event.type === "completed") {
        span.setAttribute("toolgate.outcome", "completed");
        span.setStatus({ code: 1 });
      } else {
        span.setAttribute("toolgate.outcome", event.type);
        span.setAttribute("toolgate.code", event.code);
        span.addEvent(`toolgate.${event.type}`, { "toolgate.code": event.code });
        span.setStatus({ code: 2, message: event.code });
      }
      span.end();
    } finally {
      spans.delete(event.requestId);
    }
  };
}
