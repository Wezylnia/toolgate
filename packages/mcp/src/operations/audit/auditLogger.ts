import type { ToolRisk } from "../../core/gate/types.js";

export type AuditDecision = "allowed" | "blocked" | "failed";

export interface AuditEntry {
  timestamp: string;
  tool: string;
  risk: ToolRisk;
  decision: AuditDecision;
  requestId: string;
  previousHash?: string | null;
  entryHash?: string;
  durationMs?: number;
  reason?: string;
  input?: unknown;
  outputSummary?: Record<string, unknown>;
  error?: unknown;
  metadata?: Record<string, unknown>;
}

export interface AuditLogger {
  log(entry: AuditEntry): void | Promise<void>;
}

export interface CreateAuditLoggerOptions {
  file: string;
  failOnError?: boolean;
  hashChain?: boolean;
}
