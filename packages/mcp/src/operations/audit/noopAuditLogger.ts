import type { AuditEntry, AuditLogger } from "./auditLogger.js";

export const noopAuditLogger: AuditLogger = {
  log(_entry: AuditEntry): void {
    // Intentionally empty.
  }
};
