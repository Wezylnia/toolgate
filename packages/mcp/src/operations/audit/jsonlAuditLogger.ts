import { mkdir, appendFile } from "node:fs/promises";
import path from "node:path";
import { safeJsonStringify } from "../../shared/utils/safeJson.js";
import type { AuditEntry, AuditLogger, CreateAuditLoggerOptions } from "./auditLogger.js";

export function createAuditLogger(options: CreateAuditLoggerOptions): AuditLogger {
  return {
    async log(entry: AuditEntry): Promise<void> {
      try {
        await mkdir(path.dirname(options.file), { recursive: true });
        await appendFile(options.file, `${safeJsonStringify(entry)}\n`, "utf8");
      } catch (error) {
        if (options.failOnError) {
          throw error;
        }
      }
    }
  };
}
