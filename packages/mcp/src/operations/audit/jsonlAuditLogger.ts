import { mkdir, appendFile, readFile } from "node:fs/promises";
import path from "node:path";
import { safeJsonStringify } from "../../shared/utils/safeJson.js";
import type { AuditEntry, AuditLogger, CreateAuditLoggerOptions } from "./auditLogger.js";
import { chainAuditEntry } from "./auditIntegrity.js";

export function createAuditLogger(options: CreateAuditLoggerOptions): AuditLogger {
  let previousHash: string | null | undefined;

  return {
    async log(entry: AuditEntry): Promise<void> {
      try {
        await mkdir(path.dirname(options.file), { recursive: true });
        const auditEntry = options.hashChain
          ? chainAuditEntry(entry, previousHash ?? await readLastHash(options.file))
          : entry;
        previousHash = auditEntry.entryHash ?? null;
        await appendFile(options.file, `${safeJsonStringify(auditEntry)}\n`, "utf8");
      } catch (error) {
        if (options.failOnError) {
          throw error;
        }
      }
    }
  };
}

async function readLastHash(file: string): Promise<string | null> {
  try {
    const content = await readFile(file, "utf8");
    const lastLine = content.trim().split(/\r?\n/).filter(Boolean).at(-1);
    if (!lastLine) return null;
    const value = JSON.parse(lastLine) as { entryHash?: unknown };
    return typeof value.entryHash === "string" ? value.entryHash : null;
  } catch {
    return null;
  }
}
