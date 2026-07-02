import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditDecision, AuditEntry } from "./auditLogger.js";

export interface AuditQuery {
  tool?: string;
  decision?: AuditDecision;
  reason?: string;
  since?: string | Date;
  until?: string | Date;
  limit?: number;
}

export interface AuditReadIssue {
  line: number;
  message: string;
}

export interface AuditReadResult {
  entries: AuditEntry[];
  issues: AuditReadIssue[];
}

export interface AuditSummary {
  total: number;
  decisions: Record<AuditDecision, number>;
  tools: Record<string, number>;
  reasons: Record<string, number>;
  averageDurationMs: number | null;
}

export async function readAuditLog(file: string, query: AuditQuery = {}): Promise<AuditReadResult> {
  const range = normalizeRange(query);
  const entries: AuditEntry[] = [];
  const issues: AuditReadIssue[] = [];
  const lines = createInterface({
    input: createReadStream(file, { encoding: "utf8" }),
    crlfDelay: Infinity
  });
  let lineNumber = 0;

  for await (const line of lines) {
    lineNumber += 1;
    if (line.trim().length === 0) {
      continue;
    }
    try {
      const value: unknown = JSON.parse(line);
      const issue = validateAuditEntry(value);
      if (issue) {
        issues.push({ line: lineNumber, message: issue });
        continue;
      }
      const entry = value as AuditEntry;
      if (!matchesQuery(entry, query, range)) {
        continue;
      }
      entries.push(entry);
      if (query.limit !== undefined && entries.length > query.limit) {
        entries.shift();
      }
    } catch (error) {
      issues.push({
        line: lineNumber,
        message: error instanceof Error ? error.message : "Invalid JSON."
      });
    }
  }

  return { entries, issues };
}

export function summarizeAudit(entries: AuditEntry[]): AuditSummary {
  const summary: AuditSummary = {
    total: entries.length,
    decisions: { allowed: 0, blocked: 0, failed: 0 },
    tools: {},
    reasons: {},
    averageDurationMs: null
  };
  let durationTotal = 0;
  let durationCount = 0;

  for (const entry of entries) {
    summary.decisions[entry.decision] += 1;
    summary.tools[entry.tool] = (summary.tools[entry.tool] ?? 0) + 1;
    if (entry.reason) {
      summary.reasons[entry.reason] = (summary.reasons[entry.reason] ?? 0) + 1;
    }
    if (typeof entry.durationMs === "number" && Number.isFinite(entry.durationMs)) {
      durationTotal += entry.durationMs;
      durationCount += 1;
    }
  }

  summary.averageDurationMs = durationCount === 0 ? null : durationTotal / durationCount;
  return summary;
}

function normalizeRange(query: AuditQuery): { since?: number; until?: number } {
  if (query.decision !== undefined && !["allowed", "blocked", "failed"].includes(query.decision)) {
    throw new TypeError("Audit query decision must be allowed, blocked, or failed.");
  }
  if (query.limit !== undefined && (!Number.isInteger(query.limit) || query.limit <= 0)) {
    throw new TypeError("Audit query limit must be a positive integer.");
  }
  return {
    since: normalizeDate(query.since, "since"),
    until: normalizeDate(query.until, "until")
  };
}

function normalizeDate(value: string | Date | undefined, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  const timestamp = value instanceof Date ? value.getTime() : Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new TypeError(`Audit query ${name} must be a valid date.`);
  }
  return timestamp;
}

function matchesQuery(
  entry: AuditEntry,
  query: AuditQuery,
  range: { since?: number; until?: number }
): boolean {
  if (query.tool && entry.tool !== query.tool) return false;
  if (query.decision && entry.decision !== query.decision) return false;
  if (query.reason && entry.reason !== query.reason) return false;
  const timestamp = Date.parse(entry.timestamp);
  if (range.since !== undefined && timestamp < range.since) return false;
  if (range.until !== undefined && timestamp > range.until) return false;
  return true;
}

function validateAuditEntry(value: unknown): string | undefined {
  if (!isRecord(value)) return "Audit entry must be an object.";
  if (typeof value.timestamp !== "string" || !Number.isFinite(Date.parse(value.timestamp))) {
    return "Audit entry timestamp must be a valid date string.";
  }
  if (typeof value.tool !== "string" || value.tool.length === 0) return "Audit entry tool is invalid.";
  if (!["read", "write", "external", "destructive"].includes(String(value.risk))) {
    return "Audit entry risk is invalid.";
  }
  if (!["allowed", "blocked", "failed"].includes(String(value.decision))) {
    return "Audit entry decision is invalid.";
  }
  if (typeof value.requestId !== "string" || value.requestId.length === 0) {
    return "Audit entry requestId is invalid.";
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
