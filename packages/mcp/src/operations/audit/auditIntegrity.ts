import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditEntry } from "./auditLogger.js";

export interface AuditVerificationIssue {
  line: number;
  code: "INVALID_JSON" | "INVALID_ENTRY" | "HASH_MISMATCH" | "CHAIN_BROKEN" | "DUPLICATE_REQUEST_ID" | "TIMESTAMP_REGRESSED";
  message: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  entries: number;
  issues: AuditVerificationIssue[];
  lastHash?: string;
}

export function hashAuditEntry(entry: AuditEntry): string {
  const { entryHash, ...hashable } = entry;
  return createHash("sha256").update(stableJson(hashable)).digest("hex");
}

export function chainAuditEntry(entry: AuditEntry, previousHash: string | null = null): AuditEntry {
  const chained: AuditEntry = { ...entry, previousHash };
  return { ...chained, entryHash: hashAuditEntry(chained) };
}

export async function verifyAuditLog(file: string): Promise<AuditVerificationResult> {
  const entries: AuditEntry[] = [];
  const issues: AuditVerificationIssue[] = [];
  const lines = createInterface({
    input: createReadStream(file, { encoding: "utf8" }),
    crlfDelay: Infinity
  });
  let line = 0;

  for await (const raw of lines) {
    line += 1;
    const normalizedLine = line === 1 ? raw.replace(/^\uFEFF/, "") : raw;
    if (normalizedLine.trim().length === 0) continue;
    try {
      const value: unknown = JSON.parse(normalizedLine);
      if (!isAuditEntry(value)) {
        issues.push({ line, code: "INVALID_ENTRY", message: "Audit entry is malformed." });
        continue;
      }
      entries.push(value);
    } catch (error) {
      issues.push({
        line,
        code: "INVALID_JSON",
        message: error instanceof Error ? error.message : "Invalid JSON."
      });
    }
  }

  return verifyAuditEntries(entries, issues);
}

export function verifyAuditEntries(
  entries: AuditEntry[],
  existingIssues: AuditVerificationIssue[] = []
): AuditVerificationResult {
  const issues = [...existingIssues];
  const requestIds = new Set<string>();
  let previousHash: string | null = null;
  let previousTimestamp = 0;
  let line = 0;

  for (const entry of entries) {
    line += 1;
    if (requestIds.has(entry.requestId)) {
      issues.push({ line, code: "DUPLICATE_REQUEST_ID", message: "Audit requestId is duplicated." });
    }
    requestIds.add(entry.requestId);

    const timestamp = Date.parse(entry.timestamp);
    if (Number.isFinite(timestamp) && previousTimestamp > timestamp) {
      issues.push({ line, code: "TIMESTAMP_REGRESSED", message: "Audit timestamps moved backwards." });
    }
    if (Number.isFinite(timestamp)) previousTimestamp = timestamp;

    if (entry.entryHash) {
      if ((entry.previousHash ?? null) !== previousHash) {
        issues.push({ line, code: "CHAIN_BROKEN", message: "Audit hash chain previousHash is not continuous." });
      }
      const actual = hashAuditEntry(entry);
      if (actual !== entry.entryHash) {
        issues.push({ line, code: "HASH_MISMATCH", message: "Audit entry hash does not match entry content." });
      }
      previousHash = entry.entryHash;
    } else {
      previousHash = null;
    }
  }

  return {
    valid: issues.length === 0,
    entries: entries.length,
    issues,
    lastHash: previousHash ?? undefined
  };
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

function isAuditEntry(value: unknown): value is AuditEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return typeof record.timestamp === "string"
    && typeof record.tool === "string"
    && typeof record.risk === "string"
    && typeof record.decision === "string"
    && typeof record.requestId === "string";
}
