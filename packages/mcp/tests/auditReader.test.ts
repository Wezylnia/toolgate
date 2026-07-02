import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readAuditLog, summarizeAudit } from "../src/operations/audit/readAuditLog.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "toolgate-audit-reader-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("audit reader", () => {
  it("filters entries and keeps the most recent limited matches", async () => {
    const file = await writeAuditFile([
      entry("2026-01-01T00:00:00.000Z", "read_file", "allowed", 10),
      entry("2026-01-02T00:00:00.000Z", "delete_file", "blocked", 20, "APPROVAL_DENIED"),
      entry("2026-01-03T00:00:00.000Z", "delete_file", "blocked", 30, "PATH_DENIED")
    ]);

    const result = await readAuditLog(file, { tool: "delete_file", decision: "blocked", limit: 1 });

    expect(result.issues).toEqual([]);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].reason).toBe("PATH_DENIED");
  });

  it("reports malformed lines without discarding valid entries", async () => {
    const file = path.join(tempDir, "audit.jsonl");
    await writeFile(file, `${JSON.stringify(entry("2026-01-01T00:00:00.000Z", "read", "allowed", 5))}\nnot-json\n`, "utf8");

    const result = await readAuditLog(file);

    expect(result.entries).toHaveLength(1);
    expect(result.issues[0].line).toBe(2);
  });

  it("summarizes decisions, tools, reasons, and duration", () => {
    const summary = summarizeAudit([
      entry("2026-01-01T00:00:00.000Z", "read", "allowed", 10),
      entry("2026-01-01T00:01:00.000Z", "read", "blocked", 20, "PATH_DENIED")
    ]);

    expect(summary).toMatchObject({
      total: 2,
      decisions: { allowed: 1, blocked: 1, failed: 0 },
      tools: { read: 2 },
      reasons: { PATH_DENIED: 1 },
      averageDurationMs: 15
    });
  });
});

function entry(
  timestamp: string,
  tool: string,
  decision: "allowed" | "blocked" | "failed",
  durationMs: number,
  reason?: string
) {
  return { timestamp, tool, risk: "read" as const, decision, requestId: `${tool}-${timestamp}`, durationMs, reason };
}

async function writeAuditFile(entries: unknown[]): Promise<string> {
  const file = path.join(tempDir, "audit.jsonl");
  await writeFile(file, `${entries.map((value) => JSON.stringify(value)).join("\n")}\n`, "utf8");
  return file;
}
