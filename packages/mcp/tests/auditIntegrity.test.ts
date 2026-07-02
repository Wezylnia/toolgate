import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  chainAuditEntry,
  createAuditLogger,
  hashAuditEntry,
  verifyAuditLog
} from "../src/index.js";
import { runCli } from "../src/operations/cli/cli.js";
import type { AuditEntry } from "../src/index.js";

describe("audit integrity", () => {
  it("writes and verifies hash-chained audit entries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "toolgate-audit-"));
    const file = join(dir, "audit.jsonl");
    try {
      const logger = createAuditLogger({ file, hashChain: true, failOnError: true });
      await logger.log(entry("a", "2026-07-02T00:00:00.000Z"));
      await logger.log(entry("b", "2026-07-02T00:00:01.000Z"));

      const verification = await verifyAuditLog(file);
      expect(verification).toMatchObject({ valid: true, entries: 2, issues: [] });
      expect(verification.lastHash).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("detects tampered chained audit entries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "toolgate-audit-"));
    const file = join(dir, "audit.jsonl");
    try {
      const first = chainAuditEntry(entry("a", "2026-07-02T00:00:00.000Z"));
      const second = chainAuditEntry(entry("b", "2026-07-02T00:00:01.000Z"), first.entryHash);
      await writeFile(file, `${JSON.stringify(first)}\n${JSON.stringify({ ...second, decision: "blocked" })}\n`, "utf8");

      const verification = await verifyAuditLog(file);
      expect(verification.valid).toBe(false);
      expect(verification.issues.map((issue) => issue.code)).toContain("HASH_MISMATCH");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("supports audit verify and export CLI commands", async () => {
    const dir = await mkdtemp(join(tmpdir(), "toolgate-audit-"));
    const file = join(dir, "audit.jsonl");
    try {
      await writeFile(file, `${JSON.stringify(chainAuditEntry(entry("a", "2026-07-02T00:00:00.000Z")))}\n`, "utf8");
      let stdout = "";
      let stderr = "";
      const io = {
        stdout: { write: (chunk: string) => { stdout += chunk; return true; } },
        stderr: { write: (chunk: string) => { stderr += chunk; return true; } }
      };

      await expect(runCli(["audit", "verify", "--file", file, "--json"], io)).resolves.toBe(0);
      expect(JSON.parse(stdout)).toMatchObject({ valid: true, entries: 1 });
      expect(stderr).toBe("");

      stdout = "";
      await expect(runCli(["audit", "export", "--file", file, "--format", "ndjson"], io)).resolves.toBe(0);
      expect(stdout.trim().split("\n")).toHaveLength(1);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("hashes audit entry content without entryHash", () => {
    const chained = chainAuditEntry(entry("a", "2026-07-02T00:00:00.000Z"));
    expect(hashAuditEntry({ ...chained, entryHash: "changed" })).toBe(chained.entryHash);
  });
});

function entry(requestId: string, timestamp: string): AuditEntry {
  return {
    timestamp,
    tool: "read_file",
    risk: "read",
    decision: "allowed",
    requestId,
    durationMs: 1,
    input: { path: "README.md" }
  };
}
