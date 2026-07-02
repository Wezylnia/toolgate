import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createAuditLogger } from "../src/operations/audit/jsonlAuditLogger.js";
import { gate } from "../src/core/gate/gate.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "toolgate-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("audit logger", () => {
  it("writes redacted JSONL entries", async () => {
    const auditFile = path.join(tempDir, "audit.jsonl");
    const protectedHandler = gate(
      {
        name: "read_file",
        audit: createAuditLogger({ file: auditFile }),
        redact: true
      },
      async () => ({ content: "hello" })
    );

    await protectedHandler({ path: "src/index.ts", token: "secret" });

    const lines = (await readFile(auditFile, "utf8")).trim().split("\n");
    expect(lines).toHaveLength(1);
    const entry = JSON.parse(lines[0]);
    expect(entry.tool).toBe("read_file");
    expect(entry.decision).toBe("allowed");
    expect(entry.input.token).toBe("[REDACTED]");
  });

  it("uses the default JSONL audit file when audit is true", async () => {
    await rm(".toolgate", { recursive: true, force: true });
    const protectedHandler = gate(
      {
        name: "default_audit",
        audit: true
      },
      async () => ({ ok: true })
    );

    await protectedHandler({ path: "src/index.ts" });

    const lines = (await readFile(path.join(".toolgate", "audit.jsonl"), "utf8"))
      .trim()
      .split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).tool).toBe("default_audit");
    await rm(".toolgate", { recursive: true, force: true });
  });

  it("does not crash when audit input contains circular or bigint values", async () => {
    const auditFile = path.join(tempDir, "safe-audit.jsonl");
    const input: Record<string, unknown> = { count: 1n };
    input.self = input;
    const protectedHandler = gate(
      {
        name: "safe_audit",
        audit: createAuditLogger({ file: auditFile }),
        redact: true
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler(input);

    expect(result.ok).toBe(true);
    const entry = JSON.parse((await readFile(auditFile, "utf8")).trim());
    expect(entry.input.count).toBe("1");
    expect(entry.input.self).toBe("[Circular]");
  });
});
