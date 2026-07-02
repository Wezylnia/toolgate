import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = path.join(".test-tmp", `toolgate-fs-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  await mkdir(path.join(tempDir, "src"), { recursive: true });
  await writeFile(path.join(tempDir, "src", "index.ts"), "export const ok = true;\n");
  await writeFile(path.join(tempDir, ".env"), "TOKEN=secret\n");
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("filesystem integration", () => {
  it("allows safe file access and blocks denied paths", async () => {
    const readFileTool = gate(
      {
        name: "read_file",
        risk: "read",
        allowedPaths: [`${tempDir.replaceAll("\\", "/")}/src/**`],
        deniedPaths: [`${tempDir.replaceAll("\\", "/")}/.env`],
        redact: true
      },
      async ({ path: filePath }: { path: string }) => ({
        content: await readFile(filePath, "utf8")
      })
    );

    const allowed = await readFileTool({ path: path.join(tempDir, "src", "index.ts") });
    expect(allowed.ok).toBe(true);
    if (allowed.ok) {
      expect(allowed.data.content).toContain("ok");
    }

    const blocked = await readFileTool({ path: path.join(tempDir, ".env") });
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) {
      expect(blocked.error.code).toBe("PATH_DENIED");
    }
  });

  it("blocks destructive tools that require approval", async () => {
    let deleted = false;
    const deleteFileTool = gate(
      {
        name: "delete_file",
        risk: "destructive",
        requireApproval: true,
        allowedPaths: ["src/**"]
      },
      async () => {
        deleted = true;
        return { ok: true };
      }
    );

    const result = await deleteFileTool({ path: "src/index.ts" });

    expect(deleted).toBe(false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("APPROVAL_REQUIRED");
    }
  });

  it("returns a structured timeout result", async () => {
    const slowTool = gate(
      {
        name: "slow_tool",
        timeoutMs: 5
      },
      async () => {
        await new Promise((resolve) => setTimeout(resolve, 25));
        return { ok: true };
      }
    );

    const result = await slowTool({});

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TOOL_TIMEOUT");
    }
  });
});
