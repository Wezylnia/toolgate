import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";

describe("path policy", () => {
  it("lets denylist win over allowlist", async () => {
    const protectedHandler = gate(
      {
        name: "read_file",
        allowedPaths: ["src/**", ".env"],
        deniedPaths: [".env"]
      },
      async () => "secret"
    );

    const result = await protectedHandler({ path: ".env" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PATH_DENIED");
    }
  });

  it("denies paths outside allowlist", async () => {
    const protectedHandler = gate(
      {
        name: "read_file",
        allowedPaths: ["src/**"]
      },
      async () => "ok"
    );

    const result = await protectedHandler({ filePath: "docs/readme.md" });

    expect(result.ok).toBe(false);
  });

  it("normalizes mixed slashes", async () => {
    const protectedHandler = gate(
      {
        name: "read_file",
        allowedPaths: ["src/**"]
      },
      async () => "ok"
    );

    const result = await protectedHandler({ targetPath: "src\\index.ts" });

    expect(result.ok).toBe(true);
  });

  it("blocks traversal attempts", async () => {
    const protectedHandler = gate(
      {
        name: "read_file",
        allowedPaths: ["src/**"]
      },
      async () => "ok"
    );

    const result = await protectedHandler({ path: "../.env" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PATH_DENIED");
    }
  });

  it("resolves symlinks before matching pathRoot-scoped globs", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "toolgate-path-"));
    const workspace = path.join(tempDir, "workspace");
    const outside = path.join(tempDir, "outside");
    await mkdir(path.join(workspace, "src"), { recursive: true });
    await mkdir(outside, { recursive: true });
    await writeFile(path.join(outside, "secret.txt"), "secret");
    try {
      await symlink(outside, path.join(workspace, "src", "outside"), "junction");
    } catch {
      await rm(tempDir, { recursive: true, force: true });
      return;
    }

    const protectedHandler = gate(
      {
        name: "read_file",
        pathRoot: workspace,
        allowedPaths: ["src/**"]
      },
      async () => "secret"
    );

    const result = await protectedHandler({ path: "src/outside/secret.txt" });

    await rm(tempDir, { recursive: true, force: true });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PATH_DENIED");
      expect(result.error.details).toEqual({ reasonCode: "PATH_OUTSIDE_ROOT" });
    }
  });
});
