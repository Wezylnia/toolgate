import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runCli } from "../src/operations/cli/cli.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "toolgate-cli-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("cli", () => {
  it("prints help", async () => {
    const io = createIo();

    const exitCode = await runCli(["--help"], io);

    expect(exitCode).toBe(0);
    expect(io.stdoutText()).toContain("toolgate manifest");
  });

  it("creates a manifest from config", async () => {
    const configPath = path.join(tempDir, "toolgate.config.json");
    const outPath = path.join(tempDir, "policy-manifest.json");
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: "1.0",
        name: "example-server",
        tools: [
          {
            name: "read_file",
            risk: "read",
            allowedPaths: ["src/**"],
            audit: true
          }
        ]
      }),
      "utf8"
    );

    const exitCode = await runCli(["manifest", "--config", configPath, "--out", outPath], createIo());

    expect(exitCode).toBe(0);
    const manifest = JSON.parse(await readFile(outPath, "utf8"));
    expect(manifest.name).toBe("example-server");
    expect(manifest.tools[0].name).toBe("read_file");
  });

  it("validates manifest files", async () => {
    const manifestPath = path.join(tempDir, "policy-manifest.json");
    await writeFile(
      manifestPath,
      JSON.stringify({
        schemaVersion: "1.0",
        tools: [
          {
            name: "fetch_url",
            risk: "external",
            requiresApproval: false,
            audit: true,
            redact: false
          }
        ]
      }),
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(["validate-manifest", "--file", manifestPath], io);

    expect(exitCode).toBe(0);
    expect(io.stdoutText()).toContain("Manifest is valid.");
  });

  it("validates policy config files", async () => {
    const configPath = path.join(tempDir, "toolgate.config.json");
    await writeFile(
      configPath,
      JSON.stringify({ schemaVersion: "1.0", tools: [{ name: "run", rateLimit: { max: 0, windowMs: 1000 } }] }),
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(["validate-config", "--file", configPath], io);

    expect(exitCode).toBe(1);
    expect(io.stderrText()).toContain("$.tools[0].rateLimit.max");
  });

  it("reads UTF-8 BOM JSON files", async () => {
    const configPath = path.join(tempDir, "toolgate.config.json");
    await writeFile(
      configPath,
      `\uFEFF${JSON.stringify({ schemaVersion: "1.0", tools: [{ name: "read_file" }] })}`,
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(["validate-config", "--file", configPath], io);

    expect(exitCode).toBe(0);
    expect(io.stdoutText()).toContain("Policy config is valid.");
  });

  it("returns errors for invalid manifests", async () => {
    const manifestPath = path.join(tempDir, "bad-manifest.json");
    await writeFile(manifestPath, JSON.stringify({ schemaVersion: "1.0", tools: [{ name: "" }] }), "utf8");
    const io = createIo();

    const exitCode = await runCli(["validate-manifest", "--file", manifestPath], io);

    expect(exitCode).toBe(1);
    expect(io.stderrText()).toContain("$.tools[0].name");
  });

  it("summarizes filtered audit logs as JSON", async () => {
    const auditPath = path.join(tempDir, "audit.jsonl");
    await writeFile(
      auditPath,
      `${JSON.stringify({
        timestamp: "2026-01-01T00:00:00.000Z",
        tool: "read_file",
        risk: "read",
        decision: "blocked",
        requestId: "req-1",
        reason: "PATH_DENIED",
        durationMs: 4
      })}\n`,
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(
      ["audit", "--file", auditPath, "--decision", "blocked", "--json"],
      io
    );

    expect(exitCode).toBe(0);
    expect(JSON.parse(io.stdoutText()).summary).toMatchObject({ total: 1, reasons: { PATH_DENIED: 1 } });
  });

  it("fails manifest checks when a protection is removed", async () => {
    const basePath = path.join(tempDir, "base.json");
    const headPath = path.join(tempDir, "head.json");
    await writeFile(basePath, JSON.stringify({ schemaVersion: "1.0", tools: [{ name: "delete", risk: "destructive", requiresApproval: true, audit: true, redact: true }] }), "utf8");
    await writeFile(headPath, JSON.stringify({ schemaVersion: "1.0", tools: [{ name: "delete", risk: "destructive", requiresApproval: false, audit: true, redact: true }] }), "utf8");
    const io = createIo();

    const exitCode = await runCli(["check-manifest", "--base", basePath, "--head", headPath, "--json"], io);

    expect(exitCode).toBe(1);
    const output = JSON.parse(io.stdoutText());
    expect(output.passed).toBe(false);
    expect(output.changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "APPROVAL_DISABLED", severity: "danger" })
    ]));
  });

  it("lints policy configs with machine-readable advisories", async () => {
    const configPath = path.join(tempDir, "toolgate.config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: "1.0",
        tools: [
          {
            name: "delete_file",
            risk: "destructive",
            allowedPaths: ["src/**"],
            allowedCommands: ["npm *"]
          }
        ]
      }),
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(["lint-policy", "--config", configPath, "--json"], io);

    expect(exitCode).toBe(1);
    const output = JSON.parse(io.stdoutText());
    expect(output.passed).toBe(false);
    expect(output.findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "DESTRUCTIVE_WITHOUT_APPROVAL", severity: "danger" }),
      expect.objectContaining({ code: "BROAD_COMMAND_ALLOWLIST", severity: "danger" })
    ]));
    expect(io.stdoutText()).not.toContain("npm *");
  });

  it("lints manifests with strict path mode", async () => {
    const manifestPath = path.join(tempDir, "policy-manifest.json");
    await writeFile(
      manifestPath,
      JSON.stringify({
        schemaVersion: "1.0",
        tools: [
          {
            name: "read_file",
            risk: "read",
            requiresApproval: false,
            allowedPaths: ["src/**"],
            audit: true,
            redact: true
          }
        ]
      }),
      "utf8"
    );
    const io = createIo();

    const exitCode = await runCli(["lint-manifest", "--file", manifestPath, "--strict-path-mode", "--json"], io);

    expect(exitCode).toBe(1);
    const output = JSON.parse(io.stdoutText());
    expect(output.findings).toContainEqual(expect.objectContaining({
      code: "PATH_POLICY_WITHOUT_ROOT",
      severity: "danger"
    }));
  });

  it("can fail manifest checks on head manifest lint findings", async () => {
    const basePath = path.join(tempDir, "base.json");
    const headPath = path.join(tempDir, "head.json");
    const manifest = {
      schemaVersion: "1.0",
      tools: [
        {
          name: "read_file",
          risk: "read",
          requiresApproval: false,
          allowedPaths: ["src/**"],
          audit: true,
          redact: true
        }
      ]
    };
    await writeFile(basePath, JSON.stringify(manifest), "utf8");
    await writeFile(headPath, JSON.stringify(manifest), "utf8");
    const io = createIo();

    const exitCode = await runCli(
      ["check-manifest", "--base", basePath, "--head", headPath, "--lint", "--strict-path-mode", "--json"],
      io
    );

    expect(exitCode).toBe(1);
    const output = JSON.parse(io.stdoutText());
    expect(output.changes).toEqual([]);
    expect(output.lint.passed).toBe(false);
  });

  it("migrates legacy config and manifest files", async () => {
    const oldConfig = path.join(tempDir, "old-config.json");
    const newConfig = path.join(tempDir, "new-config.json");
    const oldManifest = path.join(tempDir, "old-manifest.json");
    const newManifest = path.join(tempDir, "new-manifest.json");
    await writeFile(oldConfig, JSON.stringify({ tools: [{ name: "read" }] }), "utf8");
    await writeFile(oldManifest, JSON.stringify({ tools: [{ name: "read", risk: "read", requiresApproval: false, audit: false }] }), "utf8");

    expect(await runCli(["migrate-config", "--file", oldConfig, "--out", newConfig], createIo())).toBe(0);
    expect(await runCli(["migrate-manifest", "--file", oldManifest, "--out", newManifest], createIo())).toBe(0);
    expect(JSON.parse(await readFile(newConfig, "utf8")).schemaVersion).toBe("1.0");
    expect(JSON.parse(await readFile(newManifest, "utf8")).schemaVersion).toBe("1.0");
  });

  it("prints stable config and manifest schemas", async () => {
    const configIo = createIo();
    const manifestIo = createIo();

    expect(await runCli(["schema", "--type", "config"], configIo)).toBe(0);
    expect(await runCli(["schema", "--type", "manifest"], manifestIo)).toBe(0);
    expect(JSON.parse(configIo.stdoutText()).properties.schemaVersion.const).toBe("1.0");
    expect(JSON.parse(manifestIo.stdoutText()).properties.schemaVersion.const).toBe("1.0");
  });
});

function createIo(): {
  stdout: { write: (chunk: string) => boolean };
  stderr: { write: (chunk: string) => boolean };
  stdoutText: () => string;
  stderrText: () => string;
} {
  let stdout = "";
  let stderr = "";

  return {
    stdout: {
      write(chunk: string): boolean {
        stdout += chunk;
        return true;
      }
    },
    stderr: {
      write(chunk: string): boolean {
        stderr += chunk;
        return true;
      }
    },
    stdoutText: () => stdout,
    stderrText: () => stderr
  };
}
