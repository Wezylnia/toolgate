import { describe, expect, it } from "vitest";
import { gate } from "../src/gate/gate.js";

describe("custom input extractors", () => {
  it("uses extractPaths when provided", async () => {
    const protectedHandler = gate(
      {
        name: "read_file",
        allowedPaths: ["workspace/**"],
        extractPaths: (input) => {
          const record = input as { nested?: { filename?: string } };
          return record.nested?.filename;
        }
      },
      async () => ({ ok: true })
    );

    const allowed = await protectedHandler({ nested: { filename: "workspace/readme.md" } });
    const blocked = await protectedHandler({ nested: { filename: "secrets/token.txt" } });

    expect(allowed.ok).toBe(true);
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) {
      expect(blocked.error.code).toBe("PATH_DENIED");
    }
  });

  it("supports extractors returning multiple paths", async () => {
    const protectedHandler = gate(
      {
        name: "copy_files",
        allowedPaths: ["src/**"],
        deniedPaths: ["src/secrets/**"],
        extractPaths: (input) => {
          const record = input as { from: string; to: string };
          return [record.from, record.to];
        }
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({
      from: "src/index.ts",
      to: "src/secrets/output.ts"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PATH_DENIED");
      expect(result.error.details).toEqual({ reasonCode: "PATH_DENYLIST_MATCH" });
    }
  });

  it("can expose built-in policy denial details when explicitly configured", async () => {
    const protectedHandler = gate(
      {
        name: "copy_files",
        allowedPaths: ["src/**"],
        deniedPaths: ["src/secrets/**"],
        exposePolicyDenialDetails: true,
        extractPaths: (input) => {
          const record = input as { from: string; to: string };
          return [record.from, record.to];
        }
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({
      from: "src/index.ts",
      to: "src/secrets/output.ts"
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({
        path: "src/secrets/output.ts",
        reasonCode: "PATH_DENYLIST_MATCH"
      });
    }
  });
});
