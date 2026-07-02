import { describe, expect, it } from "vitest";
import { migrateManifest } from "../src/operations/manifest/migrate.js";
import {
  createManifestFromConfig,
  policyConfigSchema,
  validatePolicyConfig
} from "../src/policies/config/configSchema.js";
import { migratePolicyConfig } from "../src/policies/config/migrateConfig.js";

describe("v1 schemas", () => {
  it("validates and converts a stable policy config", () => {
    const config = {
      schemaVersion: "1.0" as const,
      name: "server",
      tools: [{ name: "read_file", risk: "read" as const, deniedPaths: [".env"], audit: true }]
    };

    expect(validatePolicyConfig(config)).toEqual({ valid: true, issues: [] });
    expect(createManifestFromConfig(config)).toMatchObject({
      schemaVersion: "1.0",
      name: "server",
      tools: [{ name: "read_file", requiresApproval: false, audit: true, redact: false }]
    });
    expect(policyConfigSchema.required).toEqual(["schemaVersion", "tools"]);
  });

  it("rejects unknown config fields", () => {
    const result = validatePolicyConfig({
      schemaVersion: "1.0",
      tools: [{ name: "read", unrestricted: true }]
    });

    expect(result.valid).toBe(false);
    expect(result.issues).toContainEqual({
      path: "$.tools[0].unrestricted",
      message: "Unknown policy field."
    });
  });

  it("migrates valid pre-v1 manifests and configs", () => {
    const manifest = migrateManifest({
      tools: [{ name: "read", risk: "read", requiresApproval: false, audit: true }]
    });
    const config = migratePolicyConfig({ tools: [{ name: "read" }] });

    expect(manifest.schemaVersion).toBe("1.0");
    expect(manifest.tools[0].redact).toBe(false);
    expect(config.schemaVersion).toBe("1.0");
  });

  it("keeps the manual manifest validator strict with the JSON Schema", async () => {
    const { validateManifest } = await import("../src/operations/manifest/schema.js");
    const result = validateManifest({
      schemaVersion: "1.0",
      unexpected: true,
      tools: [
        { name: "same", risk: "read", requiresApproval: false, audit: false, redact: false, extra: true },
        { name: "same", risk: "read", requiresApproval: false, audit: false, redact: false }
      ]
    });

    expect(result.valid).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual(expect.arrayContaining([
      "$.unexpected",
      "$.tools[0].extra",
      "$.tools[1].name"
    ]));
  });

  it("does not hide invalid legacy data during migration", () => {
    expect(() => migrateManifest({ tools: [{ name: "" }] })).toThrow("Invalid policy manifest");
    expect(() => migratePolicyConfig({ tools: [{ name: "", timeoutMs: 0 }] })).toThrow("Invalid tool policy");
  });
});
