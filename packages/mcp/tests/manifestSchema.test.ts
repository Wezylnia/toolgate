import { describe, expect, it } from "vitest";
import { createManifest } from "../src/operations/manifest/manifest.js";
import { policyManifestSchema, validateManifest } from "../src/operations/manifest/schema.js";

describe("manifest schema", () => {
  it("validates manifests created by createManifest", () => {
    const manifest = createManifest(
      [
        {
          name: "fetch_url",
          risk: "external",
          allowedDomains: ["api.github.com"],
          rateLimit: {
            max: 10,
            windowMs: 60_000
          },
          audit: true
        }
      ],
      { name: "example-server" }
    );

    expect(validateManifest(manifest)).toEqual({
      valid: true,
      issues: []
    });
  });

  it("reports invalid manifest fields", () => {
    const result = validateManifest({
      schemaVersion: "1.0",
      tools: [
        {
          name: "",
          risk: "danger",
          requiresApproval: "yes",
          audit: "true",
          redact: false,
          allowedDomains: [42],
          rateLimit: {
            max: 0,
            windowMs: -1
          }
        }
      ]
    });

    expect(result.valid).toBe(false);
    expect(result.issues.map((issue) => issue.path)).toEqual([
      "$.tools[0].name",
      "$.tools[0].risk",
      "$.tools[0].requiresApproval",
      "$.tools[0].audit",
      "$.tools[0].allowedDomains",
      "$.tools[0].rateLimit.max",
      "$.tools[0].rateLimit.windowMs"
    ]);
  });

  it("exports a JSON schema object", () => {
    expect(policyManifestSchema.title).toBe("ToolGateKit Policy Manifest");
    expect(policyManifestSchema.required).toEqual(["schemaVersion", "tools"]);
  });
});
