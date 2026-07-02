import { describe, expect, it } from "vitest";
import { createManifest } from "../src/operations/manifest/manifest.js";

describe("manifest", () => {
  it("exports public policy visibility", () => {
    const manifest = createManifest(
      [
        {
          name: "read_file",
          risk: "read",
          allowedPaths: ["src/**"],
          deniedPaths: [".env"],
          allowedDomains: ["api.github.com"],
          deniedDomains: ["metadata.google.internal"],
          allowedCommands: ["npm test"],
          deniedCommands: ["npm publish*"],
          rateLimit: {
            max: 10,
            windowMs: 60_000
          },
          audit: true,
          redact: false,
          timeoutMs: 5000
        },
        {
          name: "delete_file",
          risk: "destructive",
          requireApproval: true
        }
      ],
      { name: "filesystem-mcp" }
    );

    expect(manifest).toEqual({
      schemaVersion: "1.0",
      name: "filesystem-mcp",
      tools: [
        {
          name: "read_file",
          description: undefined,
          risk: "read",
          requiresApproval: false,
          allowedPaths: ["src/**"],
          deniedPaths: [".env"],
          allowedDomains: ["api.github.com"],
          deniedDomains: ["metadata.google.internal"],
          allowedCommands: ["npm test"],
          deniedCommands: ["npm publish*"],
          customRules: undefined,
          rateLimit: {
            max: 10,
            windowMs: 60_000,
            keyed: false,
            namespace: undefined
          },
          audit: true,
          redact: false,
          exposesPolicyDenialDetails: undefined,
          exposesRuleDenialDetails: undefined,
          timeoutMs: 5000,
          metadata: undefined
        },
        {
          name: "delete_file",
          description: undefined,
          risk: "destructive",
          requiresApproval: true,
          allowedPaths: undefined,
          deniedPaths: undefined,
          allowedDomains: undefined,
          deniedDomains: undefined,
          allowedCommands: undefined,
          deniedCommands: undefined,
          customRules: undefined,
          rateLimit: undefined,
          audit: false,
          redact: false,
          exposesPolicyDenialDetails: undefined,
          exposesRuleDenialDetails: undefined,
          timeoutMs: undefined,
          metadata: undefined
        }
      ]
    });
  });
});
