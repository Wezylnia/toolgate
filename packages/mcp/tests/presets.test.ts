import { describe, expect, it } from "vitest";
import {
  destructiveFilesystemPolicy,
  externalApiPolicy,
  readOnlyFilesystemPolicy
} from "../src/policies/presets/presets.js";

describe("policy presets", () => {
  it("creates a read-only filesystem policy", () => {
    expect(
      readOnlyFilesystemPolicy({
        name: "read_file",
        allowedPaths: ["src/**"]
      })
    ).toMatchObject({
      name: "read_file",
      risk: "read",
      allowedPaths: ["src/**"],
      deniedPaths: [".env", "secrets/**", "node_modules/**"],
      redact: true
    });
  });

  it("creates a destructive filesystem policy requiring approval", () => {
    expect(
      destructiveFilesystemPolicy({
        name: "delete_file"
      })
    ).toMatchObject({
      name: "delete_file",
      risk: "destructive",
      requireApproval: true,
      redact: true
    });
  });

  it("creates an external API policy", () => {
    expect(
      externalApiPolicy({
        name: "fetch_url",
        allowedDomains: ["api.github.com"]
      })
    ).toMatchObject({
      name: "fetch_url",
      risk: "external",
      allowedDomains: ["api.github.com"],
      timeoutMs: 10_000,
      redact: true
    });
  });
});
