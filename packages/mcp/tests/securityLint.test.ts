import { describe, expect, it } from "vitest";
import {
  strictPathPolicy,
  summarizePolicySecurity,
  validateManifestSecurity,
  validatePolicyConfigSecurity,
  validatePolicySecurity
} from "../src/index.js";

describe("security lint", () => {
  it("reports stable advisories without echoing secret policy values", () => {
    const findings = validatePolicySecurity({
      name: "run_command",
      risk: "destructive",
      allowedCommands: ["npm run *"],
      allowedPaths: ["secrets/**"],
      allowedDomains: ["*.com"],
      rateLimit: { max: 5, windowMs: 60_000 },
      exposeRuleDenialDetails: true
    });

    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "DESTRUCTIVE_WITHOUT_APPROVAL", severity: "danger" }),
      expect.objectContaining({ code: "PATH_POLICY_WITHOUT_ROOT", severity: "warning" }),
      expect.objectContaining({ code: "BROAD_COMMAND_ALLOWLIST", severity: "danger" }),
      expect.objectContaining({ code: "BROAD_DOMAIN_ALLOWLIST", severity: "danger" }),
      expect.objectContaining({ code: "RULE_DENIAL_DETAILS_EXPOSED", severity: "warning" })
    ]));
    expect(JSON.stringify(findings)).not.toContain("secrets/**");
    expect(JSON.stringify(findings)).not.toContain("npm run *");
    expect(JSON.stringify(findings)).not.toContain("*.com");
  });

  it("can make pathRoot advisories strict", () => {
    const findings = validatePolicySecurity(
      { name: "read_file", allowedPaths: ["src/**"] },
      { strictPathMode: true }
    );

    expect(findings).toContainEqual(expect.objectContaining({
      code: "PATH_POLICY_WITHOUT_ROOT",
      severity: "danger"
    }));
  });

  it("summarizes lint results at a selected threshold", () => {
    const findings = validateManifestSecurity({
      schemaVersion: "1.0",
      tools: [
        {
          name: "read_file",
          risk: "read",
          requiresApproval: false,
          allowedPaths: ["src/**"],
          audit: false,
          redact: false
        }
      ]
    });

    expect(summarizePolicySecurity(findings, "danger").passed).toBe(true);
    expect(summarizePolicySecurity(findings, "warning").passed).toBe(false);
  });

  it("supports static config linting", () => {
    const findings = validatePolicyConfigSecurity({
      schemaVersion: "1.0",
      tools: [
        {
          name: "fetch_url",
          risk: "external",
          allowedDomains: ["*"],
          rateLimit: { max: 10, windowMs: 60_000 }
        }
      ]
    });

    expect(findings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "BROAD_DOMAIN_ALLOWLIST", severity: "danger" }),
      expect.objectContaining({ code: "UNKEYED_RATE_LIMIT", severity: "warning" })
    ]));
  });

  it("provides a strict path helper for runtime policies", () => {
    expect(() => strictPathPolicy({ name: "read_file", allowedPaths: ["src/**"] })).toThrow(
      "uses path rules without pathRoot"
    );
    expect(strictPathPolicy({ name: "read_file", pathRoot: ".", allowedPaths: ["src/**"] }).pathRoot).toBe(".");
  });
});
