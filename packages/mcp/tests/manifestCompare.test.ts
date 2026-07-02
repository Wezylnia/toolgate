import { describe, expect, it } from "vitest";
import { compareManifests } from "../src/operations/manifest/compare.js";
import type { PolicyManifest } from "../src/operations/manifest/manifest.js";

describe("manifest comparison", () => {
  it("detects protection removal and policy expansion as danger", () => {
    const base = manifest({
      name: "delete_file",
      risk: "write",
      requiresApproval: true,
      audit: true,
      redact: true,
      timeoutMs: 1000,
      allowedPaths: ["tmp/**"],
      deniedPaths: [".env", "secrets/**"],
      rateLimit: { max: 5, windowMs: 60_000 },
      customRules: ["tenant"]
    });
    const head = manifest({
      name: "delete_file",
      risk: "destructive",
      requiresApproval: false,
      audit: false,
      redact: false,
      allowedPaths: ["tmp/**", "src/**"],
      deniedPaths: [".env"],
      exposesPolicyDenialDetails: true,
      exposesRuleDenialDetails: true
    });

    const result = compareManifests(base, head);
    const dangerCodes = result.changes
      .filter((change) => change.severity === "danger")
      .map((change) => change.code);

    expect(result.safe).toBe(false);
    expect(dangerCodes).toEqual(expect.arrayContaining([
      "RISK_INCREASED",
      "APPROVAL_DISABLED",
      "AUDIT_DISABLED",
      "REDACTION_DISABLED",
      "TIMEOUT_REMOVED",
      "RATE_LIMIT_REMOVED",
      "ALLOW_PATHS_ENTRIES_ADDED",
      "DENY_PATHS_ENTRIES_REMOVED",
      "CUSTOM_RULES_REMOVED",
      "POLICY_DENIAL_DETAILS_EXPOSED",
      "RULE_DENIAL_DETAILS_EXPOSED"
    ]));
  });

  it("classifies tighter controls as safe informational changes", () => {
    const result = compareManifests(
      manifest({ name: "read", risk: "read", requiresApproval: false, audit: false }),
      manifest({
        name: "read",
        risk: "read",
        requiresApproval: true,
        audit: true,
        deniedPaths: [".env"],
        timeoutMs: 1000
      })
    );

    expect(result.safe).toBe(true);
    expect(result.changes.every((change) => change.severity === "info")).toBe(true);
  });

  it("reports added and removed tools", () => {
    const result = compareManifests(
      manifest({ name: "old", risk: "read", requiresApproval: false, audit: false }),
      manifest({ name: "new", risk: "read", requiresApproval: false, audit: false })
    );

    expect(result.changes).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "TOOL_ADDED", severity: "warning" }),
      expect.objectContaining({ code: "TOOL_REMOVED", severity: "info" })
    ]));
  });
});

function manifest(
  tool: Omit<PolicyManifest["tools"][number], "redact"> & { redact?: boolean }
): PolicyManifest {
  return { schemaVersion: "1.0", name: "server", tools: [{ redact: false, ...tool }] };
}
