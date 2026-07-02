import { describe, expect, it } from "vitest";
import {
  compareManifests,
  createManifest,
  createToolGate,
  definePolicyProfile,
  destructiveWithApprovalProfile,
  PolicyProfileError
} from "../src/index.js";

describe("policy profiles", () => {
  it("applies built-in profiles in the registry and exposes profile expansion in manifests", () => {
    const registry = createToolGate();
    registry.protect({ name: "delete_file", profile: "destructiveWithApproval" }, async () => "ok");

    const policy = registry.getPolicy("delete_file");
    expect(policy).toMatchObject({
      profile: "destructiveWithApproval",
      risk: "destructive",
      requireApproval: true,
      audit: true,
      redact: true
    });

    const manifest = registry.manifest();
    expect(manifest.tools[0]).toMatchObject({
      profile: "destructiveWithApproval",
      requiresApproval: true,
      profileDefaults: { risk: "destructive", requireApproval: true }
    });
  });

  it("keeps profile deny lists additive with tool deny lists", () => {
    const profile = definePolicyProfile("workspace", {
      risk: "write",
      audit: true,
      deniedPaths: ["**/.env*"]
    });
    const registry = createToolGate({ profiles: [profile] });
    registry.protect({ name: "write_file", profile: "workspace", deniedPaths: ["**/.git/**"] }, async () => "ok");

    expect(registry.getPolicy("write_file")?.deniedPaths).toEqual(["**/.env*", "**/.git/**"]);
  });

  it("rejects silent profile weakening unless explicitly allowed", () => {
    const registry = createToolGate({ profiles: [destructiveWithApprovalProfile] });

    expect(() => registry.protect({
      name: "delete_file",
      profile: "destructiveWithApproval",
      requireApproval: false
    }, async () => "ok")).toThrow(PolicyProfileError);
  });

  it("detects profile removals and weakened profile defaults in manifest compare", () => {
    const base = createManifest([{
      name: "delete_file",
      profile: "destructiveWithApproval",
      risk: "destructive",
      requireApproval: true,
      audit: true,
      redact: true,
      metadata: {
        toolgateProfile: {
          name: "destructiveWithApproval",
          defaults: { risk: "destructive", requireApproval: true, audit: true, redact: true }
        }
      }
    }]);
    const removed = createManifest([{ name: "delete_file", risk: "destructive", requireApproval: true, audit: true, redact: true }]);
    const weakened = structuredClone(base);
    weakened.tools[0].profileDefaults = { risk: "read", requireApproval: false, audit: true, redact: true };

    expect(compareManifests(base, removed).changes.map((change) => change.code)).toContain("PROFILE_REMOVED");
    expect(compareManifests(base, weakened).changes).toContainEqual(expect.objectContaining({
      code: "PROFILE_DEFAULTS_CHANGED",
      severity: "danger"
    }));
  });
});
