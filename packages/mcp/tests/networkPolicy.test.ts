import { describe, expect, it } from "vitest";
import { gate } from "../src/gate/gate.js";
import { evaluatePolicy } from "../src/policy/evaluatePolicy.js";

describe("network policy", () => {
  it("allows configured domains", async () => {
    const protectedHandler = gate(
      {
        name: "fetch_url",
        risk: "external",
        allowedDomains: ["api.github.com"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ url: "https://api.github.com/repos/openai/codex" });

    expect(result.ok).toBe(true);
  });

  it("denies domains outside allowlist", async () => {
    const protectedHandler = gate(
      {
        name: "fetch_url",
        risk: "external",
        allowedDomains: ["api.github.com"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ endpoint: "https://example.com/data" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("DOMAIN_DENIED");
      expect(result.error.details).toEqual({ reasonCode: "DOMAIN_ALLOWLIST_MISS" });
    }
  });

  it("lets denied domains win over allowed wildcard domains", () => {
    const decision = evaluatePolicy(
      {
        name: "fetch_url",
        allowedDomains: ["*.company.com"],
        deniedDomains: ["metadata.company.com"]
      },
      { url: "https://metadata.company.com/latest" }
    );

    expect(decision.allowed).toBe(false);
    expect(decision.code).toBe("DOMAIN_DENIED");
  });

  it("supports custom URL extractors", async () => {
    const protectedHandler = gate(
      {
        name: "fetch_url",
        allowedDomains: ["docs.company.com"],
        extractUrls: (input) => {
          const record = input as { request?: { href?: string } };
          return record.request?.href;
        }
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({
      request: { href: "https://evil.example.com" }
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("DOMAIN_DENIED");
    }
  });

  it("blocks invalid URLs when network policy is configured", async () => {
    const protectedHandler = gate(
      {
        name: "fetch_url",
        allowedDomains: ["api.github.com"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ url: "not a url" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_URL");
      expect(result.error.details).toEqual({ reasonCode: "URL_INVALID" });
    }
  });
});
