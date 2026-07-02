import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";
import { createMemoryRateLimitStore } from "../src/core/rateLimit/rateLimiter.js";

describe("rate limiting", () => {
  it("blocks calls after max calls in a window", async () => {
    let calls = 0;
    const protectedHandler = gate(
      {
        name: "limited_tool",
        rateLimit: {
          max: 2,
          windowMs: 1000
        }
      },
      async () => {
        calls += 1;
        return { ok: true };
      }
    );

    expect((await protectedHandler({})).ok).toBe(true);
    expect((await protectedHandler({})).ok).toBe(true);
    const blocked = await protectedHandler({});

    expect(calls).toBe(2);
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) {
      expect(blocked.error.code).toBe("RATE_LIMITED");
      expect(blocked.error.type).toBe("rate_limited");
      expect(blocked.error.details?.retryAfterMs).toBeGreaterThan(0);
    }
  });

  it("isolates quotas by extracted key", async () => {
    const protectedHandler = gate(
      {
        name: "search",
        rateLimit: {
          max: 1,
          windowMs: 1000,
          key: (input) => (input as { tenantId: string }).tenantId
        }
      },
      async () => "ok"
    );

    expect((await protectedHandler({ tenantId: "a" })).ok).toBe(true);
    expect((await protectedHandler({ tenantId: "b" })).ok).toBe(true);
    const blocked = await protectedHandler({ tenantId: "a" });
    expect(blocked.ok).toBe(false);
    if (!blocked.ok) expect(blocked.error.code).toBe("RATE_LIMITED");
  });

  it("shares a quota across handlers through a store and namespace", async () => {
    const store = createMemoryRateLimitStore();
    const options = {
      max: 1,
      windowMs: 1000,
      namespace: "shared-api",
      store,
      key: (input: unknown) => (input as { userId: string }).userId
    };
    const first = gate({ name: "one", rateLimit: options }, async () => "one");
    const second = gate({ name: "two", rateLimit: options }, async () => "two");

    expect((await first({ userId: "u1" })).ok).toBe(true);
    const blocked = await second({ userId: "u1" });

    expect(blocked.ok).toBe(false);
    expect(store.size()).toBe(1);
    store.clear();
    expect(store.size()).toBe(0);
  });

  it("fails closed when key extraction or a shared store fails", async () => {
    const keyFailure = gate(
      { name: "key", rateLimit: { max: 1, windowMs: 1000, key: () => { throw new Error("bad key"); } } },
      async () => "never"
    );
    const storeFailure = gate(
      {
        name: "store",
        rateLimit: {
          max: 1,
          windowMs: 1000,
          store: { consume: async () => { throw new Error("store offline"); } }
        }
      },
      async () => "never"
    );

    for (const result of [await keyFailure({}), await storeFailure({})]) {
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toMatchObject({ type: "rate_limit_error", code: "RATE_LIMIT_ERROR" });
    }
  });

  it("supports deterministic direct store consumption", async () => {
    const store = createMemoryRateLimitStore();
    expect(await store.consume("key", { max: 1, windowMs: 100 }, 1000)).toEqual({ allowed: true });
    expect(await store.consume("key", { max: 1, windowMs: 100 }, 1050)).toEqual({ allowed: false, retryAfterMs: 50 });
    expect(await store.consume("key", { max: 1, windowMs: 100 }, 1100)).toEqual({ allowed: true });
  });
});
