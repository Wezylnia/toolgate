import type { RateLimitOptions } from "../gate/types.js";

export interface RateLimitDecision {
  allowed: boolean;
  retryAfterMs?: number;
}

export interface RateLimitStore {
  consume(
    key: string,
    limit: { max: number; windowMs: number },
    now?: number
  ): RateLimitDecision | Promise<RateLimitDecision>;
}

export interface RateLimiter {
  check(key?: string, now?: number): RateLimitDecision | Promise<RateLimitDecision>;
}

export interface MemoryRateLimitStore extends RateLimitStore {
  clear(key?: string): void;
  size(): number;
}

export function createMemoryRateLimitStore(): MemoryRateLimitStore {
  const windows = new Map<string, { startedAt: number; count: number }>();
  return {
    consume(key, limit, now = Date.now()): RateLimitDecision {
      let window = windows.get(key);
      if (!window || now - window.startedAt >= limit.windowMs) {
        window = { startedAt: now, count: 0 };
        windows.set(key, window);
      }
      if (window.count >= limit.max) {
        return {
          allowed: false,
          retryAfterMs: Math.max(0, limit.windowMs - (now - window.startedAt))
        };
      }
      window.count += 1;
      return { allowed: true };
    },
    clear(key?: string): void {
      if (key === undefined) windows.clear();
      else windows.delete(key);
    },
    size(): number {
      return windows.size;
    }
  };
}

export function createRateLimiter(options: RateLimitOptions | undefined): RateLimiter | undefined {
  if (!options) return undefined;
  const store = options.store ?? createMemoryRateLimitStore();
  return {
    check(key = "global", now = Date.now()) {
      return store.consume(key, { max: options.max, windowMs: options.windowMs }, now);
    }
  };
}

export function createRateLimitKey(
  options: RateLimitOptions,
  input: unknown,
  toolName: string
): string {
  const namespace = options.namespace ?? toolName;
  const extracted = options.key?.(input);
  const key = extracted === undefined || extracted.length === 0 ? "global" : extracted;
  return `${namespace}:${key}`;
}
