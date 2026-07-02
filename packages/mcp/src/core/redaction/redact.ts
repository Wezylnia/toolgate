import { defaultSensitiveKeys, defaultSensitivePatterns } from "./defaultPatterns.js";

export interface RedactionOptions {
  enabled?: boolean;
  replacement?: string;
  keys?: string[];
  patterns?: RegExp[];
}

export function redact<T>(value: T, options: boolean | RedactionOptions = true): T {
  const normalized = normalizeRedactionOptions(options);
  if (!normalized.enabled) {
    return value;
  }

  return redactValue(value, normalized) as T;
}

export function normalizeRedactionOptions(options: boolean | RedactionOptions): Required<RedactionOptions> {
  if (options === false) {
    return {
      enabled: false,
      replacement: "[REDACTED]",
      keys: defaultSensitiveKeys,
      patterns: defaultSensitivePatterns
    };
  }

  if (options === true) {
    return {
      enabled: true,
      replacement: "[REDACTED]",
      keys: defaultSensitiveKeys,
      patterns: defaultSensitivePatterns
    };
  }

  return {
    enabled: options.enabled ?? true,
    replacement: options.replacement ?? "[REDACTED]",
    keys: [...defaultSensitiveKeys, ...(options.keys ?? [])],
    patterns: [...defaultSensitivePatterns, ...(options.patterns ?? [])]
  };
}

function redactValue(value: unknown, options: Required<RedactionOptions>): unknown {
  if (typeof value === "string") {
    return redactString(value, options);
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, options));
  }

  if (value && typeof value === "object") {
    if (value instanceof Date) {
      return value;
    }

    const output: Record<string, unknown> = {};
    for (const [key, nestedValue] of Object.entries(value)) {
      output[key] = isSensitiveKey(key, options.keys)
        ? options.replacement
        : redactValue(nestedValue, options);
    }
    return output;
  }

  return value;
}

function redactString(value: string, options: Required<RedactionOptions>): string {
  return options.patterns.reduce(
    (current, pattern) => current.replace(pattern, options.replacement),
    value
  );
}

function isSensitiveKey(key: string, sensitiveKeys: string[]): boolean {
  const normalizedKey = key.toLowerCase();
  return sensitiveKeys.some((sensitiveKey) => {
    const normalizedSensitiveKey = sensitiveKey.toLowerCase();
    return (
      normalizedKey === normalizedSensitiveKey ||
      normalizedKey.endsWith(normalizedSensitiveKey)
    );
  });
}
