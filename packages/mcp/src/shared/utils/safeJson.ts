export function safeJsonClone<T>(value: T): T {
  if (value === undefined) {
    return value;
  }

  return JSON.parse(safeJsonStringify(value)) as T;
}

export function safeJsonStringify(value: unknown): string {
  const seen = new WeakSet<object>();

  return JSON.stringify(value, (_key, nestedValue) => {
    if (typeof nestedValue === "bigint") {
      return nestedValue.toString();
    }

    if (typeof nestedValue === "function") {
      return "[Function]";
    }

    if (typeof nestedValue === "symbol") {
      return nestedValue.toString();
    }

    if (nestedValue && typeof nestedValue === "object") {
      if (seen.has(nestedValue)) {
        return "[Circular]";
      }
      seen.add(nestedValue);
    }

    return nestedValue;
  });
}

export function summarizeOutput(output: unknown): Record<string, unknown> {
  if (typeof output === "string") {
    return { type: "text", size: output.length };
  }

  if (output === null) {
    return { type: "null", size: 0 };
  }

  if (Buffer.isBuffer(output)) {
    return { type: "buffer", size: output.byteLength };
  }

  const serialized = safeJsonStringify(output);
  return {
    type: Array.isArray(output) ? "array" : typeof output,
    size: serialized?.length ?? 0
  };
}
