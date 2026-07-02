import type { ToolPolicy } from "../gate/types.js";

export class ToolTimeoutError extends Error {
  constructor(
    public readonly policy: ToolPolicy,
    public readonly timeoutMs: number
  ) {
    super(`Tool '${policy.name}' exceeded timeout of ${timeoutMs}ms.`);
    this.name = "ToolTimeoutError";
  }
}

export async function withTimeout<T>(
  task: Promise<T> | T,
  timeoutMs: number | undefined,
  controller: AbortController,
  policy: ToolPolicy
): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) {
    return task;
  }

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new ToolTimeoutError(policy, timeoutMs));
    }, timeoutMs);
  });

  try {
    return await Promise.race([Promise.resolve(task), timeout]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
}
