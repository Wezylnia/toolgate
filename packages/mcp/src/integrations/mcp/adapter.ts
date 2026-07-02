import { createGateExecutor, gate } from "../../core/gate/gate.js";
import type {
  ToolGateContext,
  ToolGateResult,
  ToolHandler,
  ToolPolicy
} from "../../core/gate/types.js";
import { safeJsonClone, safeJsonStringify } from "../../shared/utils/safeJson.js";

export interface McpContentBlock {
  type: string;
  [key: string]: unknown;
}

export interface McpToolResult {
  content: McpContentBlock[];
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface McpAdapterOptions {
  includeStructuredContent?: boolean;
}

export type McpSdkToolHandler<TInput, TExtra, TOutput> = (
  input: TInput,
  extra: TExtra,
  context: ToolGateContext
) => TOutput | Promise<TOutput>;

export function toMcpToolResult<T>(
  result: ToolGateResult<T>,
  options: McpAdapterOptions = {}
): McpToolResult {
  const output: McpToolResult = {
    content: [
      {
        type: "text",
        text: result.ok && typeof result.data === "string"
          ? result.data
          : safeJsonStringify(result)
      }
    ]
  };

  if (!result.ok) {
    output.isError = true;
  }
  if (options.includeStructuredContent) {
    output.structuredContent = { toolgate: safeJsonClone(result) };
  }
  return output;
}

export function gateMcp<TInput, TOutput>(
  policy: ToolPolicy,
  handler: ToolHandler<TInput, TOutput>,
  options: McpAdapterOptions = {}
): (input: TInput) => Promise<McpToolResult> {
  const protectedHandler = gate(policy, handler);

  return async (input: TInput): Promise<McpToolResult> => {
    const result = await protectedHandler(input);
    if (result.ok && isMcpToolResult(result.data)) {
      return result.data;
    }
    return toMcpToolResult(result, options);
  };
}

export function gateMcpHandler<TInput, TExtra, TOutput>(
  policy: ToolPolicy,
  handler: McpSdkToolHandler<TInput, TExtra, TOutput>,
  options: McpAdapterOptions = {}
): (input: TInput, extra: TExtra) => Promise<McpToolResult> {
  const protectedHandler = createGateExecutor<TInput, TOutput, [TExtra]>(
    policy,
    (input, context, extra) => handler(input, extra, context)
  );

  return async (input: TInput, extra: TExtra): Promise<McpToolResult> => {
    const result = await protectedHandler(input, extra);
    if (result.ok && isMcpToolResult(result.data)) return result.data;
    return toMcpToolResult(result, options);
  };
}

export function isMcpToolResult(value: unknown): value is McpToolResult {
  if (!value || typeof value !== "object" || !("content" in value)) {
    return false;
  }
  const content = (value as { content?: unknown }).content;
  return Array.isArray(content) && content.every(isContentBlock);
}

function isContentBlock(value: unknown): value is McpContentBlock {
  return Boolean(value) && typeof value === "object" && typeof (value as { type?: unknown }).type === "string";
}
