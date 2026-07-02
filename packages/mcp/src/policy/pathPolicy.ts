import type { ToolPolicy } from "../gate/types.js";
import { globMatch } from "../utils/globMatch.js";
import {
  canonicalPathForPolicy,
  canonicalPatternForPolicy,
  canonicalRootForPolicy,
  isCanonicalPathInsideRoot,
  isTraversalPath,
  normalizePathForPolicy
} from "../utils/normalizePath.js";

const pathKeys = ["path", "filePath", "filepath", "targetPath"];

export interface PathPolicyResult {
  allowed: boolean;
  code?: string;
  message?: string;
  details?: Record<string, unknown>;
}

export function extractPolicyPaths(input: unknown): string[] {
  if (!input || typeof input !== "object") {
    return [];
  }

  const record = input as Record<string, unknown>;
  return pathKeys.flatMap((key) => {
    const value = record[key];
    return typeof value === "string" ? [value] : [];
  });
}

export function evaluatePathPolicy(policy: ToolPolicy, input: unknown): PathPolicyResult {
  if (!policy.allowedPaths?.length && !policy.deniedPaths?.length) {
    return { allowed: true };
  }

  const paths = policy.extractPaths
    ? normalizeExtractorResult(policy.extractPaths(input))
    : extractPolicyPaths(input);
  if (paths.length === 0) {
    return { allowed: true };
  }

  const canonicalRoot = policy.pathRoot ? canonicalRootForPolicy(policy.pathRoot) : undefined;
  const deniedPaths = canonicalRoot
    ? policy.deniedPaths?.map((pattern) => canonicalPatternForPolicy(pattern, canonicalRoot))
    : policy.deniedPaths;
  const allowedPaths = canonicalRoot
    ? policy.allowedPaths?.map((pattern) => canonicalPatternForPolicy(pattern, canonicalRoot))
    : policy.allowedPaths;

  for (const rawPath of paths) {
    const normalizedPath = canonicalRoot
      ? canonicalPathForPolicy(rawPath, canonicalRoot)
      : normalizePathForPolicy(rawPath);

    if (!canonicalRoot && isTraversalPath(rawPath)) {
      return denied(policy, normalizedPath, "PATH_TRAVERSAL");
    }

    if (canonicalRoot && !isCanonicalPathInsideRoot(normalizedPath, canonicalRoot)) {
      return denied(policy, normalizedPath, "PATH_OUTSIDE_ROOT");
    }

    if (deniedPaths?.length && globMatch(normalizedPath, deniedPaths)) {
      return denied(policy, normalizedPath, "PATH_DENYLIST_MATCH");
    }

    if (allowedPaths?.length && !globMatch(normalizedPath, allowedPaths)) {
      return denied(policy, normalizedPath, "PATH_ALLOWLIST_MISS");
    }
  }

  return { allowed: true };
}

function normalizeExtractorResult(value: string | string[] | undefined): string[] {
  if (typeof value === "string") {
    return [value];
  }

  return value ?? [];
}

function denied(policy: ToolPolicy, path: string, reasonCode: string): PathPolicyResult {
  return {
    allowed: false,
    code: "PATH_DENIED",
    message: `Tool '${policy.name}' is not allowed to access the requested path.`,
    details: policy.exposePolicyDenialDetails
      ? { path, reasonCode }
      : { reasonCode }
  };
}
