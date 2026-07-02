import { existsSync, realpathSync } from "node:fs";
import path from "node:path";

export function normalizePathForPolicy(value: string): string {
  const normalized = path.posix.normalize(value.replaceAll("\\", "/"));
  return normalized.startsWith("./") ? normalized.slice(2) : normalized;
}

export function isTraversalPath(value: string): boolean {
  const normalized = normalizePathForPolicy(value);
  return normalized === ".." || normalized.startsWith("../") || path.isAbsolute(value);
}

export function normalizeSystemPathForPolicy(value: string): string {
  return value.replaceAll("\\", "/");
}

export function canonicalRootForPolicy(root: string): string {
  return normalizeSystemPathForPolicy(resolveExistingPath(path.resolve(root)));
}

export function canonicalPathForPolicy(value: string, root: string): string {
  const rootPath = path.resolve(root);
  const candidate = path.isAbsolute(value) ? value : path.resolve(rootPath, value);
  return normalizeSystemPathForPolicy(resolveExistingPath(candidate));
}

export function canonicalPatternForPolicy(pattern: string, root: string): string {
  const candidate = path.isAbsolute(pattern) ? pattern : path.resolve(root, pattern);
  const normalized = path.normalize(candidate);
  const parsed = path.parse(normalized);
  const segments = normalized
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean);
  const magicIndex = segments.findIndex(hasGlobMagic);
  if (magicIndex === -1) {
    return normalizeSystemPathForPolicy(resolveExistingPath(normalized));
  }

  const literalSegments = segments.slice(0, magicIndex);
  const literalPath = literalSegments.length > 0
    ? path.join(parsed.root, ...literalSegments)
    : parsed.root;
  const suffix = segments.slice(magicIndex).join("/");
  const canonicalPrefix = normalizeSystemPathForPolicy(resolveExistingPath(literalPath));
  return canonicalPrefix.endsWith("/") ? `${canonicalPrefix}${suffix}` : `${canonicalPrefix}/${suffix}`;
}

export function isCanonicalPathInsideRoot(value: string, root: string): boolean {
  const normalizedValue = normalizeSystemPathForPolicy(path.resolve(value));
  const normalizedRoot = normalizeSystemPathForPolicy(path.resolve(root));
  return normalizedValue === normalizedRoot || normalizedValue.startsWith(`${normalizedRoot}/`);
}

function resolveExistingPath(value: string): string {
  let current = path.resolve(value);
  const missingSegments: string[] = [];

  while (!existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    missingSegments.unshift(path.basename(current));
    current = parent;
  }

  const resolvedBase = existsSync(current) ? realpathSync.native(current) : current;
  return path.resolve(resolvedBase, ...missingSegments);
}

function hasGlobMagic(segment: string): boolean {
  return /[*?[\]{}()!+@]/.test(segment);
}
