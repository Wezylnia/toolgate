import { minimatch } from "minimatch";

export function globMatch(value: string, patterns: string[]): boolean {
  return patterns.some((pattern) =>
    minimatch(value, pattern.replaceAll("\\", "/"), {
      dot: true,
      nocase: process.platform === "win32"
    })
  );
}
