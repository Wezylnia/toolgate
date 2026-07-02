import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("package metadata", () => {
  it("points public package paths at the layered dist layout", () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8")
    ) as {
      bin: Record<string, string>;
      exports: Record<string, { import: string; types: string }>;
    };

    expect(packageJson.bin.toolgate).toBe("dist/operations/cli/index.js");
    expect(packageJson.exports["./schema"]).toEqual({
      types: "./dist/operations/manifest/schema.d.ts",
      import: "./dist/operations/manifest/schema.js"
    });
  });
});
