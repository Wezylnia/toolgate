import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("GitHub policy check action", () => {
  it("pins the release CLI and forwards all comparison inputs", async () => {
    const action = await readFile("../../action.yml", "utf8");

    expect(action).toContain("using: composite");
    expect(action).toContain("default: 1.3.0");
    expect(action).toContain("toolgate-mcp@${TOOLGATE_VERSION}");
    expect(action).toContain('--base "${TOOLGATE_BASE}"');
    expect(action).toContain('--head "${TOOLGATE_HEAD}"');
    expect(action).toContain('--fail-on "${TOOLGATE_FAIL_ON}"');
    expect(action).toContain("TOOLGATE_LINT");
    expect(action).toContain("--fail-on-advisory");
    expect(action).toContain("--strict-path-mode");
  });
});
