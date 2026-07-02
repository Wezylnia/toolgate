import { describe, expect, it } from "vitest";
import { gate } from "../src/core/gate/gate.js";
import { redact } from "../src/core/redaction/redact.js";

describe("redaction", () => {
  it("redacts sensitive keys recursively", () => {
    const output = redact({
      token: "ghp_abcdefghijklmnopqrstuvwxyz",
      nested: {
        password: "super-secret"
      }
    });

    expect(output).toEqual({
      token: "[REDACTED]",
      nested: {
        password: "[REDACTED]"
      }
    });
  });

  it("redacts common compound secret keys", () => {
    const output = redact({
      githubToken: "ghp_abcdefghijklmnopqrstuvwxyz",
      databasePassword: "secret"
    });

    expect(output).toEqual({
      githubToken: "[REDACTED]",
      databasePassword: "[REDACTED]"
    });
  });

  it("redacts handler output when enabled", async () => {
    const protectedHandler = gate(
      { name: "get_config", redact: true },
      async () => ({
        authorization: "Bearer abcdefghijklmnopqrstuvwxyz",
        public: "visible"
      })
    );

    const result = await protectedHandler({});

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data.authorization).toBe("[REDACTED]");
      expect(result.data.public).toBe("visible");
    }
  });
});
