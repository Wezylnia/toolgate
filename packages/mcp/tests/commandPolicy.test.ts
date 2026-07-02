import { describe, expect, it } from "vitest";
import { gate } from "../src/gate/gate.js";

describe("command policy", () => {
  it("allows configured commands", async () => {
    const protectedHandler = gate(
      {
        name: "run_command",
        risk: "destructive",
        allowedCommands: ["npm test", "npm run build"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ command: "npm test" });

    expect(result.ok).toBe(true);
  });

  it("denies commands outside allowlist", async () => {
    const protectedHandler = gate(
      {
        name: "run_command",
        allowedCommands: ["npm test"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ cmd: "npm publish" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("COMMAND_DENIED");
    }
  });

  it("lets denied commands win over allowlist", async () => {
    const protectedHandler = gate(
      {
        name: "run_command",
        allowedCommands: ["npm *"],
        deniedCommands: ["npm publish*"]
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ script: "npm publish --access public" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("COMMAND_DENIED");
    }
  });

  it("supports custom command extractors", async () => {
    const protectedHandler = gate(
      {
        name: "run_command",
        allowedCommands: ["pnpm test"],
        extractCommands: (input) => {
          const record = input as { task?: { command?: string } };
          return record.task?.command;
        }
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ task: { command: "pnpm deploy" } });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({ reasonCode: "COMMAND_ALLOWLIST_MISS" });
    }
  });

  it("can expose denied commands when explicitly configured", async () => {
    const protectedHandler = gate(
      {
        name: "run_command",
        allowedCommands: ["pnpm test"],
        exposePolicyDenialDetails: true
      },
      async () => ({ ok: true })
    );

    const result = await protectedHandler({ command: "pnpm deploy" });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.details).toEqual({
        command: "pnpm deploy",
        reasonCode: "COMMAND_ALLOWLIST_MISS"
      });
    }
  });
});
