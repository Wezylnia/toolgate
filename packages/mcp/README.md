# ToolGateKit

Put guardrails around your MCP tools.

`toolgate-mcp` is a TypeScript middleware package for Model Context Protocol server authors. It wraps existing tool handlers and enforces a declared policy before an AI agent can use that handler.

```bash
npm install toolgate-mcp
```

## What It Does

ToolGateKit protects tool handlers at the point where they are registered. A policy can say:

- this tool is `read`, `write`, `external`, or `destructive`
- this tool requires approval before execution
- this tool can ask the host for an explicit async approval decision
- this tool may only access specific file paths
- this tool may only call specific network domains
- this tool may only run specific command strings
- this tool must pass application-specific sync or async policy rules
- this tool can be rate limited in memory
- this tool must time out after a fixed duration
- this tool output and audit logs should redact secrets
- this tool call should be written to a JSONL audit log
- this tool should emit privacy-conscious lifecycle events to a telemetry adapter

It returns structured results instead of throwing for expected policy failures.

Policies are validated when `gate()` is created, so invalid timeouts, rate limits, risks, and
policy lists fail before a handler is exposed.

Set `audit: true` to write to `.toolgate/audit.jsonl`, or pass `createAuditLogger({ file })` for a custom path.

## Quick Start

```ts
import { createAuditLogger, gate } from "toolgate-mcp";

const audit = createAuditLogger({
  file: ".toolgate/audit.jsonl"
});

const deleteFileTool = gate(
  {
    name: "delete_file",
    risk: "destructive",
    requireApproval: true,
    pathRoot: process.cwd(),
    allowedPaths: ["src/**", "docs/**"],
    deniedPaths: [".env", "secrets/**", "node_modules/**"],
    timeoutMs: 10_000,
    redact: true,
    audit
  },
  async ({ path }) => {
    await fs.rm(path);
    return { ok: true };
  }
);
```

For servers with multiple tools, `createToolGate()` applies shared defaults, rejects duplicate
tool names, and generates a manifest from registered policies.

Because this policy requires approval, the handler is not executed:

```json
{
  "ok": false,
  "error": {
    "type": "approval_required",
    "code": "APPROVAL_REQUIRED",
    "message": "Tool 'delete_file' requires user approval before execution."
  }
}
```

## Execution Flow

For every protected call, ToolGateKit:

1. Normalizes and evaluates policy inputs.
2. Blocks policy violations or obtains a host approval decision when configured.
3. Creates a handler context with `requestId`, `risk`, `startedAt`, and `AbortSignal`.
4. Runs the handler with timeout protection.
5. Redacts output when enabled.
6. Writes an audit log entry when configured.
7. Returns `{ ok: true, data, meta }` or `{ ok: false, error, meta }`.

## Path Policy

ToolGateKit detects common input keys: `path`, `filePath`, `filepath`, and `targetPath`.

Rules:

- deny rules win over allow rules
- paths are normalized before matching
- when `pathRoot` is set, paths and glob patterns are canonicalized before matching so symlink
  escapes are denied
- without `pathRoot`, traversal and absolute paths are blocked
- with `pathRoot`, the canonical target must remain inside the root
- if `allowedPaths` is set, paths outside it are denied

## Network Policy

```ts
gate(
  {
    name: "fetch_url",
    risk: "external",
    allowedDomains: ["api.github.com"],
    deniedDomains: ["metadata.google.internal"]
  },
  async ({ url }) => fetch(url)
);
```

Supported default URL input keys are `url`, `uri`, `href`, `endpoint`, and `targetUrl`. Use `extractUrls` for custom input shapes.

## Command Policy

```ts
gate(
  {
    name: "run_command",
    risk: "destructive",
    allowedCommands: ["npm test", "npm run build"],
    deniedCommands: ["npm publish*"]
  },
  async ({ command }) => runCommand(command)
);
```

Supported default command input keys are `command`, `cmd`, `script`, and `shellCommand`. Use `extractCommands` for custom input shapes.

## Rate Limit

```ts
gate(
  {
    name: "search_docs",
    rateLimit: {
      max: 20,
      windowMs: 60_000
    }
  },
  handler
);
```

Rate limiting defaults to an in-memory store. Add `key` for per-user or per-tenant quotas. Share a
store and `namespace` across handlers, or implement `RateLimitStore` for an atomic external backend.

## Public API

```ts
export {
  gate,
  gateMcp,
  gateMcpHandler,
  toMcpToolResult,
  createOpenTelemetryObserver,
  evaluateCustomRules,
  emitToolGateEvent,
  createAuditLogger,
  readAuditLog,
  summarizeAudit,
  createManifest,
  migrateManifest,
  compareManifests,
  createToolGate,
  createMemoryRateLimitStore,
  destructiveFilesystemPolicy,
  externalApiPolicy,
  readOnlyFilesystemPolicy,
  policyManifestSchema,
  policyConfigSchema,
  validatePolicyConfig,
  migratePolicyConfig,
  validatePolicy,
  validatePolicies,
  validateManifest,
  redact,
  evaluatePolicy
};
```

## CLI

```bash
toolgate manifest --config toolgate.config.json --out policy-manifest.json
toolgate validate-config --file toolgate.config.json
toolgate validate-manifest --file policy-manifest.json
toolgate audit --file .toolgate/audit.jsonl --decision blocked
toolgate check-manifest --base policy-main.json --head policy-pr.json
toolgate migrate-config --file old.json --out toolgate.config.json
toolgate schema --type config --out toolgate-config.schema.json
```

The config file for `toolgate manifest` is JSON:

```json
{
  "schemaVersion": "1.0",
  "name": "filesystem-mcp",
  "tools": [
    {
      "name": "read_file",
      "risk": "read",
      "allowedPaths": ["src/**"],
      "deniedPaths": [".env"],
      "audit": true
    }
  ]
}
```

## Security Boundary

ToolGateKit is not an MCP server, MCP client, gateway, proxy, sandbox, approval UI, agent framework, or authentication system. It reduces risk around tool handlers, but it does not make unsafe handler code safe by itself.

Important limitations:

- It cannot stop unsafe behavior inside a handler if the handler ignores policy inputs.
- It cannot fully prevent prompt injection.
- Timeout cannot always kill underlying work if the handler ignores `AbortSignal`.
- Approval UI must be implemented by the host application.

## Status

Stable v1 for TypeScript MCP servers. ESM-first, Node.js 18+.
