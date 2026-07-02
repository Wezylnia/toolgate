# ToolGateKit

Put guardrails around your MCP tools.

ToolGateKit is a TypeScript middleware library for developers building Model Context Protocol servers. It wraps your existing MCP tool handlers and checks a declared policy before the handler runs.

Use it when a tool can read files, write data, call APIs, delete records, send messages, or expose sensitive output to an AI agent.

```bash
npm install toolgate-mcp
```

## What Problem It Solves

MCP tools are just functions, but once an agent can call them they need explicit boundaries:

- Can this tool read any path, or only `src/**`?
- Should `.env`, `secrets/**`, or `node_modules/**` always be blocked?
- Does a destructive tool require approval before it runs?
- Should secrets be redacted before output is returned?
- Should every tool call be written to an audit log?
- What happens if the handler hangs?

ToolGateKit puts those checks next to the handler, so the policy is visible, testable, and versioned with your server code.

## How It Works

```text
policy + handler -> protected handler
```

For each call, ToolGateKit:

1. Evaluates the declared policy.
2. Blocks approval-required or policy-violating calls.
3. Runs the handler with timeout support.
4. Redacts sensitive output if enabled.
5. Writes an audit entry if configured.
6. Returns a structured success or error result.

## Example

```ts
import { createAuditLogger, gate } from "toolgate-mcp";

const audit = createAuditLogger({
  file: ".toolgate/audit.jsonl"
});

const readFileTool = gate(
  {
    name: "read_file",
    risk: "read",
    pathRoot: process.cwd(),
    allowedPaths: ["src/**", "docs/**"],
    deniedPaths: [".env", "secrets/**"],
    timeoutMs: 5000,
    redact: true,
    audit
  },
  async ({ path }, ctx) => ({
    content: await fs.readFile(path, { encoding: "utf8", signal: ctx.signal })
  })
);
```

If the agent asks for `.env`, the handler is not executed:

```json
{
  "ok": false,
  "error": {
    "type": "policy_violation",
    "code": "PATH_DENIED",
    "message": "Tool 'read_file' is not allowed to access '.env'."
  }
}
```

## Core Features

- `gate(policy, handler)` wrapper for MCP tool handlers
- `createToolGate()` registry for shared defaults, duplicate detection, and manifest collection
- `gateMcp(policy, handler)` adapter for MCP-compatible `content` and `isError` results
- `gateMcpHandler()` integration preserving MCP SDK request context
- risk levels: `read`, `write`, `external`, `destructive`
- approval-required blocking for dangerous tools
- host-driven async approval providers bound to subject, input hash, versions, expiry, and nonce
- canonical path allowlists and denylists with deny-first behavior when `pathRoot` is set
- network domain allowlists and denylists
- command allowlists and denylists
- keyed rate limiting with in-memory or custom shared stores
- custom input extractors for paths, URLs, and commands
- fail-closed sync or async custom policy rules for application-specific checks
- policy presets for common filesystem and external API tools
- timeout handling with `AbortSignal`
- default redaction for common secrets and tokens
- append-only JSONL audit logs, with `audit: true` writing to `.toolgate/audit.jsonl`
- streaming audit-log filtering and summaries through API or CLI
- lifecycle observer events for OpenTelemetry or custom metrics adapters
- dependency-free OpenTelemetry span bridge
- policy manifest export for visibility
- versioned v1 policy-config and manifest JSON Schemas with migration commands
- fail-fast runtime policy validation and duplicate-name config checks
- manifest JSON schema and validation helpers
- security-aware manifest comparison for policy regression checks
- reusable GitHub Action for blocking dangerous manifest changes in pull requests
- `toolgate` CLI for manifest generation and validation
- predictable structured errors

## What It Is Not

ToolGateKit is not an MCP server, MCP client, gateway, proxy, sandbox, approval UI, agent framework, or authentication system. It reduces risk around tool handlers, but it does not make unsafe handler code safe by itself.

## Status

Stable v1 for TypeScript MCP servers. ESM-first, Node.js 18+.

## CLI

Generate a manifest from a JSON policy config:

```bash
toolgate manifest --config toolgate.config.json --out policy-manifest.json
```

Validate a manifest:

```bash
toolgate validate-manifest --file policy-manifest.json
```

Validate a policy config before generating its manifest:

```bash
toolgate validate-config --file toolgate.config.json
```

Inspect blocked calls in an audit log:

```bash
toolgate audit --file .toolgate/audit.jsonl --decision blocked --limit 100
```

Fail CI when a policy manifest removes protection:

```bash
toolgate check-manifest --base policy-main.json --head policy-pr.json
```

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
npm audit
```

## Releases

Npm publishing is automated only from GitHub Releases. Normal commits and pushes do not publish.

Create a release tag that matches the package version, such as `v1.0.1`, and the publish workflow will run tests before publishing `toolgate-mcp` to npm. See [Release Process](docs/release.md).

## Docs

- [Package README](packages/mcp/README.md)
- [Policies](docs/policies.md)
- [Approvals](docs/approvals.md)
- [Audit logs](docs/audit-logs.md)
- [Redaction](docs/redaction.md)
- [Manifest](docs/manifest.md)
- [CLI](docs/cli.md)
- [Limitations](docs/limitations.md)
- [Examples](docs/examples.md)
- [MCP Integration](docs/mcp-integration.md)
- [Observability](docs/observability.md)
- [GitHub Action](docs/github-action.md)
- [Tool Registry](docs/registry.md)
- [v1 Migration](docs/v1-migration.md)
- [Release Process](docs/release.md)
- [Changelog](CHANGELOG.md)
