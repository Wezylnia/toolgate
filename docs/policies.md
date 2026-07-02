# Policies

ToolGateKit policies describe the guardrails around one MCP tool handler.

Policies are validated when `gate()` is called. Invalid configuration throws an
`InvalidToolPolicyError` before the handler can be exposed. Use `validatePolicy()` or
`validatePolicies()` when validation errors need to be displayed instead of thrown.

```ts
import { gate } from "toolgate-mcp";

const readFileTool = gate(
  {
    name: "read_file",
    risk: "read",
    allowedPaths: ["src/**", "docs/**"],
    deniedPaths: [".env", "secrets/**"],
    timeoutMs: 5000,
    redact: true
  },
  async ({ path }) => ({
    content: await fs.readFile(path, "utf8")
  })
);
```

## Risk Levels

- `read`: reads local or remote data without modifying it
- `write`: creates or updates data
- `external`: interacts with external services or APIs
- `destructive`: deletes, overwrites, sends irreversible actions, or runs dangerous operations

Risk levels are metadata. They appear in results, logs, and manifests.

## Approval

When `requireApproval` is true, ToolGateKit blocks execution and returns a structured
`APPROVAL_REQUIRED` response unless the host supplies an async `approval` provider. See
[Approvals](approvals.md).

## Path Policy

Path policy is evaluated from common input fields: `path`, `filePath`, `filepath`, and `targetPath`.

Rules:

- denied paths win over allowed paths
- paths are normalized before matching
- without `pathRoot`, traversal attempts and absolute paths are blocked
- with `pathRoot`, the canonical target must remain inside the root
- if `allowedPaths` is present, paths outside it are denied

For filesystem tools, set `pathRoot` to the authenticated workspace or project root. With
`pathRoot`, ToolGateKit resolves the requested path and glob patterns to canonical filesystem paths
before matching. Symlinks or junctions that resolve outside `pathRoot` are denied before glob
checks run.

```ts
gate(
  {
    name: "read_file",
    pathRoot: workspaceRoot,
    allowedPaths: ["src/**", "docs/**"],
    deniedPaths: [".env", "secrets/**"]
  },
  handler
);
```

Use `extractPaths` for custom input shapes.

Use `strictPathPolicy(policy)` in code paths where any path allowlist or denylist must include a
`pathRoot`. This helper fails fast during registration-time setup and is useful for project-level
filesystem presets.

Policy denials are machine-readable through `error.code` and a generic `reasonCode`. They do not
echo requested paths, URLs, commands, denylist entries, or allowlist misses by default. Set
`exposePolicyDenialDetails: true` only for trusted callers that are allowed to see the denied
input value.

## Network Policy

Network policy is evaluated from common input fields: `url`, `uri`, `href`, `endpoint`, and `targetUrl`.

```ts
gate(
  {
    name: "fetch_url",
    risk: "external",
    allowedDomains: ["api.github.com"],
    deniedDomains: ["metadata.google.internal"]
  },
  handler
);
```

Rules:

- denied domains win over allowed domains
- `*.example.com` matches `example.com` and subdomains
- invalid URLs are blocked when network policy is configured

Use `extractUrls` for custom input shapes.

## Command Policy

Command policy is evaluated from common input fields: `command`, `cmd`, `script`, and `shellCommand`.

```ts
gate(
  {
    name: "run_command",
    risk: "destructive",
    allowedCommands: ["npm test", "npm run build"],
    deniedCommands: ["npm publish*"]
  },
  handler
);
```

Rules:

- denied commands win over allowed commands
- command matching uses glob patterns

Use `extractCommands` for custom input shapes.

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

Rate limiting uses an in-memory store by default. Use a key extractor for independent tenant or
user quotas:

```ts
rateLimit: {
  max: 100,
  windowMs: 60_000,
  key: (input) => input.tenantId
}
```

Use `createMemoryRateLimitStore()` and a shared `namespace` to apply one quota across multiple
handlers. Implement `RateLimitStore.consume()` to use Redis, a database, or another atomic shared
backend. Store and key-extractor failures fail closed as `RATE_LIMIT_ERROR`.

The built-in store is process-local and retains one entry per key until cleared. Use an external
bounded store for multi-process deployments or untrusted high-cardinality keys.

## Policy Profiles

Use profiles to share conservative defaults across many tools without copying every policy field:

```ts
import { createToolGate, definePolicyProfile } from "toolgate-mcp";

const workspaceWrite = definePolicyProfile("workspaceWrite", {
  risk: "write",
  audit: true,
  redact: true,
  deniedPaths: ["**/.env*", "**/.git/**"],
  timeoutMs: 15_000
});

const tools = createToolGate({ profiles: [workspaceWrite] });

tools.protect(
  {
    name: "write_file",
    profile: "workspaceWrite",
    deniedPaths: ["**/secrets/**"]
  },
  handler
);
```

Built-in profiles are `readOnlyWorkspace`, `writeWorkspace`, `externalApi`, and
`destructiveWithApproval`. Profile deny lists are additive with tool deny lists. A tool cannot
silently disable profile protections such as approval, audit, redaction, stricter risk, timeout,
or rate limit unless that profile explicitly allows the override.

Generated manifests include the applied `profile` and a safe `profileDefaults` snapshot so policy
review can see what was expanded. Manifest comparison reports removed profiles and weakened
profile defaults.

## Custom Rules

Use custom rules for application-specific checks that cannot be expressed as paths, domains, or
commands. Rules run sequentially after built-in policies and before approval or handler execution.

```ts
gate(
  {
    name: "create_ticket",
    rules: [
      {
        name: "tenant_access",
        evaluate: async (input, context) => ({
          allowed: await canAccessTenant(input.tenantId),
          code: "TENANT_DENIED",
          details: { requestId: context.requestId }
        })
      }
    ]
  },
  handler
);
```

Rules may return a boolean or a decision object. Evaluation stops at the first denial. Denials are
machine-readable through `error.code`; by default ToolGateKit does not include the rule name,
exception message, or custom detail payload in the tool-visible error. Set
`exposeRuleDenialDetails: true` only when the caller is allowed to learn which rule fired.
Exceptions fail closed as `POLICY_RULE_ERROR`; they never allow the handler to run. Manifests
include custom rule names but not executable rule code.

## Security Advisories

Schema validation only checks whether a policy is well formed. Security linting reports
risky-but-valid choices:

```ts
import { validatePolicySecurity } from "toolgate-mcp";

const findings = validatePolicySecurity(policy, { strictPathMode: true });
```

Advisories include destructive tools without approval, filesystem rules without `pathRoot`, broad
command or domain allowlists, disabled redaction on data tools, unkeyed rate limits, and denial
detail exposure. Findings are machine-readable and avoid echoing secret policy values.
