# Manifest

Use `createManifest` to export visible policy metadata.

```ts
import { createManifest } from "toolgate-mcp";

const manifest = createManifest(
  [
    {
      name: "read_file",
      risk: "read",
      allowedPaths: ["src/**"],
      deniedPaths: [".env"],
      allowedDomains: ["api.github.com"],
      allowedCommands: ["npm test"],
      rateLimit: {
        max: 10,
        windowMs: 60000
      },
      audit: true,
      timeoutMs: 5000
    }
  ],
  { name: "filesystem-mcp" }
);
```

The manifest is intended for developer visibility. It is not an authorization system and does not enforce policy by itself.
Every v1 manifest includes `"schemaVersion": "1.0"`. Consumers should reject unknown major
schema versions instead of guessing compatibility.

## Validation

ToolGateKit exports a JSON schema object and a lightweight validator:

```ts
import { policyManifestSchema, validateManifest } from "toolgate-mcp";

const result = validateManifest(manifest);
```

The schema is also available through the package subpath:

```ts
import { policyManifestSchema } from "toolgate-mcp/schema";
```

The same subpath exports `policyConfigSchema` for static JSON policy files. Use
`migrateManifest()` and `migratePolicyConfig()` to validate and upgrade pre-v1 files.

## CLI

Create a manifest from a JSON config:

```bash
toolgate manifest --config toolgate.config.json --out policy-manifest.json
```

Validate a manifest:

```bash
toolgate validate-manifest --file policy-manifest.json
```

## Compare Security Posture

`compareManifests(base, head)` classifies policy changes as `info`, `warning`, or `danger`.
Dangerous changes include increasing risk, disabling approval, audit, or redaction, exposing
policy/rule denial details, removing timeout or rate limits, adding allowlist entries, and removing
denylist entries or custom rules.

The comparison is intentionally conservative. It compares declared patterns as sets and does not
attempt to prove whether two glob patterns are semantically equivalent.
