# Audit Logs

ToolGateKit can write JSONL audit logs for tool calls.

Use `audit: true` for the default `.toolgate/audit.jsonl` file, or pass a logger from `createAuditLogger({ file })` for a custom path.

```ts
import { createAuditLogger, gate } from "toolgate-mcp";

const audit = createAuditLogger({
  file: ".toolgate/audit.jsonl",
  hashChain: true
});

const tool = gate(
  {
    name: "read_file",
    audit,
    redact: true
  },
  async (input) => ({ ok: true })
);
```

Each line is one JSON object. Allowed, blocked, and failed calls are logged.

Logging failures do not crash tool calls by default. Custom loggers can implement stricter behavior if a host application needs it.

Logs are redacted by default unless `redact: false` is explicitly set.

## Hash Chain Verification

Set `hashChain: true` to add `previousHash` and `entryHash` to each written audit entry:

```ts
import { verifyAuditLog } from "toolgate-mcp";

const result = await verifyAuditLog(".toolgate/audit.jsonl");
```

Verification reports malformed JSON, broken hash continuity, hash mismatches, duplicate request
ids, and timestamps that move backwards. The chain hashes the audit entry as written after
ToolGateKit redaction, not raw handler input. This is tamper-evident, not tamper-proof; use
append-only storage for stronger operational guarantees.

## Read and Summarize Logs

Use the streaming reader for operational checks without parsing JSONL manually:

```ts
import { readAuditLog, summarizeAudit } from "toolgate-mcp";

const { entries, issues } = await readAuditLog(".toolgate/audit.jsonl", {
  tool: "delete_file",
  decision: "blocked",
  since: "2026-06-01T00:00:00Z",
  limit: 100
});

const summary = summarizeAudit(entries);
```

Malformed lines are reported in `issues` with their line number while valid entries remain
available. A limit retains the most recent matching entries.

The CLI can also verify and export logs:

```bash
toolgate audit verify --file .toolgate/audit.jsonl --json
toolgate audit export --file .toolgate/audit.jsonl --format ndjson
```
