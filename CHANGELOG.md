# Changelog

## 1.1.1 - 2026-07-02

### Added

- Security advisory linting for static policy configs, manifests, and runtime policies.
- `toolgate lint-policy` and `toolgate lint-manifest` CLI commands with JSON output.
- `check-manifest --lint`, `--fail-on-advisory`, and `--strict-path-mode` support.
- GitHub Action lint inputs for advisory checks in CI.
- `strictPathPolicy()` helper for enforcing `pathRoot` on runtime path policies.

### Changed

- Reorganized `src/policy` into config, enforcement, and validation submodules.
- CLI JSON reading now tolerates UTF-8 BOM-prefixed files.
- GitHub Action default `toolgate-mcp` CLI version is now `1.1.1`.

## 1.0.3 - 2026-07-02

### Added

- Bound approval decisions to authenticated subject, exact tool name, stable input hash, policy/tool version, expiry, and one-time nonce.
- `approve()`, `denyApproval()`, `createMemoryApprovalNonceStore()`, and approval validation helpers.
- `pathRoot` canonical filesystem enforcement for path policies, including symlink/junction escape protection.
- Opt-in `exposePolicyDenialDetails` and `exposeRuleDenialDetails` controls.

### Changed

- Approval providers must return a bound `ApprovalDecision`; boolean approval and unbound approvals now fail closed.
- Built-in path, URL, command, and rule denials no longer echo denied values or secret rule details by default.
- Manifest/config schemas and manifest comparison expose and flag denial-detail exposure changes.
- GitHub Action default `toolgate-mcp` CLI version is now `1.0.3`.

## 1.0.0 - 2026-06-30

### Added

- Versioned `1.0` policy-config and manifest JSON Schemas with strict validators.
- Config and manifest migration API and CLI commands for pre-v1 files.
- `createToolGate()` registry with shared defaults, duplicate detection, and manifest collection.
- Keyed rate limits, shared/custom stores, namespaces, and fail-closed store errors.
- `gateMcpHandler()` for preserving MCP SDK request context.
- Dependency-free OpenTelemetry span observer.
- Public API contract tests and a v1 migration guide.

### Changed

- Manifests require `schemaVersion: "1.0"` and per-tool `redact` state.
- Manifest validation rejects unknown fields and duplicate tool names.
- Manifest security comparison detects disabled redaction and weakened keyed rate limits.
- The GitHub policy-check Action now pins `toolgate-mcp@1.0.0`.

### Breaking

- Pre-v1 configs and manifests must be migrated or regenerated before validation.
- Static config validation is strict; unknown fields are no longer ignored.

## 0.7.0 - 2026-06-30

### Added

- Fail-closed synchronous and asynchronous custom policy rules.
- Privacy-conscious lifecycle observer events for telemetry adapters.
- Security-aware manifest comparison API and `check-manifest` CLI command.
- Reusable GitHub composite action for pull-request policy checks.

### Changed

- Policy manifests now expose custom rule names for review without serializing executable code.
- Malformed custom rule decisions fail closed as `POLICY_RULE_ERROR`.

## 0.5.0 - 2026-06-29

### Added

- Host-driven async approval providers with explicit approved, denied, and provider-error results.
- Runtime policy validation, duplicate tool-name checks, and `toolgate validate-config`.
- Streaming audit-log reading, filtering, summaries, and the `toolgate audit` command.
- Dependency-free `gateMcp()` and `toMcpToolResult()` MCP result adapters.

### Changed

- `gate()` now fails fast with `InvalidToolPolicyError` when policy configuration is invalid.
- Approval metadata is included in the final audit entry for approved or denied calls.

## 0.3.0 - 2026-06-29

- Added the manifest JSON schema, validation helpers, and CLI manifest workflows.

## 0.2.0 - 2026-06-29

- Added network and command policies, custom extractors, rate limiting, and policy presets.

## 0.1.0 - 2026-06-29

- Initial policy gate, path controls, redaction, timeout, audit logging, and manifest generation.
