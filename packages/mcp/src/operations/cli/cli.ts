import { readFile, writeFile } from "node:fs/promises";
import { readAuditLog, summarizeAudit } from "../audit/readAuditLog.js";
import type { AuditDecision } from "../audit/auditLogger.js";
import type { PolicyManifest } from "../manifest/manifest.js";
import { compareManifests } from "../manifest/compare.js";
import type { ManifestChangeSeverity } from "../manifest/compare.js";
import { policyManifestSchema, validateManifest } from "../manifest/schema.js";
import {
  createManifestFromConfig,
  policyConfigSchema,
  validatePolicyConfig,
  type PolicyConfig
} from "../../policies/config/configSchema.js";
import { migratePolicyConfig } from "../../policies/config/migrateConfig.js";
import { migrateManifest } from "../manifest/migrate.js";
import {
  summarizePolicySecurity,
  validateManifestSecurity,
  validatePolicyConfigSecurity,
  type PolicySecurityFinding,
  type PolicySecuritySeverity
} from "../../policies/validation/securityLint.js";

export interface CliIo {
  stdout: Pick<NodeJS.WriteStream, "write">;
  stderr: Pick<NodeJS.WriteStream, "write">;
}

export async function runCli(
  args: string[],
  io: CliIo = { stdout: process.stdout, stderr: process.stderr }
): Promise<number> {
  const [command, ...rest] = args;

  if (!command || command === "--help" || command === "-h") {
    writeHelp(io.stdout);
    return 0;
  }

  if (command === "manifest") {
    return runManifestCommand(rest, io);
  }

  if (command === "validate-manifest") {
    return runValidateManifestCommand(rest, io);
  }

  if (command === "validate-config") {
    return runValidateConfigCommand(rest, io);
  }

  if (command === "audit") {
    return runAuditCommand(rest, io);
  }

  if (command === "check-manifest") {
    return runCheckManifestCommand(rest, io);
  }

  if (command === "lint-policy") {
    return runLintPolicyCommand(rest, io);
  }

  if (command === "lint-manifest") {
    return runLintManifestCommand(rest, io);
  }

  if (command === "migrate-manifest") {
    return runMigrationCommand(rest, io, migrateManifest);
  }

  if (command === "migrate-config") {
    return runMigrationCommand(rest, io, migratePolicyConfig);
  }

  if (command === "schema") {
    return runSchemaCommand(rest, io);
  }

  io.stderr.write(`Unknown command '${command}'.\n`);
  writeHelp(io.stderr);
  return 1;
}

async function runManifestCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const configPath = options.config ?? options.c;

  if (!configPath) {
    io.stderr.write("Missing required --config option.\n");
    return 1;
  }

  const config = await readJson<unknown>(configPath);
  const validation = validatePolicyConfig(config);
  if (!validation.valid) {
    writeIssues(validation.issues, io.stderr);
    return 1;
  }

  const manifest = createManifestFromConfig(config as PolicyConfig);
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;

  const outPath = options.out ?? options.o;
  if (outPath) {
    await writeFile(outPath, serialized, "utf8");
  } else {
    io.stdout.write(serialized);
  }

  return 0;
}

async function runValidateConfigCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const configPath = options.file ?? options.f ?? options.config ?? options.c;
  if (!configPath) {
    io.stderr.write("Missing required --file option.\n");
    return 1;
  }

  const config = await readJson<unknown>(configPath);
  const result = validatePolicyConfig(config);
  if (result.valid) {
    io.stdout.write("Policy config is valid.\n");
    return 0;
  }
  writeIssues(result.issues, io.stderr);
  return 1;
}

async function runMigrationCommand(
  args: string[],
  io: CliIo,
  migrate: (value: unknown) => unknown
): Promise<number> {
  const options = parseOptions(args);
  const file = options.file ?? options.f;
  const out = options.out ?? options.o;
  if (!file || !out) {
    io.stderr.write("Missing required --file and --out options.\n");
    return 1;
  }
  try {
    const migrated = migrate(await readJson<unknown>(file));
    await writeFile(out, `${JSON.stringify(migrated, null, 2)}\n`, "utf8");
    io.stdout.write(`Wrote ${out}.\n`);
    return 0;
  } catch (error) {
    io.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

async function runSchemaCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const type = options.type;
  if (type !== "manifest" && type !== "config") {
    io.stderr.write("--type must be manifest or config.\n");
    return 1;
  }
  const serialized = `${JSON.stringify(type === "manifest" ? policyManifestSchema : policyConfigSchema, null, 2)}\n`;
  const out = options.out ?? options.o;
  if (out) await writeFile(out, serialized, "utf8");
  else io.stdout.write(serialized);
  return 0;
}

async function runValidateManifestCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const manifestPath = options.file ?? options.f;

  if (!manifestPath) {
    io.stderr.write("Missing required --file option.\n");
    return 1;
  }

  const manifest = await readJson<unknown>(manifestPath);
  const result = validateManifest(manifest);

  if (result.valid) {
    io.stdout.write("Manifest is valid.\n");
    return 0;
  }

  for (const issue of result.issues) {
    io.stderr.write(`${issue.path}: ${issue.message}\n`);
  }
  return 1;
}

async function runLintPolicyCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const configPath = options.config ?? options.file ?? options.c ?? options.f;
  if (!configPath) {
    io.stderr.write("Missing required --config option.\n");
    return 1;
  }
  const failOn = options["fail-on"] ?? "danger";
  if (!isPolicySecuritySeverity(failOn)) {
    io.stderr.write("--fail-on must be info, warning, or danger.\n");
    return 1;
  }
  const config = await readJson<unknown>(configPath);
  const validation = validatePolicyConfig(config);
  if (!validation.valid) {
    writeIssues(validation.issues, io.stderr);
    return 1;
  }
  const findings = validatePolicyConfigSecurity(config as PolicyConfig, {
    strictPathMode: options["strict-path-mode"] === "true"
  });
  return writeSecurityLintResult(findings, failOn, options.json === "true", io);
}

async function runLintManifestCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const manifestPath = options.file ?? options.f;
  if (!manifestPath) {
    io.stderr.write("Missing required --file option.\n");
    return 1;
  }
  const failOn = options["fail-on"] ?? "danger";
  if (!isPolicySecuritySeverity(failOn)) {
    io.stderr.write("--fail-on must be info, warning, or danger.\n");
    return 1;
  }
  const manifest = await readJson<unknown>(manifestPath);
  const validation = validateManifest(manifest);
  if (!validation.valid) {
    writeIssues(validation.issues, io.stderr);
    return 1;
  }
  const findings = validateManifestSecurity(manifest as PolicyManifest, {
    strictPathMode: options["strict-path-mode"] === "true"
  });
  return writeSecurityLintResult(findings, failOn, options.json === "true", io);
}

async function runAuditCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const file = options.file ?? options.f;
  if (!file) {
    io.stderr.write("Missing required --file option.\n");
    return 1;
  }

  try {
    const result = await readAuditLog(file, {
      tool: options.tool,
      decision: options.decision as AuditDecision | undefined,
      reason: options.reason,
      since: options.since,
      until: options.until,
      limit: options.limit === undefined ? undefined : Number(options.limit)
    });
    const summary = summarizeAudit(result.entries);

    if (options.json === "true") {
      io.stdout.write(`${JSON.stringify({ summary, issues: result.issues }, null, 2)}\n`);
    } else {
      writeAuditSummary(summary, io.stdout);
      for (const issue of result.issues) {
        io.stderr.write(`line ${issue.line}: ${issue.message}\n`);
      }
    }
    return result.issues.length === 0 ? 0 : 1;
  } catch (error) {
    io.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

async function runCheckManifestCommand(args: string[], io: CliIo): Promise<number> {
  const options = parseOptions(args);
  const basePath = options.base;
  const headPath = options.head;
  if (!basePath || !headPath) {
    io.stderr.write("Missing required --base and --head options.\n");
    return 1;
  }
  const failOn = options["fail-on"] ?? "danger";
  if (!isSeverity(failOn)) {
    io.stderr.write("--fail-on must be info, warning, or danger.\n");
    return 1;
  }
  const failOnAdvisory = options["fail-on-advisory"] ?? failOn;
  if (!isPolicySecuritySeverity(failOnAdvisory)) {
    io.stderr.write("--fail-on-advisory must be info, warning, or danger.\n");
    return 1;
  }

  try {
    const base = await readJson<unknown>(basePath);
    const head = await readJson<unknown>(headPath);
    const baseValidation = validateManifest(base);
    const headValidation = validateManifest(head);
    if (!baseValidation.valid || !headValidation.valid) {
      writeIssues(baseValidation.issues.map((issue) => ({ ...issue, path: `base:${issue.path}` })), io.stderr);
      writeIssues(headValidation.issues.map((issue) => ({ ...issue, path: `head:${issue.path}` })), io.stderr);
      return 1;
    }

    const comparison = compareManifests(base as PolicyManifest, head as PolicyManifest);
    const lint = options.lint === "true"
      ? summarizePolicySecurity(
          validateManifestSecurity(head as PolicyManifest, {
            strictPathMode: options["strict-path-mode"] === "true"
          }),
          failOnAdvisory
        )
      : undefined;
    const failed = comparison.changes.some((change) => severityRank(change.severity) >= severityRank(failOn)) || (lint ? !lint.passed : false);
    if (options.json === "true") {
      io.stdout.write(`${JSON.stringify({ ...comparison, lint, passed: !failed, failOn }, null, 2)}\n`);
    } else if (comparison.changes.length === 0) {
      io.stdout.write("No policy manifest changes.\n");
      if (lint) writeSecurityFindings(lint.findings, io.stdout);
    } else {
      for (const change of comparison.changes) {
        io.stdout.write(`[${change.severity.toUpperCase()}] ${change.code} ${change.message}\n`);
      }
      if (lint) writeSecurityFindings(lint.findings, io.stdout);
      io.stdout.write(`Policy check ${failed ? "failed" : "passed"} at '${failOn}' threshold.\n`);
    }
    return failed ? 1 : 0;
  } catch (error) {
    io.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
}

function parseOptions(args: string[]): Record<string, string | undefined> {
  const options: Record<string, string | undefined> = {};

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith("-")) {
      continue;
    }

    const normalized = arg.replace(/^-+/, "");
    const inlineSeparator = normalized.indexOf("=");
    if (inlineSeparator >= 0) {
      options[normalized.slice(0, inlineSeparator)] = normalized.slice(inlineSeparator + 1);
      continue;
    }

    const next = args[index + 1];
    if (next === undefined || next.startsWith("-")) {
      options[normalized] = "true";
    } else {
      options[normalized] = next;
      index += 1;
    }
  }

  return options;
}

async function readJson<T>(file: string): Promise<T> {
  const content = await readFile(file, "utf8");
  return JSON.parse(content.replace(/^\uFEFF/, "")) as T;
}

function writeHelp(output: Pick<NodeJS.WriteStream, "write">): void {
  output.write(`ToolGateKit CLI

Usage:
  toolgate manifest --config toolgate.config.json [--out policy-manifest.json]
  toolgate validate-config --file toolgate.config.json
  toolgate validate-manifest --file policy-manifest.json
  toolgate audit --file .toolgate/audit.jsonl [--tool name] [--decision blocked] [--json]
  toolgate check-manifest --base before.json --head after.json [--fail-on danger] [--json]
  toolgate lint-policy --config toolgate.config.json [--fail-on danger] [--json]
  toolgate lint-manifest --file policy-manifest.json [--fail-on danger] [--json]
  toolgate migrate-manifest --file old.json --out policy-manifest.json
  toolgate migrate-config --file old.json --out toolgate.config.json
  toolgate schema --type manifest|config [--out schema.json]

Commands:
  manifest           Create a policy manifest from a JSON config.
  validate-config    Validate a JSON policy config.
  validate-manifest  Validate a policy manifest.
  audit              Filter and summarize a JSONL audit log.
  check-manifest     Detect security-relevant policy manifest changes.
  lint-policy        Report security advisories for a static policy config.
  lint-manifest      Report security advisories for a policy manifest.
  migrate-manifest   Upgrade a pre-v1 manifest to schema version 1.0.
  migrate-config     Upgrade a pre-v1 config to schema version 1.0.
  schema             Print or write a stable v1 JSON Schema.
`);
}

function isSeverity(value: string): value is ManifestChangeSeverity {
  return value === "info" || value === "warning" || value === "danger";
}

function isPolicySecuritySeverity(value: string): value is PolicySecuritySeverity {
  return value === "info" || value === "warning" || value === "danger";
}

function severityRank(value: ManifestChangeSeverity): number {
  return { info: 0, warning: 1, danger: 2 }[value];
}

function writeAuditSummary(
  summary: ReturnType<typeof summarizeAudit>,
  output: Pick<NodeJS.WriteStream, "write">
): void {
  output.write(`Audit entries: ${summary.total}\n`);
  output.write(
    `Decisions: allowed=${summary.decisions.allowed} blocked=${summary.decisions.blocked} failed=${summary.decisions.failed}\n`
  );
  output.write(
    `Average duration: ${summary.averageDurationMs === null ? "n/a" : `${summary.averageDurationMs.toFixed(2)}ms`}\n`
  );
  for (const [tool, count] of Object.entries(summary.tools).sort(([a], [b]) => a.localeCompare(b))) {
    output.write(`Tool ${tool}: ${count}\n`);
  }
}

function writeIssues(
  issues: Array<{ path: string; message: string }>,
  output: Pick<NodeJS.WriteStream, "write">
): void {
  for (const issue of issues) {
    output.write(`${issue.path}: ${issue.message}\n`);
  }
}

function writeSecurityLintResult(
  findings: PolicySecurityFinding[],
  failOn: PolicySecuritySeverity,
  json: boolean,
  io: CliIo
): number {
  const result = summarizePolicySecurity(findings, failOn);
  if (json) {
    io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else if (findings.length === 0) {
    io.stdout.write("No policy security advisories.\n");
  } else {
    writeSecurityFindings(findings, io.stdout);
    io.stdout.write(`Policy lint ${result.passed ? "passed" : "failed"} at '${failOn}' threshold.\n`);
  }
  return result.passed ? 0 : 1;
}

function writeSecurityFindings(
  findings: PolicySecurityFinding[],
  output: Pick<NodeJS.WriteStream, "write">
): void {
  for (const finding of findings) {
    output.write(`[${finding.severity.toUpperCase()}] ${finding.code} ${finding.path} ${finding.message}\n`);
  }
}
