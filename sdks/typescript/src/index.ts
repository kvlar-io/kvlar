/**
 * Kvlar TypeScript SDK — subprocess wrapper around the kvlar CLI.
 *
 * @packageDocumentation
 */

import { execFileSync, type ExecFileSyncOptions } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Policy evaluation outcome. */
export type Decision = "allow" | "deny" | "require_approval";

/** Result of a policy evaluation. */
export interface EvalResult {
  decision: Decision;
  ruleId?: string;
  reason?: string;
  raw: Record<string, unknown>;
}

/** Result of running a policy test suite. */
export interface TestResult {
  passed: boolean;
  total: number;
  failures: number;
  output: string;
}

/** Action to evaluate against a policy. */
export interface Action {
  tool: string;
  arguments?: Record<string, unknown>;
  agentId?: string;
}

/** Options for creating a KvlarEngine. */
export interface KvlarEngineOptions {
  /** Path to the kvlar binary. Defaults to "kvlar". */
  binary?: string;
  /** Timeout in milliseconds for CLI commands. Defaults to 30000. */
  timeout?: number;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Raised when the kvlar CLI is missing or returns an unexpected error. */
export class KvlarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KvlarError";
  }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/**
 * Wraps the `kvlar` CLI binary for policy evaluation.
 *
 * @example
 * ```ts
 * const engine = new KvlarEngine("policy.yaml");
 * const result = engine.evaluate({ tool: "query", arguments: { sql: "DROP TABLE users" } });
 * if (result.decision === "deny") {
 *   console.log(`Blocked: ${result.reason}`);
 * }
 * ```
 */
export class KvlarEngine {
  readonly policyPath: string;
  readonly binary: string;
  readonly timeout: number;

  constructor(policyPath: string, options?: KvlarEngineOptions) {
    this.policyPath = resolve(policyPath);
    this.binary = options?.binary ?? "kvlar";
    this.timeout = options?.timeout ?? 30_000;
    this.resolveBinary();
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /** Evaluate a tool-call action against the loaded policy. */
  evaluate(action: Action): EvalResult {
    const args = ["eval", "-f", this.policyPath, "--tool", action.tool];

    if (action.arguments && Object.keys(action.arguments).length > 0) {
      args.push("--args", JSON.stringify(action.arguments));
    }

    if (action.agentId) {
      args.push("--agent", action.agentId);
    }

    const stdout = this.run(args);

    try {
      const data = JSON.parse(stdout) as Record<string, unknown>;
      const decisionStr = ((data.decision as string) ?? "deny").toLowerCase();
      const decision = parseDecision(decisionStr);

      return {
        decision,
        ruleId: data.rule_id as string | undefined,
        reason: data.reason as string | undefined,
        raw: data,
      };
    } catch {
      // Fallback: parse human-readable output
      const lower = stdout.toLowerCase();
      if (lower.includes("allow")) {
        return { decision: "allow", raw: {} };
      }
      if (lower.includes("require") && lower.includes("approval")) {
        return { decision: "require_approval", raw: {} };
      }
      return { decision: "deny", raw: {} };
    }
  }

  /** Run a `kvlar test` suite against a test YAML file. */
  testPolicy(testFile: string): TestResult {
    const args = ["test", "-f", resolve(testFile)];
    const { stdout, exitCode } = this.runUnchecked(args);

    let total = 0;
    let failures = 0;
    for (const line of stdout.split("\n")) {
      const matches = line.toLowerCase().matchAll(/(\d+)\s+(passed|failed)/g);
      for (const m of matches) {
        total += parseInt(m[1], 10);
        if (m[2] === "failed") {
          failures += parseInt(m[1], 10);
        }
      }
    }

    return {
      passed: exitCode === 0,
      total,
      failures,
      output: stdout.trim(),
    };
  }

  /** Validate the policy file syntax. Returns true if valid. */
  validate(): boolean {
    const { exitCode } = this.runUnchecked([
      "validate",
      "-f",
      this.policyPath,
    ]);
    return exitCode === 0;
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private resolveBinary(): void {
    // Quick check: try running --version
    try {
      execFileSync(this.binary, ["--version"], {
        timeout: 5000,
        stdio: "pipe",
      });
    } catch {
      throw new KvlarError(
        `kvlar binary not found: '${this.binary}'. Install it with: cargo install kvlar-cli`
      );
    }
  }

  private run(args: string[]): string {
    const opts: ExecFileSyncOptions = {
      timeout: this.timeout,
      stdio: ["pipe", "pipe", "pipe"],
      encoding: "utf-8" as BufferEncoding,
    };
    try {
      const result = execFileSync(this.binary, args, opts);
      return (result as unknown as string) ?? "";
    } catch (err: unknown) {
      if (isExecError(err)) {
        throw new KvlarError(
          `kvlar command failed (exit ${err.status}): ${(err.stderr as string)?.trim() ?? ""}`
        );
      }
      throw new KvlarError(`kvlar command failed: ${String(err)}`);
    }
  }

  private runUnchecked(args: string[]): { stdout: string; exitCode: number } {
    const opts: ExecFileSyncOptions = {
      timeout: this.timeout,
      stdio: ["pipe", "pipe", "pipe"],
      encoding: "utf-8" as BufferEncoding,
    };
    try {
      const result = execFileSync(this.binary, args, opts);
      return { stdout: (result as unknown as string) ?? "", exitCode: 0 };
    } catch (err: unknown) {
      if (isExecError(err)) {
        const stdout =
          ((err.stdout as string) ?? "") + ((err.stderr as string) ?? "");
        return { stdout, exitCode: err.status ?? 1 };
      }
      return { stdout: "", exitCode: 1 };
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseDecision(s: string): Decision {
  if (s === "allow" || s === "deny" || s === "require_approval") return s;
  return "deny";
}

interface ExecError {
  status: number;
  stdout: unknown;
  stderr: unknown;
}

function isExecError(err: unknown): err is ExecError {
  return (
    typeof err === "object" &&
    err !== null &&
    "status" in err &&
    typeof (err as ExecError).status === "number"
  );
}
