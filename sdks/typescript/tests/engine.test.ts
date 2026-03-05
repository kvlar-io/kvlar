import { describe, it, expect, vi, beforeEach } from "vitest";
import { KvlarEngine, KvlarError } from "../src/index.js";
import type { Action, EvalResult, TestResult, Decision } from "../src/index.js";

// ---------------------------------------------------------------------------
// Mock child_process.execFileSync
// ---------------------------------------------------------------------------

const mockExecFileSync = vi.fn();
vi.mock("node:child_process", () => ({
  execFileSync: (...args: unknown[]) => mockExecFileSync(...args),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Make the binary check succeed. */
function allowBinaryCheck(): void {
  mockExecFileSync.mockImplementationOnce(() => "kvlar 0.3.0");
}

/** Create an engine with the binary check mocked. */
function createEngine(policy = "policy.yaml"): KvlarEngine {
  allowBinaryCheck();
  return new KvlarEngine(policy);
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe("KvlarEngine constructor", () => {
  beforeEach(() => {
    mockExecFileSync.mockReset();
  });

  it("throws KvlarError if binary is not found", () => {
    mockExecFileSync.mockImplementationOnce(() => {
      throw new Error("ENOENT");
    });
    expect(() => new KvlarEngine("policy.yaml")).toThrow(KvlarError);
    expect(() => {
      mockExecFileSync.mockImplementationOnce(() => {
        throw new Error("ENOENT");
      });
      return new KvlarEngine("policy.yaml");
    }).toThrow(/kvlar binary not found/);
  });

  it("accepts a custom binary path", () => {
    allowBinaryCheck();
    const engine = new KvlarEngine("policy.yaml", {
      binary: "/usr/local/bin/kvlar",
    });
    expect(engine.binary).toBe("/usr/local/bin/kvlar");
  });

  it("stores the resolved policy path", () => {
    const engine = createEngine("policies/demo.yaml");
    expect(engine.policyPath).toContain("policies/demo.yaml");
  });

  it("defaults timeout to 30000", () => {
    const engine = createEngine();
    expect(engine.timeout).toBe(30_000);
  });

  it("accepts a custom timeout", () => {
    allowBinaryCheck();
    const engine = new KvlarEngine("policy.yaml", { timeout: 5000 });
    expect(engine.timeout).toBe(5000);
  });
});

// ---------------------------------------------------------------------------
// evaluate()
// ---------------------------------------------------------------------------

describe("KvlarEngine.evaluate", () => {
  let engine: KvlarEngine;

  beforeEach(() => {
    mockExecFileSync.mockReset();
    engine = createEngine();
  });

  it("returns allow decision from JSON output", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({ decision: "allow", rule_id: "allow-read" }),
    );
    const result = engine.evaluate({ tool: "read_file" });
    expect(result.decision).toBe("allow");
    expect(result.ruleId).toBe("allow-read");
  });

  it("returns deny decision from JSON output", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({
        decision: "deny",
        rule_id: "deny-delete",
        reason: "File deletion not allowed",
      }),
    );
    const result = engine.evaluate({ tool: "delete_file" });
    expect(result.decision).toBe("deny");
    expect(result.ruleId).toBe("deny-delete");
    expect(result.reason).toBe("File deletion not allowed");
  });

  it("returns require_approval decision from JSON output", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({ decision: "require_approval", rule_id: "approve-write" }),
    );
    const result = engine.evaluate({ tool: "write_file" });
    expect(result.decision).toBe("require_approval");
  });

  it("falls back to human-readable parsing for allow", () => {
    mockExecFileSync.mockReturnValueOnce("Decision: ALLOW");
    const result = engine.evaluate({ tool: "read_file" });
    expect(result.decision).toBe("allow");
  });

  it("falls back to human-readable parsing for deny", () => {
    mockExecFileSync.mockReturnValueOnce("Decision: DENY — blocked");
    const result = engine.evaluate({ tool: "delete_file" });
    expect(result.decision).toBe("deny");
  });

  it("falls back to human-readable parsing for require_approval", () => {
    mockExecFileSync.mockReturnValueOnce("Requires human approval");
    const result = engine.evaluate({ tool: "write_file" });
    expect(result.decision).toBe("require_approval");
  });

  it("defaults to deny for unparseable output", () => {
    mockExecFileSync.mockReturnValueOnce("something unexpected");
    const result = engine.evaluate({ tool: "unknown" });
    expect(result.decision).toBe("deny");
  });

  it("passes tool arguments to the CLI", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({ decision: "allow" }),
    );
    engine.evaluate({
      tool: "query",
      arguments: { sql: "SELECT 1" },
    });
    // calls[0] is the constructor's --version check; calls[1] is the eval call
    const callArgs = mockExecFileSync.mock.calls[1];
    const args: string[] = callArgs[1];
    expect(args).toContain("--args");
    const argsIdx = args.indexOf("--args");
    expect(JSON.parse(args[argsIdx + 1])).toEqual({ sql: "SELECT 1" });
  });

  it("passes agent ID to the CLI", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({ decision: "allow" }),
    );
    engine.evaluate({
      tool: "read_file",
      agentId: "agent-1",
    });
    const callArgs = mockExecFileSync.mock.calls[1];
    const args: string[] = callArgs[1];
    expect(args).toContain("--agent");
    expect(args[args.indexOf("--agent") + 1]).toBe("agent-1");
  });

  it("omits --args when arguments are empty", () => {
    mockExecFileSync.mockReturnValueOnce(
      JSON.stringify({ decision: "allow" }),
    );
    engine.evaluate({ tool: "read_file", arguments: {} });
    const args: string[] = mockExecFileSync.mock.calls[0][1];
    expect(args).not.toContain("--args");
  });

  it("throws KvlarError on CLI failure", () => {
    const err = Object.assign(new Error("exit 1"), {
      status: 1,
      stdout: "",
      stderr: "policy file not found",
    });
    mockExecFileSync.mockImplementationOnce(() => {
      throw err;
    });
    expect(() => engine.evaluate({ tool: "read_file" })).toThrow(KvlarError);
    expect(() => {
      mockExecFileSync.mockImplementationOnce(() => {
        throw err;
      });
      return engine.evaluate({ tool: "read_file" });
    }).toThrow(/policy file not found/);
  });

  it("stores raw JSON data in result", () => {
    const data = {
      decision: "allow",
      rule_id: "r1",
      extra_field: "extra_value",
    };
    mockExecFileSync.mockReturnValueOnce(JSON.stringify(data));
    const result = engine.evaluate({ tool: "read_file" });
    expect(result.raw).toEqual(data);
  });
});

// ---------------------------------------------------------------------------
// testPolicy()
// ---------------------------------------------------------------------------

describe("KvlarEngine.testPolicy", () => {
  let engine: KvlarEngine;

  beforeEach(() => {
    mockExecFileSync.mockReset();
    engine = createEngine();
  });

  it("returns passed=true for a passing suite", () => {
    mockExecFileSync.mockReturnValueOnce(
      "Running tests...\n5 passed, 0 failed\nAll tests passed!",
    );
    const result = engine.testPolicy("tests.yaml");
    expect(result.passed).toBe(true);
    expect(result.total).toBe(5);
    expect(result.failures).toBe(0);
  });

  it("returns passed=false for a failing suite", () => {
    const err = Object.assign(new Error("exit 1"), {
      status: 1,
      stdout: "3 passed, 2 failed\nSome tests failed",
      stderr: "",
    });
    mockExecFileSync.mockImplementationOnce(() => {
      throw err;
    });
    const result = engine.testPolicy("tests.yaml");
    expect(result.passed).toBe(false);
    expect(result.total).toBe(5);
    expect(result.failures).toBe(2);
  });

  it("captures output text", () => {
    mockExecFileSync.mockReturnValueOnce("1 passed, 0 failed");
    const result = engine.testPolicy("tests.yaml");
    expect(result.output).toBe("1 passed, 0 failed");
  });
});

// ---------------------------------------------------------------------------
// validate()
// ---------------------------------------------------------------------------

describe("KvlarEngine.validate", () => {
  let engine: KvlarEngine;

  beforeEach(() => {
    mockExecFileSync.mockReset();
    engine = createEngine();
  });

  it("returns true for valid policy", () => {
    mockExecFileSync.mockReturnValueOnce("Policy is valid");
    expect(engine.validate()).toBe(true);
  });

  it("returns false for invalid policy", () => {
    const err = Object.assign(new Error("exit 1"), {
      status: 1,
      stdout: "Invalid policy",
      stderr: "syntax error at line 5",
    });
    mockExecFileSync.mockImplementationOnce(() => {
      throw err;
    });
    expect(engine.validate()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

describe("types", () => {
  it("Decision type accepts valid values", () => {
    const decisions: Decision[] = ["allow", "deny", "require_approval"];
    expect(decisions).toHaveLength(3);
  });

  it("EvalResult has correct shape", () => {
    const result: EvalResult = {
      decision: "allow",
      raw: {},
    };
    expect(result.decision).toBe("allow");
    expect(result.ruleId).toBeUndefined();
    expect(result.reason).toBeUndefined();
  });

  it("TestResult has correct shape", () => {
    const result: TestResult = {
      passed: true,
      total: 5,
      failures: 0,
      output: "all good",
    };
    expect(result.passed).toBe(true);
    expect(result.total).toBe(5);
  });
});
