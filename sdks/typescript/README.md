# Kvlar TypeScript SDK

TypeScript/JavaScript wrapper for the [Kvlar](https://kvlar.io) policy engine CLI.

## Prerequisites

Install the `kvlar` CLI:

```bash
cargo install kvlar-cli
```

## Installation

```bash
npm install kvlar
```

## Usage

```typescript
import { KvlarEngine } from "kvlar";

const engine = new KvlarEngine("policy.yaml");

// Evaluate an action against your policy
const result = engine.evaluate({
  tool: "read_file",
  arguments: { path: "/etc/passwd" },
});

if (result.decision === "deny") {
  console.log(`Blocked: ${result.reason}`);
}

// Validate policy syntax
const valid = engine.validate();

// Run test suite
const tests = engine.testPolicy("policy.test.yaml");
console.log(`${tests.total} tests, ${tests.failures} failures`);
```

## API

### `new KvlarEngine(policyPath, options?)`

- `policyPath` — path to YAML policy file
- `options.binary` — path to kvlar binary (default: `"kvlar"`)
- `options.timeout` — CLI timeout in ms (default: `30000`)

### `engine.evaluate(action): EvalResult`

- `action.tool` — tool name
- `action.arguments` — tool arguments (optional)
- `action.agentId` — agent identifier (optional)

Returns `{ decision, ruleId?, reason?, raw }`.

### `engine.testPolicy(testFile): TestResult`

Returns `{ passed, total, failures, output }`.

### `engine.validate(): boolean`

Returns `true` if the policy file is syntactically valid.

## License

Apache-2.0
