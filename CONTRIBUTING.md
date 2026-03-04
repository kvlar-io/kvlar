# Contributing to Kvlar

Thank you for your interest in contributing to Kvlar! We welcome contributions of all kinds.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/kvlar.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run checks: `cargo test --workspace && cargo clippy --workspace -- -D warnings`
6. Commit: `git commit -m "Add my feature"`
7. Push: `git push origin my-feature`
8. Open a Pull Request

## Development Setup

```bash
# Prerequisites
rustup update stable

# Build
cargo build --workspace

# Test
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

## Code Style

- Every public type and function has a doc comment (`///`)
- Every module has a module-level doc comment (`//!`)
- No `unwrap()` in library code — use `?` or return `Result`
- `unwrap()` is OK in tests
- Keep `kvlar-core` free of I/O and async
- Tests live next to the code they test (inline `mod tests`)

## Pull Request Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo fmt --all --check` passes
- [ ] New tests added for new functionality
- [ ] Doc comments added for new public items
- [ ] CHANGELOG.md updated (if applicable)

## Architecture

Read `CLAUDE.md` for a full overview of the project architecture, crate structure, and conventions.

## License

By contributing to Kvlar, you agree that your contributions will be licensed under the Apache License 2.0.
