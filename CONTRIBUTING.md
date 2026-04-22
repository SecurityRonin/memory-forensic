# Contributing

This project follows strict TDD. For every change:

1. **RED** — write a failing test that defines the expected behavior, commit it, confirm it fails.
2. **GREEN** — write the minimal implementation to make the test pass, commit it separately, confirm it passes.
3. **REFACTOR** — clean up while keeping tests green.

Pull requests that arrive as a single "add feature + tests" commit will be asked to split. The failing-test commit is the verifiable proof that tests were written first.

## Getting started

```bash
git clone https://github.com/SecurityRonin/memory-forensic
cd memory-forensic
cargo test --workspace
```

## Pull request checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo fmt --check` passes
- [ ] RED commit (failing tests) precedes GREEN commit (implementation)

## Adding a new walker

1. Add the walker function to the appropriate crate (`memf-linux` or `memf-windows`)
2. Register it in `lib.rs`
3. Add ISF struct/field definitions to the test builder if needed
4. Follow the RED → GREEN commit pattern

## Symbol file (ISF) format

Walkers use ISF JSON (compatible with Volatility 3 symbol packs). For testing, the `IsfBuilder` in `memf-core::test_builders` constructs synthetic ISF in memory — no real symbol files required in tests.
