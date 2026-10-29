# Contributing

Open an issue before starting a large feature or changing public APIs. For bugs,
include a small reproducer, the Celerity version, enabled features, Rust version,
and operating system.

Keep pull requests focused. Add a regression test for a bug fix and explain how
you checked the change. Run the relevant checks before submitting:

```bash
cargo fmt --check
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

CI also checks individual feature combinations and the minimum Rust version.
Changes must continue to compile with Rust 1.88.

For libzmq interoperability tests, follow the setup in the [README](../README.md).
Report security vulnerabilities privately using the [security policy](SECURITY.md).
