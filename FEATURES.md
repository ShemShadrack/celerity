# Feature Brainstorming

This file is a working backlog for ideas worth exploring in Celerity.

It is intentionally not a promise, release plan, or strict priority order. The goal is to capture useful directions without forcing every idea into the main README.

## Principles

- Prioritize stable, widely used ZeroMQ-style patterns before draft-only parity work.
- Treat libzmq draft sockets as a later milestone unless they unlock a concrete user need.
- Keep benchmark work close to upstream libzmq so comparisons stay credible.

### Pattern Coverage

- `DEALER/ROUTER`
  - Important for more advanced request-routing topologies.

- `XPUB/XSUB`
  - Useful for proxying, subscription-aware routing, and richer pub-sub topologies.

- `PAIR`
  - Small surface area, but less critical than the patterns above.

### Performance and Benchmarking

- Compare loopback TCP and IPC performance.
- Add profiling notes for Linux `perf` and flamegraph-based investigation.

### Runtime Adapters

- A blocking/synchronous adapter around the sans-IO core.
  - I like the idea of supporting a sync API as well, especially since some Rust users want a pure-Rust ZMQ-style library without committing to async everywhere.
- Other async runtimes can wait unless people genuinely ask for them. This is still a personal project, even if it is open source, so I do not want to spread maintenance effort too thin too early.

### Developer Experience

- Clearer security-configuration examples, especially for non-local `NULL`.

## Later Features

These are valuable, but should come after the stable core patterns unless a real user need pulls them forward.

### libzmq Draft / Thread-Safe Family

- `CLIENT/SERVER`
- `RADIO/DISH`
- `SCATTER/GATHER`
- `PEER`
- `CHANNEL`

Notes:

- These exist in libzmq, but several are part of its draft or thread-safe family rather than the baseline pattern set.
- They should sit near the end of the todo list unless Celerity explicitly decides to chase broad libzmq feature parity, including draft APIs.
