# 8. Edition 2024, declared MSRV floor 1.85, dev toolchain pinned to fleet stable

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the **dev toolchain** (pin every repo to the
current fleet stable via `rust-toolchain.toml`) from the **declared MSRV**
(`rust-version`, a downstream promise). Published libraries are expected to keep a
*low, CI-verified* floor (typically `1.75`/`1.80`) so third parties on older
compilers can still link them.

This crate is a published library, so a low floor would be the default. Two facts
in the repo constrain it:

- `Cargo.toml` sets `edition = "2024"`. Edition 2024 was stabilized in Rust 1.85,
  so *any* edition-2024 crate has a hard minimum of 1.85 — below the fleet's usual
  library floor.
- `rust-toolchain.toml` pins the dev channel to `1.96.0` (commit `11d6002`,
  "pin toolchain to 1.96.0 (fleet toolchain policy)"), with `clippy` + `rustfmt`
  components declared in the toml (the fleet single-source-of-truth pattern).

## Decision

Adopt edition 2024 and declare `rust-version = "1.85"` — the true minimum imposed
by the edition — while pinning the dev toolchain to the fleet stable (`1.96.0`).
The declared MSRV is therefore honest: it is exactly the lowest compiler that can
build the crate as written, not an aspirational lower number the edition would make
false.

## Consequences

- The library floor is 1.85 rather than the fleet's usual 1.75/1.80. Consumers on a
  pre-1.85 compiler cannot link this crate; that is an accepted, documented cost of
  edition 2024.
- Dev/CI build on 1.96.0 while the promise to downstreams is 1.85; a low-MSRV CI
  job would verify the floor (the fleet library pattern).
- **Unrecovered rationale:** the choice of edition 2024 *over* edition 2021 — which
  would have permitted the fleet's usual lower floor — is not explained in the
  available git history. Rationale reconstructed from structure; original intent not
  recovered in available history. The most likely reason is alignment with the
  current fleet edition, but that is inference, not a recorded decision.
- **Residual lint-posture debt:** the crate has no `deny.toml`, `clippy.toml`, or
  `[lints]` table declaring the fleet panic-free posture
  (`unwrap_used`/`expect_used = deny`, `unsafe_code = forbid`). The code is pure
  safe Rust and the sole byte-parsing path is panic-free by construction and by test
  (ADR 0006), but that posture is not yet enforced by declared lints. Adding the
  base `[lints]` tier is outstanding work, not a decision recorded here.
