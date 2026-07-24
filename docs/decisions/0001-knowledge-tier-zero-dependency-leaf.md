# 1. KNOWLEDGE-tier, zero-dependency type/trait leaf

Date: 2026-07-24
Status: Accepted

## Context

The fleet layer architecture (ronin-issen `CLAUDE.md`) defines `[H]` as a
cross-cutting *functor*, not a vertical tier: it lifts each base navigation
primitive to a time-indexed variant (`[P^H]` disk snapshots, `[M^H]` memory
snapshots, `[L^H]` rotated/sealed logs, `[Q^H]` point-in-time query exports,
`[C^H] ≅ [C]` where git already encodes history). Concrete history crates
(`vss-history`, `wal-history`, `git-history`, … — all `[planned]`) each observe a
different medium and each carry heavy, medium-specific parsing. What they share is
*vocabulary*: how to name an artifact's identity, grade the provenance of a
timestamp, order states within a cohort, and describe the safety of materializing
one state.

If that shared vocabulary lived inside any one history crate, or pulled in a
datetime/serialization dependency, every other history crate would either fork the
types or inherit an unwanted dependency, and the vocabulary would drift.

## Decision

`state-history-forensic` is a KNOWLEDGE-tier leaf holding **only type definitions
and trait signatures** — no parsing algorithms, no file I/O, no binary
deserialization (`src/lib.rs` crate doc). It sits at the same layer as
`forensicnomicon` in the fleet hierarchy, and every `[H]` crate depends *down* onto
it while it depends on (almost) no one.

Concrete consequences visible in the code:

- The only dependency is the first-party `forensicnomicon-core` leaf
  (`Cargo.toml`; see ADR 0007). No external crates.
- `Timestamp` is defined in-crate as `{ secs: i64, nanos: u32 }` and is explicitly
  "Chrono-free; callers that use `chrono` can convert via
  `DateTime::from_timestamp`" (`src/cohort.rs`) — rather than take a `chrono`/`time`
  dependency into the leaf.
- Digest values (`IdentityClaim::ContentHash`, `CohortKey`, `EpochTag`) are carried
  as raw bytes with `new`/`from_bytes` constructors; the crate never hashes, so it
  needs no crypto dependency. `ArtifactRef::cohort_key` uses an explicitly
  "not crypto-secure" fold and documents that "callers that need
  collision-resistance should supply their own hashing layer above this crate".

## Consequences

- The vocabulary is defined once, fleet-wide; a new `[H]` crate implements
  `HistoricalSource` and reuses the same identity/clock/cohort types, so
  ORCHESTRATION (Issen) sees a uniform surface regardless of medium.
- A zero-external-dependency leaf compiles fast, has a trivial supply-chain
  surface, and imposes no transitive version constraints on the many crates that
  link it.
- The cost is deferral: anything requiring real computation (hashing, datetime
  math, byte parsing of a medium) lives in the consumer, not here. That is the
  intended division of labor for a KNOWLEDGE leaf.
