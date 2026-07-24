# state-history-forensic — Purpose & Scope

*This is a **library-tier** intent doc (Purpose & Scope), not a product PRD:
`state-history-forensic` ships no binary an examiner runs — it is a zero-dependency
KNOWLEDGE-tier crate that other crates link. Per the fleet PRD & ADR standard, a
library gets this lighter artifact under the unified `docs/PRD.md` filename; the
load-bearing decisions live as ADRs under [`docs/decisions/`](decisions/). Every
claim below is grounded in a read of `src/` and `Cargo.toml` (2026-07-24).*

## What it is

The shared `[H]` state-history vocabulary for the SecurityRonin forensic fleet: the
types and traits that describe an artifact's identity, the provenance of a
timestamp, the ordering of states within a cohort, and the safety of materializing
one state — with **no parsing, no I/O, and no external dependencies** (ADR 0001).

`[H]` is a cross-cutting *functor*, not a vertical tier: it lifts each base
navigation primitive to a time-indexed variant.

| Lifted primitive | Time-indexed source |
|---|---|
| `[P^H]` disk | VSS, APFS snapshots, Time Machine, btrfs |
| `[M^H]` memory | hiberfil chain, VMware memory snapshots |
| `[L^H]` log | rotated logs, journald sealed epochs |
| `[Q^H]` query | point-in-time osquery exports |
| `[C^H] ≅ [C]` | git already encodes history — `[H]` on `[C]` is the identity |

## Who links it

- **Concrete `[H]` history crates** (`vss-history`, `wal-history`, `git-history`,
  … — all currently `[planned]`) implement the `HistoricalSource`,
  `AcquisitionProtocol`, and `StateMaterializer` traits and depend *down* onto this
  leaf. They supply the medium-specific handle type `H` (ADR 0003).
- **ORCHESTRATION (Issen)** consumes the resulting `TemporalCohort<H>` uniformly to
  build timelines and correlate states across media.

The crate depends only on the first-party `forensicnomicon-core` leaf, for the
`FileId` reused inside `PersistentAddress` (ADR 0006, ADR 0007).

## What it provides

| Module | Provides |
|---|---|
| `identity` | `ArtifactRef` + `IdentityClaim` multi-facet identity, `IdentityDiscipline` selector, `PersistentAddress` with its versioned canonical binary key (ADR 0004, 0006) |
| `clock` | `ClockProvenance` — four orthogonal axes: source / trust grade / tamper resistance / ordering-only (ADR 0002) |
| `epoch` | `EpochTag`, `LsnKind`, `CohortTopology`, `MaterializationSafety`, `PruneTrigger` |
| `cohort` | `TemporalCohort<H>` / `TemporalState<H>`, `Timestamp`, `Tombstone`, `IdentityDiscontinuity` (ADR 0003) |
| `source` | `HistoricalSource`, `AcquisitionProtocol`, `StateMaterializer` traits; `Evidence` vs `WorkingCopy` boundary (ADR 0005) |

## Scope

- Define the vocabulary once so every `[H]` crate and ORCHESTRATION share one
  identity/clock/cohort/materialization model instead of N bespoke ones.
- Keep identity a genuine equivalence relation with a deterministic, in-crate,
  versioned correlation key that carries no host and no epoch (ADR 0006).
- Make evidence-destroying access structurally hard to invoke by accident (typed
  `MaterializationSafety`, `Evidence` vs `WorkingCopy` split — ADR 0005).

## Non-goals

- **No parsing, decoding, or I/O.** Reading any medium (VSS block ranges, WAL
  frames, git objects, journald streams) is the concrete `[H]` crate's job.
- **No cryptography.** Digests are carried as bytes; `cohort_key` is an explicitly
  non-cryptographic fold, and any collision-resistance layer is the caller's
  (ADR 0001, 0004).
- **No datetime library.** `Timestamp` is a plain `{ secs, nanos }` value; `chrono`
  conversion is left to the consumer (ADR 0001).
- **No ORCHESTRATION logic.** Cohort correlation, timeline assembly, and reporting
  live in Issen, above this leaf.

## Correctness posture

The only place the crate parses bytes is `PersistentAddress::decode`, which is
panic-free by construction (bounds-checked `ByteCursor`, typed `DecodeError`) and
covered by `tests/persistent_address.rs` (round-trip, per-field injectivity,
decode-never-panics-on-garbage, slot-reuse discriminator, host/epoch-exclusion
canary); `tests/api_shape.rs` pins the public surface. The fleet panic-free lint
posture is not yet declared as a `[lints]`/`deny.toml` table — tracked as residual
debt in ADR 0008.
