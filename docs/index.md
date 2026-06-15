# state-history-forensic

**The zero-dependency `[H]` state-history vocabulary for the SecurityRonin forensic fleet — the KNOWLEDGE-tier types and traits that lift every navigation primitive to a time-indexed variant.**

`state-history-forensic` contains only type definitions and trait signatures. There is no parsing, no file I/O, and no binary deserialization here — concrete `[H]` crates (vss-history, wal-history, git-history, …) implement `HistoricalSource` and depend on this crate.

## The `[H]` functor

`[H]` is a cross-cutting functor that lifts each base navigation primitive to a time-indexed variant:

- `[P^H]` — time-indexed disk (VSS, APFS snapshots, Time Machine, btrfs)
- `[M^H]` — time-indexed memory (hiberfil chain, VMware memory snapshots)
- `[L^H]` — time-indexed log (rotated logs, journald sealed epochs)
- `[Q^H]` — time-indexed live query (point-in-time osquery exports)
- `[C^H] ≅ [C]` — Git already encodes its own history, so `[H]` on `[C]` is the identity functor.

## What's in the crate

| Module | Provides |
|---|---|
| `identity` | `ArtifactRef` + `IdentityClaim` multi-facet identity and the `IdentityDiscipline` selector. |
| `clock` | `ClockProvenance` with four orthogonal axes — `source` / `trust_grade` / `tamper_resistance` / `ordering_only`. |
| `epoch` | `EpochTag`, `LsnKind` ordering keys (e.g. salt-qualified SQLite WAL frames). |
| `cohort` | `TemporalCohort<H>` / `TemporalState<H>`, `CohortTopology`, `MaterializationSafety`. |
| `source` | the `HistoricalSource` trait, `AcquisitionProtocol`, and the `StateMaterializer` trait boundary. |

## Design

- **Zero external dependencies** — a pure KNOWLEDGE leaf. Every `[H]` crate depends *down* onto it; it depends on no one.
- **Generic over a source-defined handle** (`H`) — `TemporalCohort<H>` orders an artifact's states by `wall_time` (else by ordering key) with no trait-object overhead.
- **Trust is multi-axis, not a flat level** — "local but signed" (iOS APFS) is structurally distinct from "external + attested" (Sigstore).
