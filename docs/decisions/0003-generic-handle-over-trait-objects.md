# 3. Temporal states are generic over a source-defined handle `H`, not trait objects

Date: 2026-07-24
Status: Accepted

## Context

Each `[H]` source locates and materializes a specific epoch through a
medium-specific coordinate: a VSS shadow-mount `PathBuf`, a SQLite WAL frame index
(`u32`), a git commit OID (`[u8; 20]`), and so on (`src/cohort.rs`,
`src/source.rs`). The cohort/state vocabulary must carry that coordinate without
knowing its concrete type, yet ORCHESTRATION wants one uniform API over cohorts
from any source.

Two ways to erase the coordinate type: a boxed trait object
(`Box<dyn LocateHandle>`) per state, or a generic type parameter. A source such as
a git repository can enumerate millions of commits, so per-state allocation and
dynamic dispatch are a real cost.

## Decision

`TemporalState<H>` and `TemporalCohort<H>` are generic over a source-defined handle
type `H` (`src/cohort.rs`); `HistoricalSource` exposes it as an associated
`type Handle` and `enumerate` returns `impl Iterator<Item = TemporalCohort<Self::Handle>>`
(`src/source.rs`). The doc comment states the rationale verbatim: "Using a generic
avoids trait-object overhead while preserving a uniform API for ORCHESTRATION."
`enumerate` returns an iterator rather than a `Vec` "to support streaming
enumeration of large sources (e.g. a git repo with millions of commits)."

## Consequences

- No per-state boxing or virtual dispatch on the handle; the concrete coordinate is
  monomorphized into each source's code path.
- ORCHESTRATION code is generic over `H` (or fixes it per source) and gets the same
  `at`/`nearest`/`epochs` cohort API for every medium.
- The trade-off is monomorphization: a consumer that must hold cohorts from
  *heterogeneous* sources in one collection has to erase `H` itself at that boundary
  (e.g. box at the ORCHESTRATION seam), which is the correct place for that cost —
  not inside every state of every cohort.
