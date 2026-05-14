/// `[H]` state-history layer — zero-dep KNOWLEDGE-tier types and traits.
///
/// `[H]` is a cross-cutting functor that lifts each base navigation primitive to a
/// time-indexed variant:
///
/// - `[P^H]` — time-indexed disk (VSS, APFS snapshots, Time Machine, btrfs)
/// - `[M^H]` — time-indexed memory (hiberfil chain, VMware memory snapshots)
/// - `[L^H]` — time-indexed log (rotated logs, journald sealed epochs)
/// - `[Q^H]` — time-indexed live query (point-in-time osquery exports)
/// - `[C^H] ≅ [C]` — Git already encodes its own history; `[H]` on `[C]` is the identity functor.
///
/// This crate contains only type definitions and trait signatures. No parsing algorithms,
/// no file I/O, no binary deserialization. Concrete `[H]` crates (vss-history,
/// wal-history, git-history, …) implement `HistoricalSource` and depend on this crate.

pub mod identity;
pub mod clock;
pub mod epoch;
pub mod cohort;
pub mod source;
