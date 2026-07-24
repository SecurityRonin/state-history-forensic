# 7. Reuse `forensicnomicon-core::FileId` verbatim (leaf-onto-leaf dependency)

Date: 2026-07-24
Status: Accepted

## Context

`PersistentAddress` (ADR 0006) needs a filesystem-object identifier whose second
field distinguishes a reallocated record from the original (NTFS sequence, ext
generation, APFS xid, FAT directory index). The fleet already defines exactly this
as `FileId` — an enum with `NtfsRef { entry, seq }`, `ExtInode { ino, gen }`,
`ApfsOid { oid, xid }`, `FatDirEntry { cluster, index }`, `IsoExtent { block }`, and
`Opaque(u64)`. The fleet rule is "prefer our own crates" and, more specifically here,
do not reinvent a type another leaf owns.

The subtlety is *dependency direction*. `FileId` originally lived where a naive
reuse would have made this KNOWLEDGE leaf depend on `forensic-vfs` — a
wrong-direction coupling (a KNOWLEDGE leaf must not depend on a higher contract
crate). That was resolved fleet-side by relocating `FileId` into
`forensicnomicon-core`, the zero-dep KNOWLEDGE leaf (forensicnomicon ADR 0009,
cited in this crate's `Cargo.toml`).

## Decision

Depend on `forensicnomicon-core` and embed `FileId` verbatim as
`PersistentAddress.file_id` (`Cargo.toml`, `src/identity.rs`). This is a
leaf-onto-leaf dependency with no wrong-direction coupling. The canonical encoder
(`encode_file_id`) and decoder (`ByteCursor::file_id`) enumerate every `FileId`
variant explicitly; the `#[non_exhaustive]` catch-all encodes a sentinel byte and
is annotated `// cov:unreachable` because all current `fn-core` variants are
covered.

The dependency is currently a `path` dep — the in-flight coordinated form until the
`fn-core` minor carrying `FileId` is published — and per the fleet
"prefer the published registry crate" rule it becomes a registry version pin once
published (`Cargo.toml` comment).

## Consequences

- One canonical filesystem-object identity across the fleet: readers that already
  emit `FileId` (NTFS/ext/APFS/FAT/ISO) feed `PersistentAddress` directly.
- A `FileId` variant added upstream is a non-breaking event here (the enum is
  `#[non_exhaustive]`); the encoder's catch-all keeps the match exhaustive, and the
  `cov:unreachable` marker documents that no test can currently reach it.
- The `path` → registry-pin migration is tracked debt: when `fn-core` publishes the
  minor carrying `FileId`, this crate must switch to
  `forensicnomicon-core = { version = "…", package = "…" }` and its dependents swept
  off the path dep.
