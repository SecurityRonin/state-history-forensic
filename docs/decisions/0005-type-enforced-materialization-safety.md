# 5. Materialization safety is type-enforced (Evidence vs WorkingCopy)

Date: 2026-07-24
Status: Accepted

## Context

Reading a temporal state out of its source is not uniformly safe. Some reads are
inert (a VSS block range, a Time Machine backup directory, a read-only git object
store). Some require a forensic-aware reader or they destroy the state — opening a
pre-replay SQLite WAL with `libsqlite3` auto-checkpoints it; interpreting an ESE
journal without soft-recovery invites `esentutl /r` to replay it. Some
materializations *modify the source on disk* and are irrecoverable without a copy
(`esentutl /r`, `fsck`, a default `libsqlite3` open that checkpoints the WAL). And
some states are ephemeral (an LVM snapshot near overflow, a ring buffer about to
wrap) or auto-pruned by a background process (`git gc`, log rotation, WAL
auto-checkpoint).

A comment in the docs is not enforcement: "always work on a copy" is exactly the
instruction a competent examiner skips under pressure. The fleet discipline is to
make the wrong call structurally hard, not merely documented (Secure by Design).

## Decision

Safety is a typed property, and the danger is separated at the type level
(`src/epoch.rs`, `src/source.rs`):

- `MaterializationSafety` enumerates the five classes: `ReadOnlySafe`,
  `ReadOnlyRequiresCareful`, `Destructive`, `EphemeralOnce`, and
  `AutoPruned { trigger: PruneTrigger }` — each carrying the rule and concrete
  examples in its doc.
- `StateMaterializer` provides `materialize(&self, epoch, ev: &Evidence)` for the
  read-only classes and `materialize_via_working_copy(&self, epoch, wc: &mut WorkingCopy)`
  for `Destructive` sources. `Evidence` wraps a write-blocked path; `WorkingCopy`
  wraps a mutable scratch copy. Because the destructive method takes `&mut WorkingCopy`
  and never `&Evidence`, "the compiler rejects accidental use of live evidence
  here."
- `AcquisitionProtocol` makes the acquisition contract explicit and inspectable:
  `preconditions`, `forbidden_operations`, `required_companion_artifacts`
  (e.g. `main.db-wal` + `main.db-shm`, all `.jrs` + `.chk`), and
  `destructive_if_skipped`.

## Consequences

- A destructive materializer *cannot* be handed live evidence by mistake; the
  distinction lives in the signature, not in a runbook.
- Companion-artifact and forbidden-operation requirements travel with the source
  type, so ORCHESTRATION can enforce and display them uniformly.
- The classes are descriptive enums the leaf defines; the actual careful/raw
  readers live in the concrete `[H]` crates and in ORCHESTRATION, keeping this crate
  I/O-free (ADR 0001).
