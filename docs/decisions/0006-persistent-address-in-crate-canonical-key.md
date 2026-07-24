# 6. `[P]` PersistentAddress: an in-crate, versioned, panic-free canonical binary key

Date: 2026-07-24
Status: Accepted

## Context

Correlating `[P]` persistent-storage artifacts across tools, snapshots, and a
database requires a *stable* subject-world identity for one filesystem object and a
deterministic key derived from it. Phase-1 frozen scope
(`issen/docs/plans/universal-address-design.md`, referenced by commits `77b38d0`
RED and `e821e9a` GREEN) fixed this address and its serialization.

Two design questions had to be settled:

1. **What is in the identity, and what is deliberately excluded.** A host
   identifier over-merges cloned VMs and under-merges a volume physically moved
   between machines; an epoch is temporal state, which is the cohort machinery's
   concern, not identity's. A drive letter or volume label is unstable.
2. **Who owns the key's byte layout.** If the correlation/DB key rode an external
   serialization codec (serde + a format crate), key stability would depend on that
   codec's field-ordering and version rules — a silent break surface — and would
   pull a dependency into a zero-dep leaf (ADR 0001).

## Decision

`PersistentAddress { volume, file_id, path, allocation, stream }` (`src/identity.rs`)
is the subject-world identity of one filesystem object, wired into `IdentityClaim`
as `PersistentAddress(_)` and participating in the `PathStable` and `ObjectStable`
disciplines (design §3.3).

- **Derived structural `Eq`/`Hash` over every field IS the strict identity** — a
  genuine equivalence relation, safe as a map/DB key.
- **`canonical_bytes()` is an in-crate, versioned, length-prefixed binary
  serialization** — a leading `CANONICAL_VERSION` byte, then each field in
  declaration order (`u32`-LE length prefixes for byte fields, a 1-byte discriminant
  plus fixed-width LE fields for the embedded `FileId`, 1-byte tags for the
  `Allocation`/`StreamSel` enums). It is injective, so the key equals strict
  identity, and it is computed in-crate so "key stability never depends on an
  external codec's ordering rules."
- **`volume` is a scheme-prefixed discriminator** (`gpt:<guid>`, `uuid:<hex>`,
  `vsn:<hex16>`, `mbr:<sig>.<lba>`) — never a drive letter or label — and the
  address carries **NO host and NO epoch** (design §3.2), documented on the type.
- **`decode()` is panic-free.** It reads through a bounds-checked `ByteCursor`
  (`checked_add`, `slice::get`, no indexing) and returns a typed `DecodeError`
  (`Truncated`, `UnsupportedVersion`, `BadTag`, `InvalidUtf8`, `TrailingBytes`) for
  any truncated, over-long, bad-version, bad-tag, non-UTF-8, or trailing-junk
  buffer. `decode(canonical_bytes(a)) == a` for every `a`. This is the fleet
  Paranoid-Gatekeeper posture applied to the one place the crate parses bytes; the
  `tests/persistent_address.rs` suite covers round-trip, per-field injectivity,
  decode-never-panics-on-garbage, the `FileId` slot-reuse discriminator, and a
  host/epoch-exclusion structural canary.
- `StreamSel` is deliberately tri-state (`Default`/`Named`/`Unknown`) — `Unknown`
  ("presence not determined by the producer") is a distinct concrete value, not
  "matches anything" and not `Default`.

## Consequences

- The same object gets the same key from any tool, any snapshot, on any host, with
  no shared codec dependency and no runtime serialization framework.
- Versioning the leading byte means a future layout change is a rejected
  `UnsupportedVersion`, not a silent mis-parse; the matching `decode` arm must be
  added alongside any bump.
- Excluding host and epoch keeps identity a pure equivalence relation; cross-host
  and temporal reasoning live in the cohort layer, where they belong.
- The panic-free posture here is *by construction* in the decode path (verified by
  test); the crate does not currently declare the `unwrap_used`/`expect_used` deny
  lints or a `forbid(unsafe)` attribute (no `deny.toml`/`clippy.toml`/`[lints]`
  present as of this writing) — see ADR 0008's note on residual lint-posture debt.
