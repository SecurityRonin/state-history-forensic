# 4. Multi-facet artifact identity; disagreement between facets is itself a finding

Date: 2026-07-24
Status: Accepted

## Context

"Is this the same artifact across two snapshots?" has no single answer. The same
path can hold different content (a file swapped in place); the same content can sit
at different paths (a copy); the same filesystem object can be renamed; an
application record (SQLite rowid, message GUID) can survive a file being rewritten.
A forensic tool must be able to ask each of these questions separately — and,
crucially, the *disagreement* between them is often the evidence (a path that stays
constant while its content hash changes at one epoch is a silent replacement).

## Decision

Identity is modeled as a set of coexisting facets rather than one key
(`src/identity.rs`):

- `IdentityClaim` (an open, `#[non_exhaustive]` enum) enumerates the facets:
  `CanonicalPath`, `InodeIdentity`, `NtfsFileRef`, `ApfsFileId`, `ContentHash`,
  `RecordIdentity`, `ApplicationGuid`, `SigningSubject`, and `PersistentAddress`
  (ADR 0006). `ArtifactRef` holds a `Vec<IdentityClaim>`.
- `IdentityDiscipline` selects *which* facet defines sameness at query time:
  `PathStable`, `ContentStable`, `ObjectStable`, `RecordStable`, `LogicalStable`.
  "Different disciplines for the same artifact can yield different (all valid)
  cohort groupings."
- `ArtifactRef::matches(other, discipline)` and `cohort_key(discipline)` group
  states under the chosen discipline; `IdentityDiscontinuity` (`src/cohort.rs`)
  records "the artifact's identity became inconsistent under a secondary discipline
  while remaining consistent under the primary" — i.e. disagreement surfaced as a
  first-class forensic finding, with the example of a `PathStable` cohort whose
  `ContentStable` sub-grouping splits.

`IdentityClaim` and `IdentityDiscipline` were made `#[non_exhaustive]` in commit
`e821e9a` ("the last exhaustive-match break of their kind"), so new facets are
additive.

## Consequences

- The analyst chooses the identity model per query (path- vs content- vs
  object-stable) instead of the type forcing one, and can pivot the same evidence
  through several groupings.
- Facet disagreement is a reportable observation, not a lost detail — the exact
  event (in-place swap, reinstall, copy) is inferable from *which* facet diverged
  at *which* epoch.
- `cohort_key` deliberately uses a non-cryptographic fold and documents that
  callers needing collision resistance layer their own hash on top — consistent
  with the zero-dependency leaf posture (ADR 0001).
