# 2. Clock provenance is four orthogonal axes, not one flat trust level

Date: 2026-07-24
Status: Accepted

## Context

A timestamp attached to a temporal state carries several *independent* properties
that a single ordinal "trust level" collapses and loses. Two examples the code
calls out directly (`src/clock.rs`):

- An iOS APFS snapshot timestamp is produced by a **local** subsystem
  (`TrustGrade::LocalSubsystem`-adjacent, actually graded `LocallyAttested`) yet is
  **Secure-Enclave-signed** (`TamperResistance::SignedImmutable`).
- A Windows VSS timestamp uses the *same* filesystem-metadata mechanism but is
  freely **admin-writable** (`TamperResistance::AdminWritable`).

Same format, different trust; same trust source, different tamper resistance. A
flat enum cannot express that a value is "locally produced but cryptographically
sealed" versus "locally produced and trivially forgeable." The GREEN foundational
commit (`a975fc6`) records this pivot explicitly: the four-axis `ClockProvenance`
"replaces collapsed flat trust enum."

## Decision

`ClockProvenance` (`src/clock.rs`) carries four orthogonal axes plus two optional
qualifiers:

1. `source: ClockSource` — what mechanism produced the value (RTC, file metadata,
   log record, network protocol, application-embedded, transparency log, TPM event
   log, sequence/LSN-only, analyst reconstruction, unknown).
2. `trust_grade: TrustGrade` — how trustworthy the *absolute* value is, an 8-level
   ordinal from `ExternallyAttested` down through `LocalSubsystem`,
   `LocalApplication`, `OrderingOnly`, to `Reconstructed`/`Unknown`.
3. `tamper_resistance: TamperResistance` — how hard retroactive forgery is, 6
   levels from `AppendOnlyAttested` down to `Trivial`.
4. `ordering_only: bool` — whether the epoch has no absolute wall time, only a
   relative ordering key; when set, the paired `TemporalState.wall_time` is `None`.

Plus `skew_known: Option<Duration>` and `authenticated: Option<AuthMechanism>`
(RFC3161, Sigstore, TPM PCR, APFS Secure Enclave, journald FSS, other).

`TrustGrade` and `TamperResistance` derive `PartialOrd`/`Ord` so they can be
compared, but they are separate fields — neither is derivable from the other.

## Consequences

- A downstream analyzer can answer "is this time value trustworthy?" and "could it
  have been back-dated?" independently, and can surface "local but signed" versus
  "external but unattested" as distinct forensic postures.
- The axes are coarse, deliberate enumerations rather than free-form scores, so the
  vocabulary stays comparable across every `[H]` crate.
- `ClockSource`, `AuthMechanism` carry `Unknown`/`Other(String)` escape hatches, so
  a source with an unanticipated clock mechanism degrades to a named value rather
  than forcing an enum extension.
