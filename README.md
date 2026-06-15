# state-history-forensic

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/state-history-forensic/)
[![Sponsor](https://img.shields.io/badge/Sponsor-h4x0r-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/h4x0r)

**The zero-dependency `[H]` state-history vocabulary for the SecurityRonin forensic fleet — the KNOWLEDGE-tier types and traits that lift every navigation primitive to a time-indexed variant.**

`state-history-forensic` is a pure type/trait leaf: no parsing, no I/O, no dependencies. Concrete `[H]` crates (`vss-history`, `wal-history`, `git-history`, …) implement `HistoricalSource` and depend *down* onto it.

```toml
[dependencies]
state-history-forensic = "0.1"
```

## The `[H]` functor

`[H]` lifts each base navigation primitive to a time-indexed variant:

| Lifted primitive | Time-indexed source |
|---|---|
| `[P^H]` disk | VSS, APFS snapshots, Time Machine, btrfs |
| `[M^H]` memory | hiberfil chain, VMware memory snapshots |
| `[L^H]` log | rotated logs, journald sealed epochs |
| `[Q^H]` query | point-in-time osquery exports |
| `[C^H] ≅ [C]` | Git already encodes history — `[H]` on `[C]` is the identity |

## What's in the crate

| Module | Provides |
|---|---|
| `identity` | `ArtifactRef` + `IdentityClaim` multi-facet identity, `IdentityDiscipline` selector |
| `clock` | `ClockProvenance` — four orthogonal axes (source / trust_grade / tamper_resistance / ordering_only) |
| `epoch` | `EpochTag`, `LsnKind` ordering keys (e.g. salt-qualified SQLite WAL frames) |
| `cohort` | `TemporalCohort<H>` / `TemporalState<H>`, `CohortTopology`, `MaterializationSafety` |
| `source` | the `HistoricalSource` trait, `AcquisitionProtocol`, `StateMaterializer` boundary |

## Design

- **Zero external dependencies** — a pure KNOWLEDGE leaf. Every `[H]` crate depends down onto it; it depends on no one.
- **Generic over a source-defined handle `H`** — `TemporalCohort<H>` orders states by `wall_time` (else ordering key), with no trait-object overhead.
- **Trust is multi-axis, not a flat level** — "local but signed" (iOS APFS) is structurally distinct from "external + attested" (Sigstore).

---

[Privacy Policy](https://securityronin.github.io/state-history-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/state-history-forensic/terms/) · © 2026 Security Ronin Ltd
