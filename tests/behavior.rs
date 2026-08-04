//! Behavioral tests for the `[H]` contract crate: cohort time-indexing, cohort
//! keying, identity matching under each discipline, and `DecodeError` reporting.
//! Pure construct-and-assert over the public API — no I/O.

use forensicnomicon_core::FileId;
use state_history_forensic::{
    clock::{ClockProvenance, ClockSource, TamperResistance, TrustGrade},
    cohort::{TemporalCohort, TemporalState, Timestamp},
    epoch::{CohortTopology, EpochTag, MaterializationSafety},
    identity::{
        Allocation, ArtifactRef, DecodeError, HashAlgo, IdentityClaim, IdentityDiscipline,
        PersistentAddress, StreamSel,
    },
    source::CohortQuery,
};
use std::path::PathBuf;

// ── helpers ─────────────────────────────────────────────────────────────────

fn clock() -> ClockProvenance {
    ClockProvenance {
        source: ClockSource::FileMetadata,
        trust_grade: TrustGrade::LocalSubsystem,
        tamper_resistance: TamperResistance::AdminWritable,
        ordering_only: false,
        skew_known: None,
        authenticated: None,
    }
}

/// A `TemporalState<u32>` tagged with epoch byte `tag` and an optional wall time.
fn state(tag: u8, wall_secs: Option<i64>) -> TemporalState<u32> {
    TemporalState {
        epoch: EpochTag([tag; 32]),
        ordering_key: None,
        wall_time: wall_secs.map(Timestamp::from_secs),
        clock: clock(),
        safety: MaterializationSafety::ReadOnlySafe,
        handle: u32::from(tag),
    }
}

fn cohort(states: Vec<TemporalState<u32>>) -> TemporalCohort<u32> {
    TemporalCohort {
        artifact: ArtifactRef { claims: vec![] },
        discipline: IdentityDiscipline::PathStable,
        topology: CohortTopology::DiscreteSet,
        states,
    }
}

fn one(claim: IdentityClaim) -> ArtifactRef {
    ArtifactRef {
        claims: vec![claim],
    }
}

// ── cohort / epoch / source ───────────────────────────────────────────────────

#[test]
fn timestamp_from_secs_zeroes_nanos() {
    let t = Timestamp::from_secs(1_700_000_000);
    assert_eq!(t.secs, 1_700_000_000);
    assert_eq!(t.nanos, 0);
}

#[test]
fn epoch_tag_from_bytes_and_zero() {
    let tag = EpochTag::from_bytes([0xAB; 32]);
    assert_eq!(tag.0, [0xAB; 32]);
    assert_ne!(tag, EpochTag::ZERO);
}

#[test]
fn cohort_query_all_selects_everything() {
    let q = CohortQuery::all();
    assert!(q.artifact.is_none());
    assert!(q.discipline.is_none());
}

#[test]
fn cohort_at_returns_latest_state_not_after_t() {
    let c = cohort(vec![
        state(1, Some(100)),
        state(2, Some(200)),
        state(3, Some(300)),
        state(9, None), // no wall time → never selected by `at`
    ]);
    // At t=250 the newest state at or before is the one at 200.
    let got = c
        .at(Timestamp::from_secs(250))
        .expect("a state at/before 250");
    assert_eq!(got.handle, 2);
    // Before the earliest wall time there is no answer.
    assert!(c.at(Timestamp::from_secs(50)).is_none());
}

#[test]
fn cohort_at_empty_when_no_wall_times() {
    let c = cohort(vec![state(9, None)]);
    assert!(c.at(Timestamp::from_secs(1_000)).is_none());
}

#[test]
fn cohort_nearest_picks_minimal_absolute_delta() {
    let c = cohort(vec![
        state(1, Some(100)),
        state(2, Some(200)),
        state(3, Some(300)),
        state(9, None),
    ]);
    // |300-260| = 40 beats |200-260| = 60.
    assert_eq!(c.nearest(Timestamp::from_secs(260)).unwrap().handle, 3);
    // Ties/earlier side: closest to 120 is 100.
    assert_eq!(c.nearest(Timestamp::from_secs(120)).unwrap().handle, 1);
}

#[test]
fn cohort_nearest_none_when_no_wall_times() {
    let c = cohort(vec![state(9, None)]);
    assert!(c.nearest(Timestamp::from_secs(0)).is_none());
}

#[test]
fn cohort_epochs_yields_states_in_order() {
    let c = cohort(vec![state(1, Some(100)), state(2, Some(200))]);
    let epochs: Vec<EpochTag> = c.epochs().collect();
    assert_eq!(epochs, vec![EpochTag([1; 32]), EpochTag([2; 32])]);
}

// ── identity matching per discipline ──────────────────────────────────────────

#[test]
fn path_stable_matches_equal_canonical_path() {
    let a = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
    });
    let same = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
    });
    let other = one(IdentityClaim::CanonicalPath {
        volume: "D:".into(),
        path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
    });
    assert!(a.matches(&same, IdentityDiscipline::PathStable));
    assert!(!a.matches(&other, IdentityDiscipline::PathStable));
    // A non-path claim under PathStable hits the catch-all `_ => false`.
    let hash = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Sha256,
        digest: vec![1; 32],
    });
    assert!(!a.matches(&hash, IdentityDiscipline::PathStable));
}

#[test]
fn content_stable_matches_equal_hash() {
    let a = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Sha256,
        digest: vec![0xAB; 32],
    });
    let same = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Sha256,
        digest: vec![0xAB; 32],
    });
    let diff = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Sha1,
        digest: vec![0xAB; 20],
    });
    assert!(a.matches(&same, IdentityDiscipline::ContentStable));
    assert!(!a.matches(&diff, IdentityDiscipline::ContentStable));
    // Non-hash claim under ContentStable → `_ => false`.
    let path = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("x"),
    });
    assert!(!a.matches(&path, IdentityDiscipline::ContentStable));
}

#[test]
fn object_stable_matches_inode_and_ntfs_ref() {
    let inode = one(IdentityClaim::InodeIdentity {
        volume: "uuid:abcd".into(),
        inode: 42,
        generation: Some(7),
    });
    let inode_same = one(IdentityClaim::InodeIdentity {
        volume: "uuid:abcd".into(),
        inode: 42,
        generation: Some(7),
    });
    assert!(inode.matches(&inode_same, IdentityDiscipline::ObjectStable));

    let ntfs = one(IdentityClaim::NtfsFileRef {
        volume: "vsn:1".into(),
        mft_record: 88,
        sequence: 3,
    });
    let ntfs_same = one(IdentityClaim::NtfsFileRef {
        volume: "vsn:1".into(),
        mft_record: 88,
        sequence: 3,
    });
    let ntfs_reused = one(IdentityClaim::NtfsFileRef {
        volume: "vsn:1".into(),
        mft_record: 88,
        sequence: 4, // reallocated slot
    });
    assert!(ntfs.matches(&ntfs_same, IdentityDiscipline::ObjectStable));
    assert!(!ntfs.matches(&ntfs_reused, IdentityDiscipline::ObjectStable));
    // Unrelated variants under ObjectStable → `_ => false`.
    assert!(!inode.matches(&ntfs, IdentityDiscipline::ObjectStable));
}

#[test]
fn record_stable_matches_equal_record_identity() {
    let a = one(IdentityClaim::RecordIdentity {
        schema: "sqlite:msgstore#messages".into(),
        primary_key: vec![1, 2, 3],
    });
    let same = one(IdentityClaim::RecordIdentity {
        schema: "sqlite:msgstore#messages".into(),
        primary_key: vec![1, 2, 3],
    });
    let diff = one(IdentityClaim::RecordIdentity {
        schema: "sqlite:msgstore#messages".into(),
        primary_key: vec![9],
    });
    assert!(a.matches(&same, IdentityDiscipline::RecordStable));
    assert!(!a.matches(&diff, IdentityDiscipline::RecordStable));
    // Non-record claim under RecordStable → `_ => false`.
    let path = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("x"),
    });
    assert!(!a.matches(&path, IdentityDiscipline::RecordStable));
}

#[test]
fn logical_stable_falls_back_to_path_or_record() {
    let path_a = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("app.db"),
    });
    let path_b = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("app.db"),
    });
    assert!(path_a.matches(&path_b, IdentityDiscipline::LogicalStable));

    let rec_a = one(IdentityClaim::RecordIdentity {
        schema: "s".into(),
        primary_key: vec![1],
    });
    let rec_b = one(IdentityClaim::RecordIdentity {
        schema: "s".into(),
        primary_key: vec![1],
    });
    assert!(rec_a.matches(&rec_b, IdentityDiscipline::LogicalStable));

    // Content hashes are neither path- nor record-stable → no logical match.
    let hash = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Blake3,
        digest: vec![0; 32],
    });
    assert!(!path_a.matches(&hash, IdentityDiscipline::LogicalStable));
}

// ── cohort_key (drives claim_matches_discipline + claim_fingerprint) ───────────

#[test]
fn cohort_key_is_deterministic_and_discipline_sensitive() {
    let ar = one(IdentityClaim::CanonicalPath {
        volume: "C:".into(),
        path: PathBuf::from("Windows/System32/ntoskrnl.exe"),
    });
    let k1 = ar.cohort_key(IdentityDiscipline::PathStable);
    let k2 = ar.cohort_key(IdentityDiscipline::PathStable);
    assert_eq!(k1, k2, "same artifact + discipline → same key");
    // A different discipline mixes a different leading byte.
    let k3 = ar.cohort_key(IdentityDiscipline::ContentStable);
    assert_ne!(k1, k3);
}

#[test]
fn cohort_key_fingerprints_each_matching_claim_variant() {
    // Each pairing exercises one claim_fingerprint arm through the public path.
    let cases = [
        (
            IdentityClaim::CanonicalPath {
                volume: "C:".into(),
                path: PathBuf::from("a/b"),
            },
            IdentityDiscipline::PathStable,
        ),
        (
            IdentityClaim::InodeIdentity {
                volume: "uuid:x".into(),
                inode: 5,
                generation: Some(1),
            },
            IdentityDiscipline::ObjectStable,
        ),
        (
            IdentityClaim::NtfsFileRef {
                volume: "vsn:x".into(),
                mft_record: 5,
                sequence: 1,
            },
            IdentityDiscipline::ObjectStable,
        ),
        (
            IdentityClaim::ContentHash {
                algo: HashAlgo::Sha256,
                digest: vec![3; 32],
            },
            IdentityDiscipline::ContentStable,
        ),
        (
            IdentityClaim::RecordIdentity {
                schema: "s".into(),
                primary_key: vec![7],
            },
            IdentityDiscipline::RecordStable,
        ),
        (
            IdentityClaim::PersistentAddress(PersistentAddress {
                volume: "vsn:1".into(),
                file_id: FileId::NtfsRef { entry: 1, seq: 2 },
                path: b"/a".to_vec(),
                allocation: Allocation::Allocated,
                stream: StreamSel::Default,
            }),
            IdentityDiscipline::PathStable,
        ),
    ];
    for (claim, discipline) in cases {
        // A matching claim mixes a nonzero fingerprint; the key is not the
        // all-zero-but-discipline-byte key an unmatched claim would leave.
        let key = one(claim).cohort_key(discipline);
        let empty = ArtifactRef { claims: vec![] }.cohort_key(discipline);
        assert_ne!(key, empty, "a matching claim must alter the key");
    }
}

#[test]
fn cohort_key_ignores_claims_not_matching_the_discipline() {
    // A ContentHash claim under PathStable does not match, so cohort_key leaves
    // only the discipline byte — equal to an empty artifact's key.
    let hash = one(IdentityClaim::ContentHash {
        algo: HashAlgo::Sha256,
        digest: vec![1; 32],
    });
    let empty = ArtifactRef { claims: vec![] };
    assert_eq!(
        hash.cohort_key(IdentityDiscipline::PathStable),
        empty.cohort_key(IdentityDiscipline::PathStable)
    );
}

// ── DecodeError reporting + decode discriminant guards ─────────────────────────

#[test]
fn decode_error_display_covers_every_variant() {
    let variants = [
        DecodeError::Truncated,
        DecodeError::UnsupportedVersion(9),
        DecodeError::BadTag {
            field: "allocation",
            tag: 42,
        },
        DecodeError::InvalidUtf8,
        DecodeError::TrailingBytes(3),
    ];
    for e in variants {
        let s = e.to_string();
        assert!(!s.is_empty());
        // std::error::Error is implemented (compiles as a trait object).
        let _: &dyn std::error::Error = &e;
    }
    assert!(DecodeError::UnsupportedVersion(9).to_string().contains('9'));
    assert!(DecodeError::TrailingBytes(3).to_string().contains('3'));
    assert!(DecodeError::BadTag {
        field: "stream",
        tag: 7
    }
    .to_string()
    .contains("stream"));
}

#[test]
fn decode_rejects_out_of_range_discriminants() {
    // Minimal buffers reaching each discriminant guard: version(1) + empty
    // volume(len 0) then the field under test.
    // file_id tag 6 is out of range (0..=5 defined).
    let bad_file_id = [1u8, 0, 0, 0, 0, 6];
    assert!(matches!(
        PersistentAddress::decode(&bad_file_id),
        Err(DecodeError::BadTag {
            field: "file_id",
            ..
        })
    ));

    // file_id = Opaque(0) [tag 5 + u64], empty path, then a bad allocation tag 3.
    let mut bad_alloc = vec![1u8, 0, 0, 0, 0, 5];
    bad_alloc.extend_from_slice(&0u64.to_le_bytes()); // Opaque value
    bad_alloc.extend_from_slice(&0u32.to_le_bytes()); // path len = 0
    bad_alloc.push(3); // allocation tag out of range (0..=2)
    assert!(matches!(
        PersistentAddress::decode(&bad_alloc),
        Err(DecodeError::BadTag {
            field: "allocation",
            ..
        })
    ));

    // Same prefix but a valid allocation and a bad stream tag 3.
    let mut bad_stream = vec![1u8, 0, 0, 0, 0, 5];
    bad_stream.extend_from_slice(&0u64.to_le_bytes());
    bad_stream.extend_from_slice(&0u32.to_le_bytes());
    bad_stream.push(0); // Allocation::Allocated
    bad_stream.push(3); // stream tag out of range (0..=2)
    assert!(matches!(
        PersistentAddress::decode(&bad_stream),
        Err(DecodeError::BadTag {
            field: "stream",
            ..
        })
    ));
}
