//! `[P]` persistent-storage evidential address — Phase-1 frozen scope.
//!
//! Design: `issen/docs/plans/universal-address-design.md`. The address is the
//! subject-world identity of a filesystem object: `{volume, file_id, path,
//! allocation, stream}`. Its derived `Eq`/`Hash` IS the strict identity; the
//! versioned length-prefixed binary [`PersistentAddress::canonical_bytes`] is the
//! correlation/DB key. Host and epoch are deliberately excluded (design §3.2).

use forensicnomicon_core::FileId;
use state_history_forensic::identity::{
    Allocation, ArtifactRef, DecodeError, IdentityClaim, IdentityDiscipline, PersistentAddress,
    StreamSel,
};

fn sample() -> PersistentAddress {
    PersistentAddress {
        volume: "vsn:1a2b3c4d5e6f7a8b".to_string(),
        file_id: FileId::NtfsRef {
            entry: 12345,
            seq: 3,
        },
        path: b"/Users/beth/notes.txt".to_vec(),
        allocation: Allocation::Allocated,
        stream: StreamSel::Default,
    }
}

fn aref(addr: PersistentAddress) -> ArtifactRef {
    ArtifactRef {
        claims: vec![IdentityClaim::PersistentAddress(addr)],
    }
}

#[test]
fn round_trips_through_canonical_bytes() {
    let addr = sample();
    let decoded = PersistentAddress::decode(&addr.canonical_bytes()).expect("decode own bytes");
    assert_eq!(addr, decoded);
}

#[test]
fn round_trips_every_file_id_variant_stream_and_allocation() {
    let variants = [
        FileId::NtfsRef { entry: 1, seq: 2 },
        FileId::ExtInode { ino: 3, r#gen: 4 },
        FileId::ApfsOid { oid: 5, xid: 6 },
        FileId::FatDirEntry {
            cluster: 7,
            index: 8,
        },
        FileId::IsoExtent { block: 9 },
        FileId::Opaque(10),
    ];
    let streams = [
        StreamSel::Default,
        StreamSel::Named(b"$DATA:zone.identifier".to_vec()),
        StreamSel::Unknown,
    ];
    let allocs = [
        Allocation::Allocated,
        Allocation::Deleted,
        Allocation::Orphan,
    ];
    for fid in variants {
        for stream in &streams {
            for alloc in allocs {
                let addr = PersistentAddress {
                    volume: "gpt:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
                    file_id: fid,
                    path: b"/a/b".to_vec(),
                    allocation: alloc,
                    stream: stream.clone(),
                };
                let back = PersistentAddress::decode(&addr.canonical_bytes()).expect("round-trip");
                assert_eq!(addr, back);
            }
        }
    }
}

#[test]
fn canonical_bytes_is_injective_per_field() {
    // Equal addresses -> equal bytes.
    assert_eq!(sample().canonical_bytes(), sample().canonical_bytes());

    // Changing any single field changes both the value and the key.
    let base = sample();
    let mut volume = base.clone();
    volume.volume = "vsn:ffffffffffffffff".into();
    let mut path = base.clone();
    path.path = b"/Users/beth/other.txt".to_vec();
    let mut allocation = base.clone();
    allocation.allocation = Allocation::Deleted;
    let mut stream = base.clone();
    stream.stream = StreamSel::Unknown;
    let mut file_id = base.clone();
    file_id.file_id = FileId::NtfsRef {
        entry: 12345,
        seq: 4,
    };
    for other in [&volume, &path, &allocation, &stream, &file_id] {
        assert_ne!(base, *other);
        assert_ne!(base.canonical_bytes(), other.canonical_bytes());
    }
}

#[test]
fn stream_unknown_is_a_distinct_concrete_value() {
    // `Unknown` never means "matches anything"; it is not `Default`.
    let mut a = sample();
    a.stream = StreamSel::Default;
    let mut b = sample();
    b.stream = StreamSel::Unknown;
    assert_ne!(a, b);
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
}

#[test]
fn slot_reuse_discriminator_distinguishes_reallocated_record() {
    // Same MFT entry, bumped sequence = a reallocated slot; it must never collide
    // with the original object, as a value or as a canonical key.
    let original = PersistentAddress {
        file_id: FileId::NtfsRef { entry: 88, seq: 1 },
        ..sample()
    };
    let reused = PersistentAddress {
        file_id: FileId::NtfsRef { entry: 88, seq: 2 },
        ..sample()
    };
    assert_ne!(original, reused);
    assert_ne!(original.canonical_bytes(), reused.canonical_bytes());
}

#[test]
fn decode_never_panics_on_malformed_input() {
    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0x01],                         // version only
        vec![0xFF, 0xFF, 0xFF],             // bad version
        vec![0x01, 0xFF, 0xFF, 0xFF, 0xFF], // version + absurd volume length
        (0u8..=255).collect(),              // arbitrary noise
        {
            let mut v = sample().canonical_bytes();
            v.truncate(v.len() - 1); // truncated final field
            v
        },
    ];
    for c in corpus {
        // Contract: returns a Result, never panics.
        let _: Result<PersistentAddress, DecodeError> = PersistentAddress::decode(&c);
    }

    // Specific typed errors.
    assert!(PersistentAddress::decode(&[]).is_err());
    assert!(matches!(
        PersistentAddress::decode(&[0xFF]),
        Err(DecodeError::UnsupportedVersion(0xFF))
    ));
    let mut trailing = sample().canonical_bytes();
    trailing.push(0x99);
    assert!(matches!(
        PersistentAddress::decode(&trailing),
        Err(DecodeError::TrailingBytes(_))
    ));
}

#[test]
fn address_carries_no_host_or_epoch_field() {
    // Structural canary (design §3.2): the address is exactly these five fields.
    // Re-introducing an excluded `host`/`epoch` field would force it to be named
    // here and break this exhaustive destructure at compile time.
    let PersistentAddress {
        volume,
        file_id,
        path,
        allocation,
        stream,
    } = sample();
    let _ = (volume, file_id, path, allocation, stream);
}

#[test]
fn participates_in_path_stable_and_object_stable() {
    let a = aref(sample());

    // PathStable: equal volume + path + stream, even if the object slot differs.
    let path_twin = PersistentAddress {
        file_id: FileId::NtfsRef { entry: 999, seq: 9 },
        ..sample()
    };
    assert!(a.matches(&aref(path_twin), IdentityDiscipline::PathStable));

    // ObjectStable: equal volume + file_id, even if the path was renamed.
    let renamed = PersistentAddress {
        path: b"/Users/beth/renamed.txt".to_vec(),
        ..sample()
    };
    assert!(a.matches(&aref(renamed), IdentityDiscipline::ObjectStable));

    // A genuinely different object does not match under either.
    let other = PersistentAddress {
        volume: "vsn:0000000000000000".into(),
        file_id: FileId::Opaque(1),
        path: b"/x".to_vec(),
        ..sample()
    };
    assert!(!a.matches(&aref(other.clone()), IdentityDiscipline::PathStable));
    assert!(!a.matches(&aref(other), IdentityDiscipline::ObjectStable));
}
