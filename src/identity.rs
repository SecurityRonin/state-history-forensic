use std::path::PathBuf;

use forensicnomicon_core::FileId;

/// Opaque volume identifier (e.g. drive letter "C:", APFS UUID, ext4 UUID string).
pub type VolumeId = String;

/// Schema reference string (e.g. "sqlite:msgstore#messages").
pub type SchemaRef = String;

/// Application identifier string (e.g. "com.whatsapp", "chrome").
pub type AppId = String;

/// Digest algorithm used in a `IdentityClaim::ContentHash`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Blake3,
    /// Any other algorithm, identified by name.
    Other(String),
}

/// One facet of artifact identity. Multiple claims can coexist in an `ArtifactRef`.
///
/// Identity disagreement between facets is itself a forensic finding. For example,
/// a `PathStable` cohort whose `ContentStable` subcohorts split indicates the file at
/// that path was swapped while preserving its name.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityClaim {
    /// Filesystem canonical path.
    CanonicalPath { volume: VolumeId, path: PathBuf },
    /// POSIX inode number + optional generation counter.
    InodeIdentity {
        volume: VolumeId,
        inode: u64,
        generation: Option<u32>,
    },
    /// Windows NTFS MFT record + sequence number.
    NtfsFileRef {
        volume: VolumeId,
        mft_record: u64,
        sequence: u16,
    },
    /// APFS file identifier (volume UUID as 16 bytes + file_id).
    ApfsFileId { volume_uuid: [u8; 16], file_id: u64 },
    /// Cryptographic content hash. Stable across copies; equates duplicates.
    ContentHash { algo: HashAlgo, digest: Vec<u8> },
    /// Application-level record identity (e.g. SQLite rowid, email Message-ID).
    RecordIdentity {
        schema: SchemaRef,
        primary_key: Vec<u8>,
    },
    /// Application GUID (e.g. WhatsApp message GUID).
    ApplicationGuid { app: AppId, guid: [u8; 16] },
    /// Code-signing subject (issuer DN + subject DN, e.g. from Authenticode).
    SigningSubject { issuer: String, subject: String },
    /// `[P]` persistent-storage evidential address — the subject-world identity of
    /// a filesystem object. See [`PersistentAddress`]. Derived `Eq`/`Hash` is the
    /// strict identity; [`PersistentAddress::canonical_bytes`] is the correlation
    /// key. Carries NO host and NO epoch (design §3.2).
    PersistentAddress(PersistentAddress),
}

/// `[P]` persistent-storage evidential address — the subject-world identity of one
/// filesystem object.
///
/// Derived structural `Eq`/`Hash` over every field IS the strict identity (a
/// genuine equivalence relation, safe as a map/DB key). [`canonical_bytes`] is the
/// deterministic, versioned, length-prefixed binary serialization used as the
/// correlation/DB key — injective, so the key equals strict identity, and computed
/// in-crate so key stability never depends on an external codec's ordering rules.
///
/// Deliberately carries NO label, NO host and NO epoch (design §3.2): labels are
/// display-only; a host over-merges cloned VMs and under-merges volumes moved
/// between machines; temporal state is the cohort machinery's concern. The volume
/// discriminator travels with the medium and is the correct outermost `[P]`
/// identity.
///
/// [`canonical_bytes`]: PersistentAddress::canonical_bytes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PersistentAddress {
    /// Stable, scheme-prefixed volume discriminator (`gpt:<guid>`, `uuid:<hex>`,
    /// `vsn:<hex16>`, `mbr:<sig>.<lba>`) — never a drive letter or volume label.
    pub volume: VolumeId,
    /// The fleet's [`FileId`], reused verbatim. Its second field
    /// (`seq`/`gen`/`xid`/`index`) is the slot-reuse discriminator distinguishing a
    /// reallocated record from the original.
    pub file_id: FileId,
    /// Byte-verbatim path as recovered: `/`-separated, raw bytes, no case folding,
    /// no Unicode normalization. Empty for an orphan with no recoverable name.
    pub path: Vec<u8>,
    /// Allocation state of the object.
    pub allocation: Allocation,
    /// Which data stream this address names.
    pub stream: StreamSel,
}

/// Allocation state of a [`PersistentAddress`] object.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Allocation {
    /// A live, allocated object.
    Allocated,
    /// A deleted object whose metadata is still resolvable.
    Deleted,
    /// A recovered object with no parent/name.
    Orphan,
}

/// Tri-state stream selector. `Unknown` (stream presence undetermined, e.g. a
/// producer that never inspected ADS) is a distinct concrete value — it is not
/// "matches anything", and it is not `Default`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StreamSel {
    /// The default/unnamed data stream (`$DATA`, the file's primary content).
    Default,
    /// A named stream: an NTFS ADS, an HFS+ resource fork, or an xattr.
    Named(Vec<u8>),
    /// Stream presence was not determined by the producer.
    Unknown,
}

/// Leading byte of a [`PersistentAddress::canonical_bytes`] buffer. Bump only with
/// a matching [`PersistentAddress::decode`] arm; versioning keeps a future layout
/// from silently mis-parsing.
const CANONICAL_VERSION: u8 = 1;

impl PersistentAddress {
    /// Deterministic, versioned, length-prefixed binary serialization — the
    /// correlation/DB key.
    ///
    /// Layout: `[version]` then, in declaration order, `volume` (u32-LE length +
    /// bytes), `file_id` (1 discriminant byte + fixed-width LE fields), `path`
    /// (u32-LE length + bytes), `allocation` (1 byte), `stream` (1 discriminant
    /// byte + a length-prefixed name for `Named`). Injective:
    /// `canonical_bytes(a) == canonical_bytes(b)` iff `a == b`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(CANONICAL_VERSION);
        write_len_prefixed(&mut out, self.volume.as_bytes());
        encode_file_id(&mut out, self.file_id);
        write_len_prefixed(&mut out, &self.path);
        out.push(match self.allocation {
            Allocation::Allocated => 0,
            Allocation::Deleted => 1,
            Allocation::Orphan => 2,
        });
        match &self.stream {
            StreamSel::Default => out.push(0),
            StreamSel::Named(name) => {
                out.push(1);
                write_len_prefixed(&mut out, name);
            }
            StreamSel::Unknown => out.push(2),
        }
        out
    }

    /// Parse a [`canonical_bytes`] buffer back into an address.
    ///
    /// Never panics on malformed input: a truncated, over-long, bad-version,
    /// bad-tag, non-UTF-8, or trailing-junk buffer returns a typed
    /// [`DecodeError`]. `decode(canonical_bytes(a)) == a` for every `a`.
    ///
    /// [`canonical_bytes`]: PersistentAddress::canonical_bytes
    ///
    /// # Errors
    /// Returns [`DecodeError`] for any input that is not a well-formed encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut cur = ByteCursor::new(bytes);
        let version = cur.u8()?;
        if version != CANONICAL_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let volume = cur.string()?;
        let file_id = cur.file_id()?;
        let path = cur.length_prefixed()?;
        let allocation = match cur.u8()? {
            0 => Allocation::Allocated,
            1 => Allocation::Deleted,
            2 => Allocation::Orphan,
            other => {
                return Err(DecodeError::BadTag {
                    field: "allocation",
                    tag: u32::from(other),
                });
            }
        };
        let stream = match cur.u8()? {
            0 => StreamSel::Default,
            1 => StreamSel::Named(cur.length_prefixed()?),
            2 => StreamSel::Unknown,
            other => {
                return Err(DecodeError::BadTag {
                    field: "stream",
                    tag: u32::from(other),
                });
            }
        };
        if !cur.is_empty() {
            return Err(DecodeError::TrailingBytes(cur.remaining()));
        }
        Ok(Self {
            volume,
            file_id,
            path,
            allocation,
            stream,
        })
    }
}

/// Failure decoding a [`PersistentAddress::canonical_bytes`] buffer.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ended before a field was fully read.
    Truncated,
    /// The leading version byte is not a supported encoding version.
    UnsupportedVersion(u8),
    /// An enum discriminant byte was outside the known range.
    BadTag {
        /// Which field's discriminant was out of range.
        field: &'static str,
        /// The offending byte value.
        tag: u32,
    },
    /// A length-prefixed string field was not valid UTF-8.
    InvalidUtf8,
    /// Bytes remained after a complete address was decoded.
    TrailingBytes(usize),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "buffer ended before a field was fully read"),
            DecodeError::UnsupportedVersion(v) => {
                write!(f, "unsupported canonical-encoding version {v}")
            }
            DecodeError::BadTag { field, tag } => {
                write!(f, "invalid discriminant {tag} for field `{field}`")
            }
            DecodeError::InvalidUtf8 => write!(f, "length-prefixed string was not valid UTF-8"),
            DecodeError::TrailingBytes(n) => {
                write!(f, "{n} trailing byte(s) after a complete address")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Append a `u32`-LE length prefix followed by `data`. A field longer than
/// `u32::MAX` bytes is not representable on any real filesystem path/volume/stream.
fn write_len_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(data);
}

/// Encode a [`FileId`] as a 1-byte discriminant plus its fixed-width LE fields.
fn encode_file_id(out: &mut Vec<u8>, id: FileId) {
    match id {
        FileId::NtfsRef { entry, seq } => {
            out.push(0);
            out.extend_from_slice(&entry.to_le_bytes());
            out.extend_from_slice(&seq.to_le_bytes());
        }
        FileId::ExtInode { ino, r#gen } => {
            out.push(1);
            out.extend_from_slice(&ino.to_le_bytes());
            out.extend_from_slice(&r#gen.to_le_bytes());
        }
        FileId::ApfsOid { oid, xid } => {
            out.push(2);
            out.extend_from_slice(&oid.to_le_bytes());
            out.extend_from_slice(&xid.to_le_bytes());
        }
        FileId::FatDirEntry { cluster, index } => {
            out.push(3);
            out.extend_from_slice(&cluster.to_le_bytes());
            out.extend_from_slice(&index.to_le_bytes());
        }
        FileId::IsoExtent { block } => {
            out.push(4);
            out.extend_from_slice(&block.to_le_bytes());
        }
        FileId::Opaque(v) => {
            out.push(5);
            out.extend_from_slice(&v.to_le_bytes());
        }
        // FileId is #[non_exhaustive] (owned by forensicnomicon-core); a variant
        // added upstream is unknown to this encoder. Unreachable against the
        // current fn-core, but the exhaustiveness check requires this arm.
        _ => out.push(u8::MAX), // cov:unreachable: all fn-core FileId variants covered
    }
}

/// A panic-free forward cursor: every read is bounds-checked and returns a
/// [`DecodeError`] rather than indexing out of range.
struct ByteCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        self.take(1)?.first().copied().ok_or(DecodeError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(b);
        Ok(u16::from_le_bytes(a))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(b);
        Ok(u32::from_le_bytes(a))
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn length_prefixed(&mut self) -> Result<Vec<u8>, DecodeError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        String::from_utf8(self.length_prefixed()?).map_err(|_| DecodeError::InvalidUtf8)
    }

    fn file_id(&mut self) -> Result<FileId, DecodeError> {
        let tag = self.u8()?;
        Ok(match tag {
            0 => FileId::NtfsRef {
                entry: self.u64()?,
                seq: self.u16()?,
            },
            1 => FileId::ExtInode {
                ino: self.u64()?,
                r#gen: self.u32()?,
            },
            2 => FileId::ApfsOid {
                oid: self.u64()?,
                xid: self.u64()?,
            },
            3 => FileId::FatDirEntry {
                cluster: self.u32()?,
                index: self.u16()?,
            },
            4 => FileId::IsoExtent { block: self.u32()? },
            5 => FileId::Opaque(self.u64()?),
            other => {
                return Err(DecodeError::BadTag {
                    field: "file_id",
                    tag: u32::from(other),
                });
            }
        })
    }
}

/// How to match artifact identity across temporal states when building a cohort.
///
/// Callers select a discipline at query time. Different disciplines for the same
/// artifact can yield different (all valid) cohort groupings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IdentityDiscipline {
    /// Same canonical path across snapshots. Grouping: by `CanonicalPath` claim.
    PathStable,
    /// Same content hash. Groups copies/duplicates together.
    ContentStable,
    /// Same filesystem object (inode+generation, MFT record+sequence). Detects swaps.
    ObjectStable,
    /// Same application-level record (rowid, message_id). Detects app reinstalls.
    RecordStable,
    /// Same logical artifact across reinstalls (rarely provable without external evidence).
    LogicalStable,
}

/// Opaque key used to group temporal states into a cohort under a given `IdentityDiscipline`.
///
/// Computed from the selected discipline + the relevant claim fields. Two `ArtifactRef`
/// values that produce the same `CohortKey` for a given discipline belong to the same cohort.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CohortKey([u8; 32]);

impl CohortKey {
    /// Construct from a pre-computed 32-byte key (e.g. SHA-256 of the identity claims).
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Set of identity claims describing a single artifact across all its temporal states.
///
/// Multiple claims can coexist; each facet can independently agree or disagree across
/// snapshot boundaries. Disagreement between facets is surfaced as an
/// `IdentityDiscontinuity` forensic finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub claims: Vec<IdentityClaim>,
}

impl ArtifactRef {
    /// Check whether `other` refers to the same artifact under `discipline`.
    pub fn matches(&self, other: &Self, discipline: IdentityDiscipline) -> bool {
        for a in &self.claims {
            for b in &other.claims {
                if claims_match_under(a, b, discipline) {
                    return true;
                }
            }
        }
        false
    }

    /// Derive a cohort grouping key for this artifact under `discipline`.
    ///
    /// Uses a simple FNV-like fold; callers that need collision-resistance should
    /// supply their own hashing layer above this crate.
    pub fn cohort_key(&self, discipline: IdentityDiscipline) -> CohortKey {
        let mut key = [0u8; 32];
        // Mix discipline into first byte.
        key[0] = discipline as u8;
        // Mix relevant claim bytes in a deterministic (but not crypto-secure) way.
        for (i, claim) in self.claims.iter().enumerate() {
            if claim_matches_discipline(claim, discipline) {
                let bytes = claim_fingerprint(claim);
                for (j, b) in bytes.iter().enumerate() {
                    key[(i + j + 1) % 32] ^= b;
                }
            }
        }
        CohortKey(key)
    }
}

fn claims_match_under(a: &IdentityClaim, b: &IdentityClaim, d: IdentityDiscipline) -> bool {
    match d {
        IdentityDiscipline::PathStable => match (a, b) {
            (
                IdentityClaim::CanonicalPath {
                    volume: va,
                    path: pa,
                },
                IdentityClaim::CanonicalPath {
                    volume: vb,
                    path: pb,
                },
            ) => va == vb && pa == pb,
            // Design §3.3: a PersistentAddress is PathStable on equal
            // volume + path + stream (the object slot may differ).
            (IdentityClaim::PersistentAddress(pa), IdentityClaim::PersistentAddress(pb)) => {
                pa.volume == pb.volume && pa.path == pb.path && pa.stream == pb.stream
            }
            _ => false,
        },
        IdentityDiscipline::ContentStable => match (a, b) {
            (
                IdentityClaim::ContentHash {
                    algo: aa,
                    digest: da,
                },
                IdentityClaim::ContentHash {
                    algo: ab,
                    digest: db,
                },
            ) => aa == ab && da == db,
            _ => false,
        },
        IdentityDiscipline::ObjectStable => match (a, b) {
            (
                IdentityClaim::InodeIdentity {
                    volume: va,
                    inode: ia,
                    generation: ga,
                },
                IdentityClaim::InodeIdentity {
                    volume: vb,
                    inode: ib,
                    generation: gb,
                },
            ) => va == vb && ia == ib && ga == gb,
            (
                IdentityClaim::NtfsFileRef {
                    volume: va,
                    mft_record: ma,
                    sequence: sa,
                },
                IdentityClaim::NtfsFileRef {
                    volume: vb,
                    mft_record: mb,
                    sequence: sb,
                },
            ) => va == vb && ma == mb && sa == sb,
            // Design §3.3: a PersistentAddress is ObjectStable on equal
            // volume + file_id (robust to renames; the slot-reuse discriminator
            // inside file_id keeps a reallocated record distinct).
            (IdentityClaim::PersistentAddress(pa), IdentityClaim::PersistentAddress(pb)) => {
                pa.volume == pb.volume && pa.file_id == pb.file_id
            }
            _ => false,
        },
        IdentityDiscipline::RecordStable => match (a, b) {
            (
                IdentityClaim::RecordIdentity {
                    schema: sa,
                    primary_key: ka,
                },
                IdentityClaim::RecordIdentity {
                    schema: sb,
                    primary_key: kb,
                },
            ) => sa == sb && ka == kb,
            _ => false,
        },
        IdentityDiscipline::LogicalStable => {
            // Logical stability requires out-of-band evidence; default to path+record.
            claims_match_under(a, b, IdentityDiscipline::PathStable)
                || claims_match_under(a, b, IdentityDiscipline::RecordStable)
        }
    }
}

fn claim_matches_discipline(claim: &IdentityClaim, d: IdentityDiscipline) -> bool {
    matches!(
        (claim, d),
        (
            IdentityClaim::CanonicalPath { .. },
            IdentityDiscipline::PathStable
        ) | (
            IdentityClaim::ContentHash { .. },
            IdentityDiscipline::ContentStable
        ) | (
            IdentityClaim::InodeIdentity { .. } | IdentityClaim::NtfsFileRef { .. },
            IdentityDiscipline::ObjectStable
        ) | (
            IdentityClaim::RecordIdentity { .. },
            IdentityDiscipline::RecordStable
        ) | (
            IdentityClaim::PersistentAddress(_),
            IdentityDiscipline::PathStable | IdentityDiscipline::ObjectStable
        )
    )
}

fn claim_fingerprint(claim: &IdentityClaim) -> Vec<u8> {
    match claim {
        IdentityClaim::CanonicalPath { volume, path } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(path.to_string_lossy().as_bytes());
            v
        }
        IdentityClaim::InodeIdentity {
            volume,
            inode,
            generation,
        } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(&inode.to_le_bytes());
            if let Some(g) = generation {
                v.extend_from_slice(&g.to_le_bytes());
            }
            v
        }
        IdentityClaim::NtfsFileRef {
            volume,
            mft_record,
            sequence,
        } => {
            let mut v = volume.as_bytes().to_vec();
            v.extend_from_slice(&mft_record.to_le_bytes());
            v.extend_from_slice(&sequence.to_le_bytes());
            v
        }
        IdentityClaim::ApfsFileId {
            volume_uuid,
            file_id,
        } => {
            let mut v = volume_uuid.to_vec();
            v.extend_from_slice(&file_id.to_le_bytes());
            v
        }
        IdentityClaim::ContentHash { digest, .. } => digest.clone(),
        IdentityClaim::RecordIdentity {
            schema,
            primary_key,
        } => {
            let mut v = schema.as_bytes().to_vec();
            v.extend_from_slice(primary_key);
            v
        }
        IdentityClaim::ApplicationGuid { guid, .. } => guid.to_vec(),
        IdentityClaim::SigningSubject { issuer, subject } => {
            let mut v = issuer.as_bytes().to_vec();
            v.extend_from_slice(subject.as_bytes());
            v
        }
        // The canonical bytes ARE the fingerprint: a deterministic, injective key.
        IdentityClaim::PersistentAddress(addr) => addr.canonical_bytes(),
    }
}
