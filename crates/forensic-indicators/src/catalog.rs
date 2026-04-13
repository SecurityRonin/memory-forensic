//! Universal forensic artifact catalog.
//!
//! Provides a self-describing, queryable registry of forensic artifact locations
//! (registry keys, files, event logs) with embedded decode logic. Consumers
//! query the catalog by id, hive, scope, or MITRE technique and receive fully
//! decoded [`ArtifactRecord`] values -- never raw bytes.
//!
//! # Design principles
//!
//! - **Zero mandatory external deps** -- FILETIME conversion and ROT13 are pure
//!   math/ASCII. Timestamps are ISO 8601 `String`s.
//! - **`const`/`static`-friendly** -- [`ArtifactDescriptor`] and its constituent
//!   enums are all constructible in `const` context. [`Decoder`] is flat (no
//!   recursive `&'static Decoder`).
//! - **Additive** -- existing modules (`ports`, `persistence`, ...) are untouched.
//!   This module is purely additive.
//! - **Single source of truth** -- artifact paths, decode logic, field schemas,
//!   and MITRE mappings live here. Consumers never hardcode them.

// ── Core enums ───────────────────────────────────────────────────────────────

/// The kind of forensic artifact location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactType {
    /// A registry key (container of values).
    RegistryKey,
    /// A specific registry value.
    RegistryValue,
    /// A file on disk.
    File,
    /// A directory on disk.
    Directory,
    /// A Windows Event Log channel.
    EventLog,
    /// A region of process/physical memory.
    MemoryRegion,
}

/// Which Windows registry hive an artifact lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HiveTarget {
    HklmSystem,
    HklmSoftware,
    HklmSam,
    HklmSecurity,
    NtUser,
    UsrClass,
    Amcache,
    Bcd,
    /// Non-registry artifacts (files, event logs, memory).
    None,
}

/// Whether the artifact is per-user, system-wide, or mixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataScope {
    User,
    System,
    Network,
    Mixed,
}

/// Minimum OS version / platform required for the artifact to exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsScope {
    // ── Windows ──────────────────────────────────────────────────────────
    All,
    Win7Plus,
    Win8Plus,
    Win10Plus,
    Win11Plus,
    Win11_22H2,
    // ── Linux ────────────────────────────────────────────────────────────
    /// All Linux distributions (kernel + standard POSIX userland).
    Linux,
    /// systemd-based distros (Ubuntu 16.04+, Fedora 15+, Debian 8+, Arch).
    LinuxSystemd,
    /// Debian / Ubuntu specific paths or tools.
    LinuxDebian,
    /// Red Hat / CentOS / Fedora specific paths.
    LinuxRhel,
}

// ── Binary field layout ──────────────────────────────────────────────────────

/// Primitive type of a field inside a fixed-layout binary record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFieldType {
    U16Le,
    U32Le,
    U64Le,
    I32Le,
    I64Le,
    FiletimeLe,
    Bytes { len: usize },
}

/// One field inside a fixed-layout binary record (e.g. the 72-byte UserAssist
/// value). Fully `const`-constructible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BinaryField {
    pub name: &'static str,
    pub offset: usize,
    pub field_type: BinaryFieldType,
    pub description: &'static str,
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Describes how to decode raw bytes (and/or a registry value name) into
/// structured fields.
///
/// This enum is intentionally **flat** -- no recursive `&'static Decoder` --
/// so every variant is usable in `const`/`static` context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoder {
    /// Pass-through: interpret raw bytes as UTF-8 text. Single field "value".
    Identity,
    /// ROT13-decode the *name* parameter. Single field "program".
    Rot13Name,
    /// Read an 8-byte little-endian FILETIME at the given byte offset.
    FiletimeAt { offset: usize },
    /// Interpret raw bytes as UTF-16LE text.
    Utf16Le,
    /// Split the *name* (or raw as UTF-8) on `|` and zip with field names.
    PipeDelimited { fields: &'static [&'static str] },
    /// Read a little-endian u32 from raw bytes.
    DwordLe,
    /// REG_MULTI_SZ: NUL-separated UTF-16LE strings terminated by double NUL.
    MultiSz,
    /// MRUListEx: u32-LE index list terminated by 0xFFFFFFFF.
    MruListEx,
    /// Parse a fixed-layout binary record using the given field descriptors.
    BinaryRecord(&'static [BinaryField]),
    /// ROT13-decode the *name*, then parse the binary *value* using field
    /// descriptors. Combined output has "program" plus all binary fields.
    Rot13NameWithBinaryValue(&'static [BinaryField]),
}

// ── Field schema (describes output fields) ───────────────────────────────────

/// The semantic type of a decoded output field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    Text,
    Integer,
    UnsignedInt,
    Timestamp,
    Bytes,
    Bool,
    List,
}

/// Describes one field in a decoded artifact record -- purely metadata, no data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: &'static str,
    pub value_type: ValueType,
    pub description: &'static str,
    /// If `true`, this field participates in the record's unique identifier.
    pub is_uid_component: bool,
}

// ── ArtifactDescriptor (the catalog entry) ───────────────────────────────────

/// A single entry in the forensic artifact catalog. Fully `const`-constructible
/// so it can live in a `static`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactDescriptor {
    /// Short machine-readable identifier, e.g. `"userassist"`.
    pub id: &'static str,
    /// Human-readable display name.
    pub name: &'static str,
    /// What kind of artifact location this is.
    pub artifact_type: ArtifactType,
    /// Which registry hive, or `None` for non-registry artifacts.
    pub hive: Option<HiveTarget>,
    /// Registry key path relative to the hive root (empty for non-registry).
    pub key_path: &'static str,
    /// Specific registry value name, if targeting a single value.
    pub value_name: Option<&'static str>,
    /// Filesystem path, for file/directory artifacts.
    pub file_path: Option<&'static str>,
    /// User vs System vs Mixed scope.
    pub scope: DataScope,
    /// Minimum OS version required.
    pub os_scope: OsScope,
    /// How to decode the raw data.
    pub decoder: Decoder,
    /// Forensic meaning / significance of this artifact.
    pub meaning: &'static str,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: &'static [&'static str],
    /// Schema of the decoded output fields.
    pub fields: &'static [FieldSchema],
}

// ── ArtifactValue (universal decoded value) ──────────────────────────────────

/// A decoded value produced by the catalog's decode logic. Uses only `std` types.
#[derive(Debug, Clone, PartialEq)]
pub enum ArtifactValue {
    Text(String),
    Integer(i64),
    UnsignedInt(u64),
    Timestamp(String),
    Bytes(Vec<u8>),
    Bool(bool),
    List(Vec<ArtifactValue>),
    Map(Vec<(String, ArtifactValue)>),
    Null,
}

// ── ArtifactRecord (universal decoded output) ────────────────────────────────

/// A fully decoded forensic artifact record. This is the universal output type
/// that all consumers receive -- no raw bytes, no hardcoded field names.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactRecord {
    /// Globally unique URI, e.g. `winreg://HKCU/Software/.../value_name` or
    /// `file:///path/to/file#line`.
    pub uid: String,
    /// The catalog entry id that produced this record.
    pub artifact_id: &'static str,
    /// Human-readable artifact name.
    pub artifact_name: &'static str,
    /// Data scope (User/System/...).
    pub scope: DataScope,
    /// OS scope.
    pub os_scope: OsScope,
    /// Primary timestamp in ISO 8601 UTC, if the artifact has one.
    pub timestamp: Option<String>,
    /// Ordered decoded field name-value pairs.
    pub fields: Vec<(&'static str, ArtifactValue)>,
    /// Human-readable meaning, possibly with interpolated field values.
    pub meaning: String,
    /// MITRE ATT&CK technique IDs applicable to this record.
    pub mitre_techniques: Vec<&'static str>,
    /// Confidence score 0.0-1.0, set by the decoder or classifier.
    pub confidence: f32,
}

// ── ArtifactQuery (filter parameters) ────────────────────────────────────────

/// Filter parameters for querying the catalog. All fields are optional --
/// `None` means "match any".
#[derive(Debug, Clone, Default)]
pub struct ArtifactQuery {
    pub scope: Option<DataScope>,
    pub os_scope: Option<OsScope>,
    pub artifact_type: Option<ArtifactType>,
    pub hive: Option<HiveTarget>,
    pub mitre_technique: Option<&'static str>,
    pub id: Option<&'static str>,
}

// ── DecodeError ──────────────────────────────────────────────────────────────

/// Errors that can occur during artifact decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The raw data buffer is too short for the decoder to operate.
    BufferTooShort { expected: usize, actual: usize },
    /// The raw data is not valid UTF-8 where UTF-8 was expected.
    InvalidUtf8,
    /// The raw data is not valid UTF-16LE.
    InvalidUtf16,
    /// A binary field offset+size exceeds the buffer length.
    FieldOutOfBounds {
        field: &'static str,
        offset: usize,
        size: usize,
        buf_len: usize,
    },
    /// The decoder variant does not apply to this data shape.
    UnsupportedDecoder(&'static str),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BufferTooShort { expected, actual } => {
                write!(f, "buffer too short: need {expected} bytes, got {actual}")
            }
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in raw data"),
            Self::InvalidUtf16 => write!(f, "invalid UTF-16LE in raw data"),
            Self::FieldOutOfBounds {
                field,
                offset,
                size,
                buf_len,
            } => write!(
                f,
                "field '{field}' at offset {offset} size {size} exceeds buffer length {buf_len}"
            ),
            Self::UnsupportedDecoder(msg) => write!(f, "unsupported decoder: {msg}"),
        }
    }
}

impl std::error::Error for DecodeError {}

// ── ForensicCatalog ──────────────────────────────────────────────────────────

/// A queryable collection of [`ArtifactDescriptor`]s with built-in decode logic.
pub struct ForensicCatalog {
    entries: &'static [ArtifactDescriptor],
}

impl ForensicCatalog {
    /// Create a new catalog from a static slice of descriptors.
    pub const fn new(entries: &'static [ArtifactDescriptor]) -> Self {
        Self { entries }
    }

    /// Return all descriptors in the catalog.
    pub fn list(&self) -> &[ArtifactDescriptor] {
        self.entries
    }

    /// Look up a descriptor by its `id` field.
    pub fn by_id(&self, id: &str) -> Option<&ArtifactDescriptor> {
        self.entries.iter().find(|d| d.id == id)
    }

    /// Return all descriptors matching the given query. Every `Some` field in
    /// the query must match; `None` fields are wildcards.
    pub fn filter(&self, query: &ArtifactQuery) -> Vec<&ArtifactDescriptor> {
        self.entries
            .iter()
            .filter(|d| {
                if let Some(scope) = query.scope {
                    if d.scope != scope {
                        return false;
                    }
                }
                if let Some(os) = query.os_scope {
                    if d.os_scope != os {
                        return false;
                    }
                }
                if let Some(at) = query.artifact_type {
                    if d.artifact_type != at {
                        return false;
                    }
                }
                if let Some(hive) = query.hive {
                    if d.hive != Some(hive) {
                        return false;
                    }
                }
                if let Some(tech) = query.mitre_technique {
                    if !d.mitre_techniques.contains(&tech) {
                        return false;
                    }
                }
                if let Some(id) = query.id {
                    if d.id != id {
                        return false;
                    }
                }
                true
            })
            .collect()
    }

    /// Decode raw data using the descriptor's embedded decoder.
    ///
    /// # Parameters
    /// - `descriptor` -- the catalog entry describing the artifact
    /// - `name` -- the registry value name (or filename), used by ROT13 and
    ///   PipeDelimited decoders
    /// - `raw` -- the raw byte payload of the registry value or file content
    pub fn decode(
        &self,
        descriptor: &ArtifactDescriptor,
        name: &str,
        raw: &[u8],
    ) -> Result<ArtifactRecord, DecodeError> {
        decode_artifact(descriptor, name, raw)
    }
}

// ── Decode implementation ────────────────────────────────────────────────────

/// ROT13-decode an ASCII string: rotate A-Z and a-z by 13, leave other chars.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (b'A' + (c as u8 - b'A' + 13) % 26) as char,
            'a'..='z' => (b'a' + (c as u8 - b'a' + 13) % 26) as char,
            other => other,
        })
        .collect()
}

/// Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO 8601 UTC.
///
/// Returns `None` for zero or negative Unix epoch values.
fn filetime_to_iso8601(ft: u64) -> Option<String> {
    // FILETIME epoch is 1601-01-01. Unix epoch offset in 100ns ticks:
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft == 0 {
        return None;
    }
    if ft < EPOCH_DIFF {
        return None;
    }
    let unix_secs = (ft - EPOCH_DIFF) / 10_000_000;

    // Convert unix_secs to calendar date/time via pure arithmetic.
    // Algorithm: days since epoch -> year/month/day; remainder -> H:M:S.
    let secs_per_day: u64 = 86400;
    let mut days = unix_secs / secs_per_day;
    let day_secs = unix_secs % secs_per_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Civil date from days since 1970-01-01 (Euclidean affine algorithm).
    // Shift epoch to 0000-03-01 to make leap-year logic simpler.
    days += 719_468; // days from 0000-03-01 to 1970-01-01
    let era = days / 146_097;
    let doe = days - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    ))
}

/// Read a u16 LE at `offset`, returning 0 if out of bounds.
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a u32 LE at `offset`, returning 0 if out of bounds.
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read a u64 LE at `offset`, returning 0 if out of bounds.
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read an i32 LE at `offset`, returning 0 if out of bounds.
fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    if offset + 4 > data.len() {
        return 0;
    }
    i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Read an i64 LE at `offset`, returning 0 if out of bounds.
fn read_i64_le(data: &[u8], offset: usize) -> i64 {
    if offset + 8 > data.len() {
        return 0;
    }
    i64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Decode a single [`BinaryField`] from a raw buffer into an [`ArtifactValue`].
fn decode_binary_field(field: &BinaryField, raw: &[u8]) -> Result<ArtifactValue, DecodeError> {
    let size = match field.field_type {
        BinaryFieldType::U16Le => 2,
        BinaryFieldType::U32Le | BinaryFieldType::I32Le => 4,
        BinaryFieldType::U64Le | BinaryFieldType::I64Le | BinaryFieldType::FiletimeLe => 8,
        BinaryFieldType::Bytes { len } => len,
    };
    if field.offset + size > raw.len() {
        return Err(DecodeError::FieldOutOfBounds {
            field: field.name,
            offset: field.offset,
            size,
            buf_len: raw.len(),
        });
    }
    Ok(match field.field_type {
        BinaryFieldType::U16Le => ArtifactValue::UnsignedInt(u64::from(read_u16_le(raw, field.offset))),
        BinaryFieldType::U32Le => ArtifactValue::UnsignedInt(u64::from(read_u32_le(raw, field.offset))),
        BinaryFieldType::U64Le => ArtifactValue::UnsignedInt(read_u64_le(raw, field.offset)),
        BinaryFieldType::I32Le => ArtifactValue::Integer(i64::from(read_i32_le(raw, field.offset))),
        BinaryFieldType::I64Le => ArtifactValue::Integer(read_i64_le(raw, field.offset)),
        BinaryFieldType::FiletimeLe => {
            let ft = read_u64_le(raw, field.offset);
            match filetime_to_iso8601(ft) {
                Some(ts) => ArtifactValue::Timestamp(ts),
                None => ArtifactValue::Null,
            }
        }
        BinaryFieldType::Bytes { len } => {
            ArtifactValue::Bytes(raw[field.offset..field.offset + len].to_vec())
        }
    })
}

/// Build the default UID for a registry artifact.
fn build_registry_uid(descriptor: &ArtifactDescriptor, name: &str) -> String {
    let hive_prefix = match descriptor.hive {
        Some(HiveTarget::NtUser) => "HKCU",
        Some(HiveTarget::UsrClass) => "HKCU_Classes",
        Some(HiveTarget::HklmSoftware) => "HKLM\\SOFTWARE",
        Some(HiveTarget::HklmSystem) => "HKLM\\SYSTEM",
        Some(HiveTarget::HklmSam) => "HKLM\\SAM",
        Some(HiveTarget::HklmSecurity) => "HKLM\\SECURITY",
        Some(HiveTarget::Amcache) => "Amcache",
        Some(HiveTarget::Bcd) => "BCD",
        Some(HiveTarget::None) | None => "unknown",
    };
    if name.is_empty() {
        format!("winreg://{}/{}", hive_prefix, descriptor.key_path)
    } else {
        format!("winreg://{}/{}/{}", hive_prefix, descriptor.key_path, name)
    }
}

/// Build the default UID for a file artifact.
fn build_file_uid(descriptor: &ArtifactDescriptor, name: &str) -> String {
    let path = descriptor.file_path.unwrap_or("");
    if name.is_empty() {
        format!("file://{path}")
    } else {
        format!("file://{path}#{name}")
    }
}

/// Decode a slice of [`BinaryField`]s from raw bytes, returning field values
/// and the first FILETIME timestamp encountered (if any).
#[allow(clippy::type_complexity)]
fn decode_binary_fields(
    binary_fields: &[BinaryField],
    raw: &[u8],
) -> Result<(Vec<(&'static str, ArtifactValue)>, Option<String>), DecodeError> {
    let mut decoded = Vec::new();
    let mut ts = None;
    for bf in binary_fields {
        let val = decode_binary_field(bf, raw)?;
        if bf.field_type == BinaryFieldType::FiletimeLe {
            if let ArtifactValue::Timestamp(ref s) = val {
                if ts.is_none() {
                    ts = Some(s.clone());
                }
            }
        }
        decoded.push((bf.name, val));
    }
    Ok((decoded, ts))
}

/// Core decode function: routes to the appropriate decoder variant.
#[allow(clippy::too_many_lines)]
fn decode_artifact(
    descriptor: &ArtifactDescriptor,
    name: &str,
    raw: &[u8],
) -> Result<ArtifactRecord, DecodeError> {
    let (fields, timestamp) = match descriptor.decoder {
        Decoder::Identity => {
            let text = std::str::from_utf8(raw)
                .map_err(|_| DecodeError::InvalidUtf8)?
                .to_string();
            (vec![("value", ArtifactValue::Text(text))], None)
        }

        Decoder::Rot13Name => {
            let decoded = rot13(name);
            (vec![("program", ArtifactValue::Text(decoded))], None)
        }

        Decoder::FiletimeAt { offset } => {
            if offset + 8 > raw.len() {
                return Err(DecodeError::BufferTooShort {
                    expected: offset + 8,
                    actual: raw.len(),
                });
            }
            let ft = read_u64_le(raw, offset);
            let ts = filetime_to_iso8601(ft);
            (
                vec![(
                    "timestamp",
                    match ts {
                        Some(ref s) => ArtifactValue::Timestamp(s.clone()),
                        None => ArtifactValue::Null,
                    },
                )],
                ts,
            )
        }

        Decoder::Utf16Le => {
            if raw.len() % 2 != 0 {
                return Err(DecodeError::InvalidUtf16);
            }
            let u16s: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Trim trailing NUL(s).
            let trimmed: &[u16] = match u16s.iter().position(|&c| c == 0) {
                Some(pos) => &u16s[..pos],
                None => &u16s,
            };
            let text = String::from_utf16(trimmed).map_err(|_| DecodeError::InvalidUtf16)?;
            (vec![("value", ArtifactValue::Text(text))], None)
        }

        Decoder::PipeDelimited { fields: field_names } => {
            // Try name first; fall back to raw as UTF-8.
            let source = if name.is_empty() {
                std::str::from_utf8(raw)
                    .map_err(|_| DecodeError::InvalidUtf8)?
                    .to_string()
            } else {
                name.to_string()
            };
            let parts: Vec<&str> = source.split('|').collect();
            let decoded_fields: Vec<(&'static str, ArtifactValue)> = field_names
                .iter()
                .enumerate()
                .map(|(i, &fname)| {
                    let val = match parts.get(i) {
                        Some(s) => ArtifactValue::Text((*s).to_string()),
                        None => ArtifactValue::Null,
                    };
                    (fname, val)
                })
                .collect();
            (decoded_fields, None)
        }

        Decoder::DwordLe => {
            if raw.len() < 4 {
                return Err(DecodeError::BufferTooShort {
                    expected: 4,
                    actual: raw.len(),
                });
            }
            let val = read_u32_le(raw, 0);
            (vec![("value", ArtifactValue::UnsignedInt(u64::from(val)))], None)
        }

        Decoder::MultiSz => {
            // REG_MULTI_SZ: UTF-16LE, NUL-separated, double NUL terminated.
            if raw.len() < 2 {
                return Ok(make_record(
                    descriptor,
                    name,
                    vec![("values", ArtifactValue::List(vec![]))],
                    None,
                ));
            }
            if raw.len() % 2 != 0 {
                return Err(DecodeError::InvalidUtf16);
            }
            let u16s: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            // Split on NUL, dropping the final empty string(s) from the double NUL.
            let strings: Vec<ArtifactValue> = u16s
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| {
                    ArtifactValue::Text(String::from_utf16_lossy(s))
                })
                .collect();
            (vec![("values", ArtifactValue::List(strings))], None)
        }

        Decoder::MruListEx => {
            // u32 LE index list terminated by 0xFFFFFFFF.
            let mut indices = Vec::new();
            let mut offset = 0;
            while offset + 4 <= raw.len() {
                let idx = read_u32_le(raw, offset);
                if idx == 0xFFFF_FFFF {
                    break;
                }
                indices.push(ArtifactValue::UnsignedInt(u64::from(idx)));
                offset += 4;
            }
            (vec![("indices", ArtifactValue::List(indices))], None)
        }

        Decoder::BinaryRecord(binary_fields) => decode_binary_fields(binary_fields, raw)?,

        Decoder::Rot13NameWithBinaryValue(binary_fields) => {
            let (mut fields, ts) = decode_binary_fields(binary_fields, raw)?;
            fields.insert(0, ("program", ArtifactValue::Text(rot13(name))));
            (fields, ts)
        }
    };

    Ok(make_record(descriptor, name, fields, timestamp))
}

/// Construct an [`ArtifactRecord`] from decoded fields.
fn make_record(
    descriptor: &ArtifactDescriptor,
    name: &str,
    fields: Vec<(&'static str, ArtifactValue)>,
    timestamp: Option<String>,
) -> ArtifactRecord {
    let uid = match descriptor.artifact_type {
        ArtifactType::File | ArtifactType::Directory => build_file_uid(descriptor, name),
        _ => build_registry_uid(descriptor, name),
    };
    ArtifactRecord {
        uid,
        artifact_id: descriptor.id,
        artifact_name: descriptor.name,
        scope: descriptor.scope,
        os_scope: descriptor.os_scope,
        timestamp,
        fields,
        meaning: descriptor.meaning.to_string(),
        mitre_techniques: descriptor.mitre_techniques.to_vec(),
        confidence: 1.0,
    }
}

// ── Static descriptor instances ──────────────────────────────────────────────

/// UserAssist 72-byte binary value fields (Win7+ EXE GUID).
static USERASSIST_BINARY_FIELDS: &[BinaryField] = &[
    BinaryField {
        name: "run_count",
        offset: 4,
        field_type: BinaryFieldType::U32Le,
        description: "Number of times the program was launched",
    },
    BinaryField {
        name: "focus_count",
        offset: 8,
        field_type: BinaryFieldType::U32Le,
        description: "Number of times the program received input focus",
    },
    BinaryField {
        name: "focus_duration_ms",
        offset: 12,
        field_type: BinaryFieldType::U32Le,
        description: "Total focus time in milliseconds",
    },
    BinaryField {
        name: "last_run",
        offset: 60,
        field_type: BinaryFieldType::FiletimeLe,
        description: "FILETIME of the last execution",
    },
];

/// UserAssist field schema (decoded output description).
static USERASSIST_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "program",
        value_type: ValueType::Text,
        description: "ROT13-decoded program path or name",
        is_uid_component: true,
    },
    FieldSchema {
        name: "run_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of times launched",
        is_uid_component: false,
    },
    FieldSchema {
        name: "focus_count",
        value_type: ValueType::UnsignedInt,
        description: "Number of times received focus",
        is_uid_component: false,
    },
    FieldSchema {
        name: "focus_duration_ms",
        value_type: ValueType::UnsignedInt,
        description: "Total focus time in milliseconds",
        is_uid_component: false,
    },
    FieldSchema {
        name: "last_run",
        value_type: ValueType::Timestamp,
        description: "FILETIME of last execution as ISO 8601",
        is_uid_component: false,
    },
];

/// UserAssist EXE entries (NTUSER.DAT).
///
/// GUID: `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}`
/// Key: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
/// Decoder: ROT13 the value name + parse 72-byte binary value.
pub static USERASSIST_EXE: ArtifactDescriptor = ArtifactDescriptor {
    id: "userassist_exe",
    name: "UserAssist (EXE)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
    value_name: None, // enumerate all values
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Rot13NameWithBinaryValue(USERASSIST_BINARY_FIELDS),
    meaning: "Program execution history with launch counts and timestamps",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: USERASSIST_FIELDS,
};

/// Run key field schema.
static RUN_KEY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "value",
    value_type: ValueType::Text,
    description: "Autostart command or path",
    is_uid_component: false,
}];

/// HKLM SOFTWARE Run key -- system-wide autostart persistence.
pub static RUN_KEY_HKLM_RUN: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hklm",
    name: "Run Key (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "System-wide autostart entry executed at every user logon",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
};

/// TypedURLs field schema.
static TYPED_URLS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "value",
    value_type: ValueType::Text,
    description: "URL typed into the IE/Edge address bar",
    is_uid_component: true,
}];

/// Internet Explorer / Edge TypedURLs (NTUSER.DAT).
pub static TYPED_URLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "typed_urls",
    name: "TypedURLs (IE/Edge)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Internet Explorer\TypedURLs",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "URLs manually typed into the Internet Explorer or Edge address bar",
    mitre_techniques: &["T1071.001"],
    fields: TYPED_URLS_FIELDS,
};

/// PCA AppLaunch.dic pipe-delimited fields.
static PCA_FIELDS_SCHEMA: &[FieldSchema] = &[
    FieldSchema {
        name: "exe_path",
        value_type: ValueType::Text,
        description: "Full path to the executable",
        is_uid_component: true,
    },
    FieldSchema {
        name: "timestamp",
        value_type: ValueType::Text,
        description: "Launch timestamp string",
        is_uid_component: false,
    },
];

static PCA_PIPE_FIELDS: &[&str] = &["exe_path", "timestamp"];

/// Program Compatibility Assistant AppLaunch.dic (Win11 22H2+).
///
/// A pipe-delimited text file where each line records an application launch.
pub static PCA_APPLAUNCH_DIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "pca_applaunch_dic",
    name: "PCA AppLaunch.dic",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\appcompat\pca\AppLaunch.dic"),
    scope: DataScope::System,
    os_scope: OsScope::Win11_22H2,
    decoder: Decoder::PipeDelimited {
        fields: PCA_PIPE_FIELDS,
    },
    meaning: "Program execution evidence from the Program Compatibility Assistant",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: PCA_FIELDS_SCHEMA,
};

// ── Run key HKCU variants ────────────────────────────────────────────────────

/// HKCU Run key — per-user autostart persistence.
pub static RUN_KEY_HKCU_RUN: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hkcu",
    name: "Run Key (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Run",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user autostart entry executed at every logon",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
};

/// HKCU RunOnce — per-user one-shot autostart (deleted after execution).
pub static RUN_KEY_HKCU_RUNONCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hkcu_once",
    name: "RunOnce Key (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user one-time autostart, deleted after first execution",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
};

/// HKLM RunOnce — system-wide one-shot autostart.
pub static RUN_KEY_HKLM_RUNONCE: ArtifactDescriptor = ArtifactDescriptor {
    id: "run_key_hklm_once",
    name: "RunOnce Key (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\RunOnce",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "System-wide one-time autostart, deleted after first execution",
    mitre_techniques: &["T1547.001"],
    fields: RUN_KEY_FIELDS,
};

// ── IFEO ──────────────────────────────────────────────────────────────────────

static IFEO_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "debugger",
    value_type: ValueType::Text,
    description: "Debugger path that hijacks the target process launch",
    is_uid_component: false,
}];

/// Image File Execution Options — Debugger value hijack (T1546.012).
///
/// Attacker sets `Debugger` under a target EXE's IFEO key to redirect
/// its launch to an arbitrary binary (e.g., `cmd.exe`).
pub static IFEO_DEBUGGER: ArtifactDescriptor = ArtifactDescriptor {
    id: "ifeo_debugger",
    name: "IFEO Debugger Hijack",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    value_name: Some("Debugger"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Redirects target-process launch to an attacker-controlled binary",
    mitre_techniques: &["T1546.012"],
    fields: IFEO_FIELDS,
};

// ── UserAssist (Folder GUID) ─────────────────────────────────────────────────

/// UserAssist Folder GUID entries (NTUSER.DAT).
///
/// GUID: `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` — records folder access.
pub static USERASSIST_FOLDER: ArtifactDescriptor = ArtifactDescriptor {
    id: "userassist_folder",
    name: "UserAssist (Folder)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Rot13NameWithBinaryValue(USERASSIST_BINARY_FIELDS),
    meaning: "Folder navigation history with access counts and timestamps",
    mitre_techniques: &["T1083"],
    fields: USERASSIST_FIELDS,
};

// ── ShellBags ─────────────────────────────────────────────────────────────────

static SHELLBAGS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "indices",
    value_type: ValueType::List,
    description: "MRU order of accessed shell folder slots",
    is_uid_component: false,
}];

/// ShellBags — folder navigation history in UsrClass.dat.
///
/// Records folders the user browsed via Explorer, including deleted, network,
/// and removable-media paths. Survives folder deletion.
pub static SHELLBAGS_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "shellbags_user",
    name: "ShellBags (User)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"Local Settings\Software\Microsoft\Windows\Shell\Bags",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MruListEx,
    meaning: "Folder access history; persists paths even after folder deletion",
    mitre_techniques: &["T1083", "T1005"],
    fields: SHELLBAGS_FIELDS,
};

// ── Amcache ───────────────────────────────────────────────────────────────────

static AMCACHE_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "file_id",
        value_type: ValueType::Text,
        description: "Volume GUID + MFT file reference (unique file identity)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "sha1",
        value_type: ValueType::Text,
        description: "SHA1 of the first 31.25 MB (0000-prefixed)",
        is_uid_component: false,
    },
];

/// Amcache InventoryApplicationFile — program execution evidence with hashes.
pub static AMCACHE_APP_FILE: ArtifactDescriptor = ArtifactDescriptor {
    id: "amcache_app_file",
    name: "Amcache InventoryApplicationFile",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::Amcache),
    key_path: r"Root\InventoryApplicationFile",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning: "Program execution evidence with file hash; persists after binary deletion",
    mitre_techniques: &["T1218", "T1204.002"],
    fields: AMCACHE_FIELDS,
};

// ── ShimCache (AppCompatCache) ────────────────────────────────────────────────

static SHIMCACHE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "raw",
    value_type: ValueType::Bytes,
    description: "Raw AppCompatCache binary blob (parsed by shimcache module)",
    is_uid_component: false,
}];

/// ShimCache — application compatibility cache with executable metadata.
///
/// Stored as a single binary value `AppCompatCache` under the SYSTEM hive.
/// Contains executable paths and last-modified timestamps (NOT execution times
/// on Win8+). Parsed by the shimcache module.
pub static SHIMCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "shimcache",
    name: "ShimCache (AppCompatCache)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager\AppCompatCache",
    value_name: Some("AppCompatCache"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executable metadata cache; presence proves binary existed on disk",
    mitre_techniques: &["T1218", "T1059"],
    fields: SHIMCACHE_FIELDS,
};

// ── BAM / DAM ─────────────────────────────────────────────────────────────────

static BAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "last_exec",
    value_type: ValueType::Timestamp,
    description: "FILETIME of last background execution",
    is_uid_component: false,
}];

/// Background Activity Moderator — per-user background process execution times.
///
/// Each value under a SID sub-key is the executable path; value data is an
/// 8-byte FILETIME of the last execution. Win10 1709+.
pub static BAM_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "bam_user",
    name: "BAM (Background Activity Moderator)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\bam\State\UserSettings",
    value_name: None,
    file_path: None,
    scope: DataScope::Mixed,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Last execution time of background/UWP processes per-user SID",
    mitre_techniques: &["T1059", "T1204"],
    fields: BAM_FIELDS,
};

static DAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "last_exec",
    value_type: ValueType::Timestamp,
    description: "FILETIME of last desktop application execution",
    is_uid_component: false,
}];

/// Desktop Activity Moderator — per-user desktop application execution times.
pub static DAM_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dam_user",
    name: "DAM (Desktop Activity Moderator)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\dam\State\UserSettings",
    value_name: None,
    file_path: None,
    scope: DataScope::Mixed,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Last execution time of desktop applications per-user SID",
    mitre_techniques: &["T1059", "T1204"],
    fields: DAM_FIELDS,
};

// ── SAM ───────────────────────────────────────────────────────────────────────

static SAM_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "username",
    value_type: ValueType::Text,
    description: "Local account username (sub-key name)",
    is_uid_component: true,
}];

/// SAM local user account enumeration.
///
/// Each sub-key under `Names` is a local account username. The adjacent
/// `Users\<RID>` keys contain F/V binary records with password hash metadata.
pub static SAM_USERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "sam_users",
    name: "SAM User Accounts",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSam),
    key_path: r"SAM\Domains\Account\Users\Names",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Local Windows accounts; F/V records contain login counts and NTLM hash metadata",
    mitre_techniques: &["T1003.002", "T1087.001"],
    fields: SAM_FIELDS,
};

// ── LSA Secrets / DCC2 ───────────────────────────────────────────────────────

static LSA_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "secret_name",
    value_type: ValueType::Text,
    description: "LSA secret key name (e.g. _SC_*, DPAPI_SYSTEM, DefaultPassword)",
    is_uid_component: true,
}];

/// LSA Secrets — encrypted service credentials and DPAPI material.
pub static LSA_SECRETS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_secrets",
    name: "LSA Secrets",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSecurity),
    key_path: r"Policy\Secrets",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Encrypted service credentials, auto-logon passwords, and DPAPI master key",
    mitre_techniques: &["T1003.004", "T1552.002"],
    fields: LSA_FIELDS,
};

static DCC2_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "slot_name",
    value_type: ValueType::Text,
    description: "Cache slot name (NL$1 through NL$25)",
    is_uid_component: true,
}];

/// Domain Cached Credentials 2 (MS-Cache v2 / DCC2).
///
/// PBKDF2-SHA1 hashes of the last N domain logons, enabling offline logon
/// when no DC is reachable. Crackable offline.
pub static DCC2_CACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "dcc2_cache",
    name: "Domain Cached Credentials 2 (DCC2)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSecurity),
    key_path: r"Cache",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "MS-Cache v2 (PBKDF2-SHA1) hashes enabling offline domain logon",
    mitre_techniques: &["T1003.005"],
    fields: DCC2_FIELDS,
};

// ── TypedURLsTime ─────────────────────────────────────────────────────────────

static TYPED_URLS_TIME_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "timestamp",
    value_type: ValueType::Timestamp,
    description: "FILETIME when the URL slot was typed",
    is_uid_component: false,
}];

/// IE/Edge TypedURLsTime — FILETIME timestamps parallel to TypedURLs.
pub static TYPED_URLS_TIME: ArtifactDescriptor = ArtifactDescriptor {
    id: "typed_urls_time",
    name: "TypedURLsTime (IE/Edge)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Internet Explorer\TypedURLsTime",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::FiletimeAt { offset: 0 },
    meaning: "Timestamps of URLs typed into IE/Edge address bar (paired with TypedURLs)",
    mitre_techniques: &["T1071.001"],
    fields: TYPED_URLS_TIME_FIELDS,
};

// ── MRU RecentDocs ────────────────────────────────────────────────────────────

static MRU_RECENT_DOCS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "indices",
    value_type: ValueType::List,
    description: "MRUListEx order indices of recently accessed documents",
    is_uid_component: false,
}];

/// Explorer RecentDocs MRU — most-recently-used document list.
pub static MRU_RECENT_DOCS: ArtifactDescriptor = ArtifactDescriptor {
    id: "mru_recent_docs",
    name: "MRU RecentDocs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Most-recently-used documents list (MRUListEx order of shell32 items)",
    mitre_techniques: &["T1005", "T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
};

// ── USB device enumeration ────────────────────────────────────────────────────

static USB_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "device_id",
    value_type: ValueType::Text,
    description: "USB device instance ID (VID&PID sub-key name)",
    is_uid_component: true,
}];

/// USBSTOR — USB storage device connection history.
///
/// Each sub-key records a device that was ever connected. Survives device removal.
pub static USB_ENUM: ArtifactDescriptor = ArtifactDescriptor {
    id: "usb_enum",
    name: "USB Device Enumeration (USBSTOR)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Enum\USBSTOR",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "USB storage device connection history; persists after device removal",
    mitre_techniques: &["T1200", "T1052.001"],
    fields: USB_FIELDS,
};

// ── MUICache ──────────────────────────────────────────────────────────────────

static MUICACHE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "display_name",
    value_type: ValueType::Text,
    description: "Localized display name of the executed application",
    is_uid_component: false,
}];

/// MUICache — cached display names of executed applications.
///
/// Value name is the full executable path; data is the localized display name
/// (UTF-16 LE). Program execution evidence that survives log clearing.
pub static MUICACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "muicache",
    name: "MUICache",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"Local Settings\MuiCache",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Utf16Le,
    meaning: "Cached display names keyed by executable path; program execution evidence",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: MUICACHE_FIELDS,
};

// ── AppInit_DLLs ──────────────────────────────────────────────────────────────

static APPINIT_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "dll_list",
    value_type: ValueType::Text,
    description: "Comma/space-separated DLL paths injected into user32.dll consumers",
    is_uid_component: false,
}];

/// AppInit_DLLs — DLL injection into every user-mode process (T1546.010).
///
/// Disabled by Secure Boot; still active on systems without it.
pub static APPINIT_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "appinit_dlls",
    name: "AppInit_DLLs",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Windows",
    value_name: Some("AppInit_DLLs"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs injected into every process that loads user32.dll",
    mitre_techniques: &["T1546.010"],
    fields: APPINIT_FIELDS,
};

// ── Winlogon Userinit ─────────────────────────────────────────────────────────

static WINLOGON_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "userinit",
    value_type: ValueType::Text,
    description: "Comma-separated executables launched by Winlogon at logon",
    is_uid_component: false,
}];

/// Winlogon Userinit — process launched after user authentication (T1547.004).
///
/// Default value: `C:\Windows\System32\userinit.exe,`
/// Attackers append `,malware.exe` or replace entirely.
pub static WINLOGON_USERINIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_userinit",
    name: "Winlogon Userinit",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("Userinit"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Process(es) launched by Winlogon at logon; default is userinit.exe,",
    mitre_techniques: &["T1547.004"],
    fields: WINLOGON_FIELDS,
};

// ── Screensaver persistence ───────────────────────────────────────────────────

static SCREENSAVER_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Path to the screensaver executable (.scr)",
    is_uid_component: false,
}];

/// Screensaver executable persistence (T1546.002).
///
/// `.scr` files are PE executables; an attacker can replace the screensaver
/// path with a malicious binary that executes when the screen locks.
pub static SCREENSAVER_EXE: ArtifactDescriptor = ArtifactDescriptor {
    id: "screensaver_exe",
    name: "Screensaver Executable",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Control Panel\Desktop",
    value_name: Some("SCRNSAVE.EXE"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Screensaver path; malicious .scr enables persistence on screen lock",
    mitre_techniques: &["T1546.002"],
    fields: SCREENSAVER_FIELDS,
};

// ═══════════════════════════════════════════════════════════════════════════
// Batch C — Windows persistence / execution / credential artifacts
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared field schemas (reused across multiple descriptors) ─────────────

/// Generic "command or path" field — suitable for persistence value descriptors.
static PERSIST_CMD_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "command",
    value_type: ValueType::Text,
    description: "Command, DLL path, or executable registered for execution",
    is_uid_component: false,
}];

/// Generic "DLL path" field.
static DLL_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "dll_path",
    value_type: ValueType::Text,
    description: "Path to the DLL registered for injection or loading",
    is_uid_component: false,
}];

/// Generic "directory listing" field for filesystem directory artifacts.
static DIR_ENTRY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "entry_name",
    value_type: ValueType::Text,
    description: "Name of the file or shortcut present in this directory",
    is_uid_component: true,
}];

/// Generic "file path" for single-file artifacts.
static FILE_PATH_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Full path to the artifact file",
    is_uid_component: true,
}];

// ── Windows persistence: advanced registry ────────────────────────────────

/// Winlogon Shell value — replaceable Windows Explorer shell (T1547.004).
///
/// Default: `explorer.exe`. Attackers replace or append to gain persistence
/// that launches their binary as the user's shell at logon.
pub static WINLOGON_SHELL: ArtifactDescriptor = ArtifactDescriptor {
    id: "winlogon_shell",
    name: "Winlogon Shell",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows NT\CurrentVersion\Winlogon",
    value_name: Some("Shell"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Windows shell process(es) launched by Winlogon; default is explorer.exe",
    mitre_techniques: &["T1547.004"],
    fields: PERSIST_CMD_FIELDS,
};

/// Windows Services — ImagePath value indicates binary launched as a service.
///
/// Each sub-key under `Services\*` has `ImagePath` (the executable) and
/// `Start` (0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled).
pub static SERVICES_IMAGEPATH: ArtifactDescriptor = ArtifactDescriptor {
    id: "services_imagepath",
    name: "Services ImagePath",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services",
    value_name: Some("ImagePath"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executable path of a Windows service; auto-started services persist across reboots",
    mitre_techniques: &["T1543.003"],
    fields: PERSIST_CMD_FIELDS,
};

static ACTIVE_SETUP_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "stub_path",
    value_type: ValueType::Text,
    description: "StubPath command executed once per user at logon for new installs",
    is_uid_component: false,
}];

/// Active Setup HKLM — system-side component registration (T1547.014).
///
/// Each CLSID sub-key has `StubPath`. Windows compares HKLM and HKCU versions;
/// if HKCU is missing or older, StubPath is executed as the user at logon.
pub static ACTIVE_SETUP_HKLM: ArtifactDescriptor = ArtifactDescriptor {
    id: "active_setup_hklm",
    name: "Active Setup (HKLM)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Active Setup\Installed Components",
    value_name: Some("StubPath"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Per-user setup command executed by HKLM Active Setup; malicious StubPath = user-context persistence",
    mitre_techniques: &["T1547.014"],
    fields: ACTIVE_SETUP_FIELDS,
};

/// Active Setup HKCU — user-side Active Setup version tracking.
///
/// Attacker may delete HKCU entry to trigger HKLM StubPath re-execution.
pub static ACTIVE_SETUP_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "active_setup_hkcu",
    name: "Active Setup (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Active Setup\Installed Components",
    value_name: Some("Version"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "User-side Active Setup version; mismatch with HKLM triggers StubPath re-execution",
    mitre_techniques: &["T1547.014"],
    fields: RUN_KEY_FIELDS,
};

/// COM Hijacking via HKCU CLSID registration (T1546.015).
///
/// When an application resolves a CLSID, Windows checks HKCU\Classes before
/// HKLM. Registering a malicious InprocServer32 in HKCU wins the race
/// without requiring admin privileges.
pub static COM_HIJACK_CLSID_HKCU: ArtifactDescriptor = ArtifactDescriptor {
    id: "com_hijack_clsid_hkcu",
    name: "COM Hijack CLSID (HKCU)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::UsrClass),
    key_path: r"CLSID",
    value_name: Some("InprocServer32"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "User-space CLSID registration overriding system COM server; no admin needed",
    mitre_techniques: &["T1546.015"],
    fields: DLL_FIELDS,
};

/// AppCert DLLs — DLL injected into every process calling CreateProcess (T1546.009).
///
/// Unlike AppInit_DLLs, these are loaded into more process types. Rarely
/// legitimate; any non-empty value is highly suspicious.
pub static APPCERT_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "appcert_dlls",
    name: "AppCertDlls",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager\AppCertDlls",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs injected into every process that calls CreateProcess-family APIs",
    mitre_techniques: &["T1546.009"],
    fields: DLL_FIELDS,
};

static BOOT_EXECUTE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "commands",
    value_type: ValueType::List,
    description: "Commands executed by Session Manager before Win32 subsystem starts",
    is_uid_component: false,
}];

/// Boot Execute — commands run by smss.exe before Win32 subsystem (T1547.001).
///
/// Default: `autocheck autochk *`. Additional entries run native NT executables
/// at boot, before antivirus and most defences are loaded.
pub static BOOT_EXECUTE: ArtifactDescriptor = ArtifactDescriptor {
    id: "boot_execute",
    name: "Boot Execute",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Session Manager",
    value_name: Some("BootExecute"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Native executables run by smss.exe at boot; executes before most security software",
    mitre_techniques: &["T1547.001"],
    fields: BOOT_EXECUTE_FIELDS,
};

/// LSA Security Support Providers — SSPs injected into LSASS (T1547.005).
///
/// Legitimate SSPs: kerberos, msv1_0, schannel, wdigest. Extra entries
/// indicate credential-harvesting or persistence.
pub static LSA_SECURITY_PKGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_security_pkgs",
    name: "LSA Security Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Security Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Security Support Providers loaded into LSASS; malicious SSP = persistent LSASS credential access",
    mitre_techniques: &["T1547.005"],
    fields: BOOT_EXECUTE_FIELDS,
};

/// LSA Authentication Packages — loaded by LSASS for auth (T1547.002).
pub static LSA_AUTH_PKGS: ArtifactDescriptor = ArtifactDescriptor {
    id: "lsa_auth_pkgs",
    name: "LSA Authentication Packages",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Authentication Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::MultiSz,
    meaning: "Authentication packages loaded by LSASS; extra DLLs intercept logon credentials",
    mitre_techniques: &["T1547.002"],
    fields: BOOT_EXECUTE_FIELDS,
};

/// Print Monitors — DLL loaded by the spooler service (T1547.010).
///
/// Requires admin. DLL runs as SYSTEM inside spoolsv.exe across reboots.
pub static PRINT_MONITORS: ArtifactDescriptor = ArtifactDescriptor {
    id: "print_monitors",
    name: "Print Monitors",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Print\Monitors",
    value_name: Some("Driver"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLL loaded into spoolsv.exe (SYSTEM); extra monitors = SYSTEM persistence",
    mitre_techniques: &["T1547.010"],
    fields: DLL_FIELDS,
};

/// Time Provider DLLs — loaded into svchost as part of W32Time (T1547.003).
pub static TIME_PROVIDERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "time_providers",
    name: "W32Time Time Provider DLLs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\W32Time\TimeProviders",
    value_name: Some("DllName"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs loaded by the Windows Time service; malicious entry = SYSTEM persistence",
    mitre_techniques: &["T1547.003"],
    fields: DLL_FIELDS,
};

/// Netsh Helper DLLs — COM-like DLLs loaded by netsh.exe (T1546.007).
pub static NETSH_HELPER_DLLS: ArtifactDescriptor = ArtifactDescriptor {
    id: "netsh_helper_dlls",
    name: "Netsh Helper DLLs",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\NetSh",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DLLs loaded whenever netsh.exe is invoked; attacker DLL runs in user's netsh context",
    mitre_techniques: &["T1546.007"],
    fields: DLL_FIELDS,
};

static BHO_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "clsid",
    value_type: ValueType::Text,
    description: "CLSID of the Browser Helper Object (sub-key name)",
    is_uid_component: true,
}];

/// Browser Helper Objects — COM components loaded by IE (T1176).
///
/// BHOs run inside iexplore.exe and can intercept HTTP traffic, steal
/// credentials, and maintain persistence via the COM registry.
pub static BROWSER_HELPER_OBJECTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "browser_helper_objects",
    name: "Internet Explorer Browser Helper Objects",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "COM components auto-loaded into IE; can intercept browsing and steal credentials",
    mitre_techniques: &["T1176"],
    fields: BHO_FIELDS,
};

// ── Windows persistence: filesystem ──────────────────────────────────────

/// User Startup Folder — files/LNKs here execute at user logon (T1547.001).
pub static STARTUP_FOLDER_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_folder_user",
    name: "User Startup Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executables and LNKs here run at user logon; no admin required",
    mitre_techniques: &["T1547.001"],
    fields: DIR_ENTRY_FIELDS,
};

/// System Startup Folder — files/LNKs here execute for all users at logon.
pub static STARTUP_FOLDER_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "startup_folder_system",
    name: "System Startup Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Executables and LNKs run for every user at logon; requires admin to plant",
    mitre_techniques: &["T1547.001"],
    fields: DIR_ENTRY_FIELDS,
};

/// Windows Task Scheduler task XML files (T1053.005).
///
/// Each task is stored as an XML file; key elements: `<Actions>` (what runs),
/// `<Triggers>` (when), `<Principal>` (which user/privileges).
pub static SCHEDULED_TASKS_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "scheduled_tasks_dir",
    name: "Scheduled Tasks Directory",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\Tasks"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "XML task definitions; malicious tasks can run at boot, logon, or arbitrary intervals",
    mitre_techniques: &["T1053.005"],
    fields: DIR_ENTRY_FIELDS,
};

/// WDigest credential caching control (T1003.001).
///
/// Setting `UseLogonCredential` = 1 re-enables cleartext credential caching
/// in LSASS memory on Windows 8.1+ (disabled by default since KB2871997).
pub static WDIGEST_CACHING: ArtifactDescriptor = ArtifactDescriptor {
    id: "wdigest_caching",
    name: "WDigest UseLogonCredential",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\SecurityProviders\WDigest",
    value_name: Some("UseLogonCredential"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::DwordLe,
    meaning: "1 = cleartext creds in LSASS; attackers set this before Mimikatz to harvest passwords",
    mitre_techniques: &["T1003.001"],
    fields: RUN_KEY_FIELDS,
};

// ── Windows execution evidence ────────────────────────────────────────────

/// WordWheelQuery — Explorer search bar history (MRUListEx).
pub static WORDWHEEL_QUERY: ArtifactDescriptor = ArtifactDescriptor {
    id: "wordwheel_query",
    name: "WordWheelQuery (Explorer Search)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MruListEx,
    meaning: "Search terms entered into Windows Explorer search bar; reveals attacker reconnaissance",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
};

/// OpenSaveMRU — files opened/saved via Windows common dialog (T1083).
///
/// Each file extension has a sub-key containing an MRU list of paths.
/// The `*` sub-key shows all extensions combined.
pub static OPENSAVE_MRU: ArtifactDescriptor = ArtifactDescriptor {
    id: "opensave_mru",
    name: "OpenSaveMRU (Common Dialog)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Paths of files opened or saved via Win32 common dialog boxes; per-extension history",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
};

/// LastVisitedMRU — last folder visited in common dialog per-application.
pub static LASTVISITED_MRU: ArtifactDescriptor = ArtifactDescriptor {
    id: "lastvisited_mru",
    name: "LastVisitedMRU (Common Dialog)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::MruListEx,
    meaning: "Application + last-used folder from common dialog; reveals programs accessing files",
    mitre_techniques: &["T1083"],
    fields: MRU_RECENT_DOCS_FIELDS,
};

/// Windows Prefetch files directory — execution evidence (T1204.002).
///
/// Each `.pf` file records: executable name, run count, last 8 run timestamps,
/// and volume/file references. Requires Prefetch service enabled.
pub static PREFETCH_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "prefetch_dir",
    name: "Prefetch Files Directory",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\Prefetch"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Binary .pf files recording 30-day program execution history with timestamps",
    mitre_techniques: &["T1204.002"],
    fields: DIR_ENTRY_FIELDS,
};

static SRUM_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "app_name",
        value_type: ValueType::Text,
        description: "Application executable path or service name",
        is_uid_component: true,
    },
    FieldSchema {
        name: "user_sid",
        value_type: ValueType::Text,
        description: "SID of the user who ran the application",
        is_uid_component: false,
    },
];

/// System Resource Usage Monitor database — rich execution timeline (Win8+).
///
/// SQLite database at `C:\Windows\System32\sru\SRUDB.dat`. Key tables:
/// `{D10CA2FE-...}` = Application Resource Usage (network, CPU per app),
/// `{5C8CF1C7-...}` = Network Data Usage. Retains ~30-60 days of history.
pub static SRUM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "srum_db",
    name: "SRUM Database (SRUDB.dat)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\sru\SRUDB.dat"),
    scope: DataScope::System,
    os_scope: OsScope::Win8Plus,
    decoder: Decoder::Identity,
    meaning: "Per-app CPU, network, and energy usage records; execution timeline survives log clearing",
    mitre_techniques: &["T1204.002"],
    fields: SRUM_FIELDS,
};

/// Windows Timeline / Activities Cache — cross-device activity history (Win10+).
///
/// SQLite database; `Activity` table records application focus events,
/// file opens, and clipboard content with timestamps.
pub static WINDOWS_TIMELINE: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_timeline",
    name: "Windows Timeline (ActivitiesCache.db)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Application activity timeline including focus time, file access, and clipboard events",
    mitre_techniques: &["T1059", "T1204.002"],
    fields: SRUM_FIELDS,
};

/// PowerShell PSReadLine command history (T1059.001).
///
/// Plain-text file; contains full command history including sensitive strings,
/// filenames, and lateral movement commands typed interactively.
pub static POWERSHELL_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_history",
    name: "PowerShell PSReadLine History",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
    scope: DataScope::User,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Line-by-line PowerShell interactive command history; attackers often clear this",
    mitre_techniques: &["T1059.001", "T1552"],
    fields: FILE_PATH_FIELDS,
};

/// Recycle Bin ($I metadata files) — deletion evidence (T1070.004).
///
/// Each `$I{RAND}` file (8 bytes header + original path) records file size,
/// deletion timestamp, and original full path of the deleted file.
pub static RECYCLE_BIN: ArtifactDescriptor = ArtifactDescriptor {
    id: "recycle_bin",
    name: "Recycle Bin ($I Metadata)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\$Recycle.Bin\*"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "$I files reveal original path and deletion time even after Recycle Bin is emptied",
    mitre_techniques: &["T1070.004", "T1083"],
    fields: DIR_ENTRY_FIELDS,
};

/// Windows Explorer Thumbnail Cache — file-access and image evidence.
///
/// Proprietary binary format; contains thumbnails for files browsed via
/// Explorer, including since-deleted images/documents.
pub static THUMBCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "thumbcache",
    name: "Explorer Thumbnail Cache",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Windows\Explorer"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Cached thumbnails including deleted files; proves files were viewed via Explorer",
    mitre_techniques: &["T1083"],
    fields: DIR_ENTRY_FIELDS,
};

/// Windows Search database — indexed file/content search history.
///
/// ESE/JET database at the system level recording filenames, content excerpts,
/// and metadata for all indexed items. Survives file deletion.
pub static SEARCH_DB_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "search_db_user",
    name: "Windows Search Database (Windows.db)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "ESE database of indexed file metadata; reveals filenames and content even after deletion",
    mitre_techniques: &["T1083"],
    fields: FILE_PATH_FIELDS,
};

// ── Windows credential artifacts ──────────────────────────────────────────

static DPAPI_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "guid",
    value_type: ValueType::Text,
    description: "GUID filename of the DPAPI master key or credential blob",
    is_uid_component: true,
}];

/// DPAPI User Master Keys — key material protecting all user-encrypted data.
///
/// Each file is named by a GUID; the content is the DPAPI master key encrypted
/// with the user's password hash. Decrypting unlocks all DPAPI-protected secrets.
pub static DPAPI_MASTERKEY_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_masterkey_user",
    name: "DPAPI User Master Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Protect\*"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Master keys protecting all DPAPI-encrypted user secrets (credentials, browser passwords, WiFi PSKs)",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
};

/// DPAPI Credential Blobs (Local) — encrypted credential store entries.
///
/// GUID-named binary files; each contains a DPAPI-encrypted credential blob
/// protecting a username/password pair for a network resource or application.
pub static DPAPI_CRED_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_cred_user",
    name: "DPAPI Credential Blobs (Local)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Credentials"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "DPAPI-encrypted credential blobs for network resources; decryptable with DPAPI master key",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
};

/// DPAPI Credential Blobs (Roaming) — roaming profile credential store.
pub static DPAPI_CRED_ROAMING: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_cred_roaming",
    name: "DPAPI Credential Blobs (Roaming)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Microsoft\Credentials"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Roaming DPAPI credential blobs; same structure as Local, synced across domain machines",
    mitre_techniques: &["T1555.004"],
    fields: DPAPI_FIELDS,
};

static VAULT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "policy_file",
        value_type: ValueType::Text,
        description: ".vpol policy file containing encryption key material",
        is_uid_component: false,
    },
    FieldSchema {
        name: "vcrd_file",
        value_type: ValueType::Text,
        description: ".vcrd credential file containing the encrypted credential",
        is_uid_component: true,
    },
];

/// Windows Vault (User) — Windows Credential Manager per-user vault.
///
/// `.vpol` file stores encrypted vault key; `.vcrd` files store individual
/// credentials. Credential Manager UI entries live here.
pub static WINDOWS_VAULT_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_vault_user",
    name: "Windows Vault (User)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Microsoft\Vault"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Per-user Credential Manager vault (.vpol + .vcrd); contains WEB and WINDOWS saved credentials",
    mitre_techniques: &["T1555.004"],
    fields: VAULT_FIELDS,
};

/// Windows Vault (System) — system-wide Windows Credential Manager vault.
pub static WINDOWS_VAULT_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_vault_system",
    name: "Windows Vault (System)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Vault"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-level Windows Credential Manager vault; contains machine-scoped credentials",
    mitre_techniques: &["T1555.004"],
    fields: VAULT_FIELDS,
};

static RDP_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "username_hint",
    value_type: ValueType::Text,
    description: "Last username used to connect to this RDP server",
    is_uid_component: false,
}];

/// RDP Saved Server Connections — lateral movement evidence (T1021.001).
///
/// Each sub-key is a hostname/IP; the `UsernameHint` value shows the username
/// used for that connection. Evidence of RDP-based lateral movement.
pub static RDP_CLIENT_SERVERS: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_client_servers",
    name: "RDP Client Saved Servers",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Terminal Server Client\Servers",
    value_name: Some("UsernameHint"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Hostnames and usernames of previously-connected RDP servers; lateral movement evidence",
    mitre_techniques: &["T1021.001"],
    fields: RDP_FIELDS,
};

static RDP_MRU_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "server",
    value_type: ValueType::Text,
    description: "RDP server address from the most-recently-used list",
    is_uid_component: true,
}];

/// RDP Client Default MRU — ordered list of recently connected RDP servers.
pub static RDP_CLIENT_DEFAULT: ArtifactDescriptor = ArtifactDescriptor {
    id: "rdp_client_default",
    name: "RDP Client Default MRU",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Software\Microsoft\Terminal Server Client\Default",
    value_name: None,
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "MRU0-MRU9 ordered list of RDP server addresses; confirms specific hosts were targeted",
    mitre_techniques: &["T1021.001"],
    fields: RDP_MRU_FIELDS,
};

static NTDS_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "path",
    value_type: ValueType::Text,
    description: "Full path to the NTDS.dit file",
    is_uid_component: true,
}];

/// NTDS.dit — Active Directory database (DC only) (T1003.003).
///
/// Contains all domain user account hashes. Extracting and cracking these
/// grants access to every domain account. Requires VSS or offline access.
pub static NTDS_DIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "ntds_dit",
    name: "Active Directory Database (NTDS.dit)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\NTDS\NTDS.dit"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "Domain controller AD database; contains NTLM hashes for all domain accounts",
    mitre_techniques: &["T1003.003"],
    fields: NTDS_FIELDS,
};

static BROWSER_CRED_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "origin_url",
        value_type: ValueType::Text,
        description: "URL the credential is associated with",
        is_uid_component: true,
    },
    FieldSchema {
        name: "username_value",
        value_type: ValueType::Text,
        description: "Saved username",
        is_uid_component: false,
    },
];

/// Chrome/Edge Login Data — SQLite database of saved browser passwords (T1555.003).
pub static CHROME_LOGIN_DATA: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_login_data",
    name: "Chrome/Edge Login Data (SQLite)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "SQLite DB with DPAPI-encrypted passwords for saved Chrome/Edge credentials",
    mitre_techniques: &["T1555.003"],
    fields: BROWSER_CRED_FIELDS,
};

static FIREFOX_CRED_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "hostname",
    value_type: ValueType::Text,
    description: "Hostname the Firefox credential is associated with",
    is_uid_component: true,
}];

/// Firefox logins.json — JSON credential store (T1555.003).
///
/// NSS3-encrypted credentials; decryptable with `key4.db` and user's Firefox password.
pub static FIREFOX_LOGINS: ArtifactDescriptor = ArtifactDescriptor {
    id: "firefox_logins",
    name: "Firefox logins.json",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json"),
    scope: DataScope::User,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "NSS3-encrypted Firefox saved credentials; decryptable with key4.db and master password",
    mitre_techniques: &["T1555.003"],
    fields: FIREFOX_CRED_FIELDS,
};

static WIFI_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "ssid",
        value_type: ValueType::Text,
        description: "WiFi network SSID (network name)",
        is_uid_component: true,
    },
    FieldSchema {
        name: "key_material",
        value_type: ValueType::Text,
        description: "Pre-shared key or 802.1X EAP credentials (may be DPAPI-encrypted)",
        is_uid_component: false,
    },
];

/// Wireless Network Profiles — contains PSKs for previously joined networks (T1552.001).
///
/// XML files; `<keyMaterial>` field may contain the plaintext PSK or a
/// DPAPI-encrypted blob depending on profile type.
pub static WIFI_PROFILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "wifi_profiles",
    name: "Wireless Network Profiles (WLAN)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"),
    scope: DataScope::System,
    os_scope: OsScope::All,
    decoder: Decoder::Identity,
    meaning: "XML profiles for previously joined WiFi networks; may contain plaintext PSKs",
    mitre_techniques: &["T1552.001"],
    fields: WIFI_FIELDS,
};

// ═══════════════════════════════════════════════════════════════════════════
// Batch D — Linux persistence / execution / credential artifacts
// ═══════════════════════════════════════════════════════════════════════════

// ── Shared Linux field schemas ────────────────────────────────────────────

/// Cron / script line — single scheduled command or shell line.
static CRON_LINE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "schedule_line",
    value_type: ValueType::Text,
    description: "Cron schedule expression and command, or shell script line",
    is_uid_component: false,
}];

/// SSH public key entry.
static SSH_KEY_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "public_key",
    value_type: ValueType::Text,
    description: "SSH public key entry (key-type base64 comment)",
    is_uid_component: true,
}];

/// Linux account entry (colon-delimited fields).
static ACCOUNT_FIELDS: &[FieldSchema] = &[
    FieldSchema {
        name: "username",
        value_type: ValueType::Text,
        description: "Account username",
        is_uid_component: true,
    },
    FieldSchema {
        name: "uid",
        value_type: ValueType::UnsignedInt,
        description: "Numeric user ID (0 = root)",
        is_uid_component: false,
    },
];

/// Log line / journal entry.
static LOG_LINE_FIELDS: &[FieldSchema] = &[FieldSchema {
    name: "log_line",
    value_type: ValueType::Text,
    description: "Log line or structured journal entry",
    is_uid_component: false,
}];

// ── Linux persistence: cron ───────────────────────────────────────────────

/// System-wide crontab at `/etc/crontab` (T1053.003).
///
/// Format: `minute hour dom month dow user command`. Field `user` distinguishes
/// this from per-user crontabs. Any non-root `user` with unusual commands is suspicious.
pub static LINUX_CRONTAB_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_crontab_system",
    name: "System Crontab (/etc/crontab)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/crontab"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "System-wide scheduled job definitions; user field allows cross-account execution",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
};

/// Drop-in cron jobs directory `/etc/cron.d/` (T1053.003).
///
/// Files here follow the same format as `/etc/crontab` (with user field).
/// Attackers drop files here for system-level persistence without editing crontab.
pub static LINUX_CRON_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_cron_d",
    name: "Cron Drop-in Directory (/etc/cron.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/cron.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Drop-in cron files with full crontab format; easy to add without touching crontab",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
};

/// Periodic cron directories (daily/hourly/weekly/monthly) (T1053.003).
///
/// Scripts placed here are executed by run-parts at the named interval.
/// No schedule expression needed — just a plain executable script.
pub static LINUX_CRON_PERIODIC: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_cron_periodic",
    name: "Cron Periodic Directories (/etc/cron.{daily,hourly,weekly,monthly}/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/cron.daily"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Shell scripts executed periodically by crond/anacron; no schedule syntax required",
    mitre_techniques: &["T1053.003"],
    fields: DIR_ENTRY_FIELDS,
};

/// Per-user crontab spool at `/var/spool/cron/crontabs/{user}` (T1053.003).
///
/// Each file is owned by and runs commands as the named user.
/// `crontab -e` edits this file. Direct edits by root are possible.
pub static LINUX_USER_CRONTAB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_user_crontab",
    name: "Per-User Crontab Spool",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/spool/cron/crontabs/*"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-user scheduled jobs; attacker can set up recurring execution without admin",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
};

/// Anacron configuration at `/etc/anacrontab`.
///
/// Anacron runs jobs that were missed due to system downtime — useful for
/// laptops. Format: `period delay job-id command`.
pub static LINUX_ANACRONTAB: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_anacrontab",
    name: "Anacrontab (/etc/anacrontab)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/anacrontab"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Deferred cron jobs for irregular uptime; period-based rather than time-based",
    mitre_techniques: &["T1053.003"],
    fields: CRON_LINE_FIELDS,
};

// ── Linux persistence: systemd ────────────────────────────────────────────

/// System-level systemd service units (T1543.002).
///
/// `.service` files in `/etc/systemd/system/` (admin-installed, highest priority)
/// or `/lib/systemd/system/` (package-installed). Key fields: `ExecStart`,
/// `WantedBy`, `After`. Malicious units often `WantedBy=multi-user.target`.
pub static LINUX_SYSTEMD_SYSTEM_UNIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_system_unit",
    name: "systemd System Service Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/systemd/system"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Service definitions executed as root at boot; WantedBy=multi-user.target = auto-start",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
};

/// Per-user systemd service units (T1543.002).
///
/// Stored in `~/.config/systemd/user/*.service`; executed as the user's
/// session starts. No root required. `systemctl --user enable` activates.
pub static LINUX_SYSTEMD_USER_UNIT: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_user_unit",
    name: "systemd User Service Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/systemd/user"),
    scope: DataScope::User,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "User-scope service definitions; executed without root on user login",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
};

/// systemd timer units — cron-like scheduling (T1053.006).
///
/// `.timer` files trigger associated `.service` units on a schedule.
/// More flexible than cron: supports calendar expressions and monotonic timers.
pub static LINUX_SYSTEMD_TIMER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_systemd_timer",
    name: "systemd Timer Units",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/systemd/system"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Timer-based scheduled execution; malicious timers trigger services on a schedule",
    mitre_techniques: &["T1053.006"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux persistence: init / rc.local ───────────────────────────────────

/// `/etc/rc.local` — legacy startup script (T1037.004).
///
/// Executed at the end of each multiuser runlevel. Still supported on most
/// distros. Must be executable (+x). Any command here runs as root at boot.
pub static LINUX_RC_LOCAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_rc_local",
    name: "rc.local Startup Script",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/rc.local"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Legacy boot-time script executed as root; simple and widely supported",
    mitre_techniques: &["T1037.004"],
    fields: CRON_LINE_FIELDS,
};

/// SysV init scripts directory `/etc/init.d/`.
///
/// Scripts here are executed by the init system at specific runlevels.
/// Symlinks in `/etc/rc{N}.d/` control when they run. Legacy but still present.
pub static LINUX_INIT_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_init_d",
    name: "SysV Init Scripts (/etc/init.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/init.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SysV init scripts; malicious script here runs at boot across reboots",
    mitre_techniques: &["T1543.002"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux persistence: shell startup files ────────────────────────────────

/// `~/.bashrc` — per-user Bash interactive shell startup (T1546.004).
///
/// Sourced for every non-login interactive bash shell. Attackers add aliases,
/// functions, or background processes here. Survives reboots.
pub static LINUX_BASHRC_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bashrc_user",
    name: "User ~/.bashrc",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bashrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on every interactive bash session; persistent aliases, functions, or background processes",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
};

/// `~/.bash_profile` — Bash login shell startup (T1546.004).
pub static LINUX_BASH_PROFILE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bash_profile_user",
    name: "User ~/.bash_profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bash_profile"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on Bash login shells; runs at SSH login and console login",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
};

/// `~/.profile` — POSIX login shell startup.
pub static LINUX_PROFILE_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_user",
    name: "User ~/.profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.profile"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "POSIX login shell startup; sourced by sh, dash, and bash on login",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
};

/// `~/.zshrc` — per-user Zsh interactive startup (T1546.004).
pub static LINUX_ZSHRC_USER: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_zshrc_user",
    name: "User ~/.zshrc",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.zshrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Sourced on every interactive Zsh session; same persistence vector as .bashrc",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
};

/// `/etc/profile` — system-wide login shell startup.
pub static LINUX_PROFILE_SYSTEM: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_system",
    name: "System /etc/profile",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/profile"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "System-wide login shell startup; modifications affect all users",
    mitre_techniques: &["T1546.004"],
    fields: CRON_LINE_FIELDS,
};

/// `/etc/profile.d/` — drop-in system-wide shell startup scripts.
pub static LINUX_PROFILE_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_profile_d",
    name: "System /etc/profile.d/ Drop-ins",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/profile.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Shell scripts sourced by /etc/profile for all users at login; drop-in persistence",
    mitre_techniques: &["T1546.004"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux persistence: dynamic linker ────────────────────────────────────

/// `/etc/ld.so.preload` — system-wide library preload (T1574.006).
///
/// Libraries listed here are loaded into EVERY process before any other
/// library, including setuid binaries. This is a classic rootkit technique.
/// An empty or absent file is normal; ANY entry is highly suspicious.
pub static LINUX_LD_SO_PRELOAD: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ld_so_preload",
    name: "Dynamic Linker Preload (/etc/ld.so.preload)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ld.so.preload"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Libraries preloaded into EVERY process system-wide; standard rootkit hiding mechanism",
    mitre_techniques: &["T1574.006"],
    fields: CRON_LINE_FIELDS,
};

/// `/etc/ld.so.conf.d/` — linker search path configuration (T1574.006).
///
/// Adding a directory containing malicious `.so` files here allows library
/// hijacking without needing LD_PRELOAD.
pub static LINUX_LD_SO_CONF_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ld_so_conf_d",
    name: "Linker Config Directory (/etc/ld.so.conf.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ld.so.conf.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Library search path config; malicious entry adds attacker directory to ldconfig paths",
    mitre_techniques: &["T1574.006"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux persistence: SSH ────────────────────────────────────────────────

/// SSH authorized_keys — persistent backdoor public keys (T1098.004).
///
/// Any public key listed here allows passwordless SSH login as the owner.
/// Attackers add their key for persistent remote access.
pub static LINUX_SSH_AUTHORIZED_KEYS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_authorized_keys",
    name: "SSH authorized_keys",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/authorized_keys"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Public keys permitting passwordless SSH login; attacker key = permanent backdoor",
    mitre_techniques: &["T1098.004"],
    fields: SSH_KEY_FIELDS,
};

// ── Linux persistence: PAM / privilege / kernel ───────────────────────────

/// `/etc/pam.d/` — PAM module configuration (T1556.003).
///
/// Each file configures authentication for a service (e.g., `sshd`, `sudo`,
/// `su`). Replacing `pam_unix.so` or adding a malicious module intercepts
/// ALL authentication for that service.
pub static LINUX_PAM_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_pam_d",
    name: "PAM Configuration (/etc/pam.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/pam.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "PAM module configs per service; malicious module intercepts and logs all passwords",
    mitre_techniques: &["T1556.003"],
    fields: DIR_ENTRY_FIELDS,
};

/// `/etc/sudoers.d/` — drop-in sudoers rules (T1548.003).
///
/// `NOPASSWD` entries allow sudo without password. Attackers add entries for
/// specific commands or ALL commands without password prompting.
pub static LINUX_SUDOERS_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sudoers_d",
    name: "Sudoers Drop-ins (/etc/sudoers.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/sudoers.d"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Drop-in sudoers rules; NOPASSWD entries enable privilege escalation without credentials",
    mitre_techniques: &["T1548.003"],
    fields: DIR_ENTRY_FIELDS,
};

/// `/etc/modules-load.d/` — kernel modules loaded at boot (T1547.006).
///
/// Each `.conf` file lists module names to load. Attackers register a
/// rootkit or malicious kernel module here for persistent kernel-level access.
pub static LINUX_MODULES_LOAD_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_modules_load_d",
    name: "Kernel Module Load Config (/etc/modules-load.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/modules-load.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Kernel modules auto-loaded at boot; rootkit module here = persistent kernel access",
    mitre_techniques: &["T1547.006"],
    fields: DIR_ENTRY_FIELDS,
};

/// `/etc/update-motd.d/` — dynamic MOTD scripts executed on login (Debian/Ubuntu).
///
/// Every script here runs as root at SSH login to generate the MOTD.
/// A persistent backdoor can be hidden here as it looks like a status script.
pub static LINUX_MOTD_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_motd_d",
    name: "Dynamic MOTD Scripts (/etc/update-motd.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/update-motd.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "Scripts run as root at SSH login for MOTD generation; covert execution vector",
    mitre_techniques: &["T1037.004"],
    fields: DIR_ENTRY_FIELDS,
};

/// `/etc/udev/rules.d/` — udev device event rules (T1546).
///
/// Rules can execute commands when devices are connected. An attacker can
/// create a rule that runs a payload whenever a USB is inserted or a network
/// interface comes up.
pub static LINUX_UDEV_RULES_D: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_udev_rules_d",
    name: "udev Rules (/etc/udev/rules.d/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/udev/rules.d"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Device event rules; RUN+= directive executes payload on device attach/detach",
    mitre_techniques: &["T1546"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux execution evidence ──────────────────────────────────────────────

/// `~/.bash_history` — Bash interactive command history (T1059.004).
///
/// Contains commands entered in interactive Bash sessions. Attackers often
/// clear this with `history -c` or `unset HISTFILE`. An absent or empty file
/// is itself suspicious.
pub static LINUX_BASH_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_bash_history",
    name: "Bash History (~/.bash_history)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.bash_history"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Interactive Bash command history; reveals lateral movement, exfil, and recon commands",
    mitre_techniques: &["T1059.004", "T1552"],
    fields: CRON_LINE_FIELDS,
};

/// `~/.zsh_history` — Zsh interactive command history.
pub static LINUX_ZSH_HISTORY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_zsh_history",
    name: "Zsh History (~/.zsh_history)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.zsh_history"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Interactive Zsh command history; extended format optionally includes timestamps",
    mitre_techniques: &["T1059.004", "T1552"],
    fields: CRON_LINE_FIELDS,
};

/// `/var/log/wtmp` — binary successful login history (T1078).
///
/// Utmp-format binary file; `last` command reads it. Records login, logout,
/// reboot, and shutdown events. Tampered by log-clearing tools.
pub static LINUX_WTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_wtmp",
    name: "Login History (/var/log/wtmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/wtmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary record of all successful logins/logouts/reboots; evidence of valid-account abuse",
    mitre_techniques: &["T1078", "T1021.004"],
    fields: LOG_LINE_FIELDS,
};

/// `/var/log/btmp` — binary failed login attempts.
///
/// Utmp-format binary; `lastb` command reads it. Brute-force evidence.
pub static LINUX_BTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_btmp",
    name: "Failed Login Attempts (/var/log/btmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/btmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary record of failed authentication attempts; brute-force and credential-stuffing evidence",
    mitre_techniques: &["T1110"],
    fields: LOG_LINE_FIELDS,
};

/// `/var/log/lastlog` — binary last-login-per-UID database.
///
/// Fixed-offset binary file indexed by UID. `lastlog` command reads it.
/// Each entry records last login time and source IP.
pub static LINUX_LASTLOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_lastlog",
    name: "Last Login Database (/var/log/lastlog)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/lastlog"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Per-UID last-login record including source IP; never-logged-in vs recent entries",
    mitre_techniques: &["T1078"],
    fields: LOG_LINE_FIELDS,
};

/// `/var/log/auth.log` — authentication and sudo event log (Debian/Ubuntu).
///
/// Contains PAM authentication events, sudo commands, SSH logins, and su usage.
/// Red Hat equivalent: `/var/log/secure`.
pub static LINUX_AUTH_LOG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_auth_log",
    name: "Auth Log (/var/log/auth.log)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/auth.log"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxDebian,
    decoder: Decoder::Identity,
    meaning: "PAM auth events, SSH logins, sudo commands, su usage; primary lateral-movement log",
    mitre_techniques: &["T1078", "T1548.003"],
    fields: LOG_LINE_FIELDS,
};

/// systemd journal directory `/var/log/journal/`.
///
/// Binary journal files; `journalctl` reads them. Contains all system and
/// service log messages. More tamper-resistant than syslog text files.
pub static LINUX_JOURNAL_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_journal_dir",
    name: "systemd Journal (/var/log/journal/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/log/journal"),
    scope: DataScope::System,
    os_scope: OsScope::LinuxSystemd,
    decoder: Decoder::Identity,
    meaning: "Structured binary system journal; includes boot IDs, service crashes, and audit events",
    mitre_techniques: &["T1078", "T1059.004"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Linux credential artifacts ────────────────────────────────────────────

/// `/etc/passwd` — local user account database (T1087.001).
///
/// World-readable; fields: `user:x:uid:gid:gecos:home:shell`.
/// UID=0 duplicates, unusual shells (`/bin/bash` for service accounts),
/// and accounts with homedir `/` are suspicious.
pub static LINUX_PASSWD: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_passwd",
    name: "User Account Database (/etc/passwd)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/passwd"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Local user enumeration; UID=0 duplicates or unusual shells indicate backdoor accounts",
    mitre_techniques: &["T1087.001", "T1136.001"],
    fields: ACCOUNT_FIELDS,
};

/// `/etc/shadow` — password hash database (T1003.008).
///
/// Root-readable only. Hash formats: `$1$`=MD5, `$5$`=SHA256, `$6$`=SHA512,
/// `$y$`=yescrypt (modern). `*` or `!` prefix = locked account.
pub static LINUX_SHADOW: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_shadow",
    name: "Shadow Password File (/etc/shadow)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/shadow"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Password hashes for all local accounts; crackable offline once read",
    mitre_techniques: &["T1003.008"],
    fields: ACCOUNT_FIELDS,
};

/// SSH private key files — stolen keys enable impersonation (T1552.004).
///
/// Unencrypted keys (no `Proc-Type: ENCRYPTED` header) are immediately usable.
/// Encrypted keys require the passphrase but are still high-value targets.
pub static LINUX_SSH_PRIVATE_KEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_private_key",
    name: "SSH Private Keys (~/.ssh/id_*)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/id_*"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Private key material for SSH authentication; unencrypted keys = immediate lateral movement",
    mitre_techniques: &["T1552.004"],
    fields: SSH_KEY_FIELDS,
};

/// `~/.ssh/known_hosts` — previously connected SSH server fingerprints (T1021.004).
///
/// Records host key fingerprints of servers the user has connected to.
/// Reveals lateral movement destinations and external access patterns.
pub static LINUX_SSH_KNOWN_HOSTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_ssh_known_hosts",
    name: "SSH Known Hosts (~/.ssh/known_hosts)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.ssh/known_hosts"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Previously-connected SSH server fingerprints; lateral movement destination history",
    mitre_techniques: &["T1021.004", "T1083"],
    fields: SSH_KEY_FIELDS,
};

/// `~/.gnupg/private-keys-v1.d/` — GnuPG private key store (T1552.004).
///
/// Modern GnuPG (2.1+) stores one `.key` file per secret key.
/// Exporting these enables code-signing forgery and decryption of PGP messages.
pub static LINUX_GNUPG_PRIVATE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gnupg_private",
    name: "GnuPG Private Key Store (~/.gnupg/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.gnupg"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GnuPG private keys; enables message decryption and code-signing forgery",
    mitre_techniques: &["T1552.004"],
    fields: DPAPI_FIELDS,
};

/// `~/.aws/credentials` — AWS access key material (T1552.001).
///
/// INI-format file with `aws_access_key_id` and `aws_secret_access_key`.
/// May also contain `aws_session_token` for temporary credentials.
pub static LINUX_AWS_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_aws_credentials",
    name: "AWS Credentials (~/.aws/credentials)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.aws/credentials"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "AWS long-term or temporary credentials; enables cloud infrastructure compromise",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

/// `~/.docker/config.json` — Docker registry auth tokens (T1552.001).
///
/// Contains base64-encoded `auth` tokens or `credsStore` references for
/// container registries. Grants push/pull access to private registries.
pub static LINUX_DOCKER_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_docker_config",
    name: "Docker Config (~/.docker/config.json)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.docker/config.json"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Docker registry credentials; enables container image exfil or malicious image push",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

// ── Batch E — Windows execution / persistence / credential ───────────────────

// ── Execution evidence ────────────────────────────────────────────────────────

pub static LNK_FILES: ArtifactDescriptor = ArtifactDescriptor {
    id: "lnk_files",
    name: "LNK / Shell Link Recent Files",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Shell Link (.lnk) files record target path, MAC timestamps, volume serial, and \
              NetBIOS host — evidence of file access even after target deletion. T1547.009.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
};

pub static JUMP_LIST_AUTO: ArtifactDescriptor = ArtifactDescriptor {
    id: "jump_list_auto",
    name: "Jump Lists — AutomaticDestinations",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "OLE Compound Document storing per-AppID MRU lists; reveals recently opened files \
              for each application including timestamps and target metadata.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
};

pub static JUMP_LIST_CUSTOM: ArtifactDescriptor = ArtifactDescriptor {
    id: "jump_list_custom",
    name: "Jump Lists — CustomDestinations",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Application-pinned and custom jump list entries; may persist after file deletion, \
              revealing attacker-pinned tools or exfiltrated document access.",
    mitre_techniques: &["T1547.009", "T1070.004"],
    fields: DIR_ENTRY_FIELDS,
};

pub static EVTX_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "evtx_dir",
    name: "Windows Event Log Directory (EVTX)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\winevt\Logs\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Binary EVTX log files — Security.evtx (4624/4625/4688), System.evtx, \
              PowerShell/Operational.evtx. Primary execution, logon, and process-creation record.",
    mitre_techniques: &["T1070.001", "T1059.001"],
    fields: DIR_ENTRY_FIELDS,
};

pub static USN_JOURNAL: ArtifactDescriptor = ArtifactDescriptor {
    id: "usn_journal",
    name: "USN Journal ($UsnJrnl:$J)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"\\.\C:\$Extend\$UsnJrnl:$J"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "NTFS change journal records file create/delete/rename operations with USN sequence \
              number; persists even after file deletion, proving prior file existence.",
    mitre_techniques: &["T1070.004", "T1059"],
    fields: DIR_ENTRY_FIELDS,
};

// ── Persistence ───────────────────────────────────────────────────────────────

pub static WMI_MOF_DIR: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_mof_dir",
    name: "WMI MOF Subscription Repository",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\wbem\Repository\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "WMI CIM repository stores EventFilter, EventConsumer, and FilterToConsumerBinding \
              objects; persistence survives reboots and is invisible to registry-only tools.",
    mitre_techniques: &["T1546.003"],
    fields: DIR_ENTRY_FIELDS,
};

pub static BITS_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "bits_db",
    name: "BITS Job Queue Database",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Network\Downloader\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Background Intelligent Transfer Service queue DB (qmgr0.dat); records download \
              jobs including URL, destination, and command-to-notify — abused for stealthy malware staging.",
    mitre_techniques: &["T1197"],
    fields: DIR_ENTRY_FIELDS,
};

static WMI_SUB_FIELDS: &[FieldSchema] = &[
    FieldSchema { name: "filter_name", description: "WMI EventFilter name", value_type: ValueType::Text, is_uid_component: true },
    FieldSchema { name: "consumer_type", description: "Consumer type (Script/CommandLine)", value_type: ValueType::Text, is_uid_component: false },
    FieldSchema { name: "consumer_value", description: "Script or command executed on trigger", value_type: ValueType::Text, is_uid_component: false },
    FieldSchema { name: "query", description: "WQL query that triggers the subscription", value_type: ValueType::Text, is_uid_component: false },
];

pub static WMI_SUBSCRIPTIONS: ArtifactDescriptor = ArtifactDescriptor {
    id: "wmi_subscriptions",
    name: "WMI Event Subscriptions (Registry)",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSoftware),
    key_path: r"Microsoft\WBEM\ESS\//./root/subscription",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MultiSz,
    meaning: "Registry-side index of WMI subscriptions; cross-reference with MOF repository for \
              complete picture of WMI-based persistence.",
    mitre_techniques: &["T1546.003"],
    fields: WMI_SUB_FIELDS,
};

pub static LOGON_SCRIPTS: ArtifactDescriptor = ArtifactDescriptor {
    id: "logon_scripts",
    name: "Logon Scripts (UserInitMprLogonScript)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::NtUser),
    key_path: r"Environment",
    value_name: Some("UserInitMprLogonScript"),
    file_path: None,
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Script executed at logon via WinLogon; per-user value allowing unprivileged \
              persistence that survives password resets.",
    mitre_techniques: &["T1037.001"],
    fields: PERSIST_CMD_FIELDS,
};

pub static WINSOCK_LSP: ArtifactDescriptor = ArtifactDescriptor {
    id: "winsock_lsp",
    name: "Winsock Layered Service Provider",
    artifact_type: ArtifactType::RegistryKey,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9",
    value_name: None,
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "LSP DLLs intercept all Winsock traffic; malicious LSPs can log credentials from \
              plaintext protocols. Rare but high-signal indicator of network interception.",
    mitre_techniques: &["T1547.010"],
    fields: DLL_FIELDS,
};

pub static APPSHIM_DB: ArtifactDescriptor = ArtifactDescriptor {
    id: "appshim_db",
    name: "Application Shim Database",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\apppatch\Custom\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Custom SDB shim databases; attackers inject shims to redirect API calls, \
              disable security checks, or load malicious DLLs without modifying the target binary.",
    mitre_techniques: &["T1546.011"],
    fields: DIR_ENTRY_FIELDS,
};

pub static PASSWORD_FILTER_DLL: ArtifactDescriptor = ArtifactDescriptor {
    id: "password_filter_dll",
    name: "Password Filter DLL (Notification Packages)",
    artifact_type: ArtifactType::RegistryValue,
    hive: Some(HiveTarget::HklmSystem),
    key_path: r"CurrentControlSet\Control\Lsa",
    value_name: Some("Notification Packages"),
    file_path: None,
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::MultiSz,
    meaning: "DLLs registered here receive cleartext passwords during every password change; \
              malicious filter captures and exfiltrates credentials.",
    mitre_techniques: &["T1556.002"],
    fields: DLL_FIELDS,
};

pub static OFFICE_NORMAL_DOTM: ArtifactDescriptor = ArtifactDescriptor {
    id: "office_normal_dotm",
    name: "Office Normal Template (Normal.dotm)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Templates\Normal.dotm"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Global Word template auto-loaded on every document open; malicious macros \
              embedded here achieve persistence across all Word sessions.",
    mitre_techniques: &["T1137.001"],
    fields: FILE_PATH_FIELDS,
};

pub static POWERSHELL_PROFILE_ALL: ArtifactDescriptor = ArtifactDescriptor {
    id: "powershell_profile_all",
    name: "PowerShell All-Users Profile (profile.ps1)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "System-wide PowerShell profile executed for every user on every PS session start; \
              SYSTEM-writable, provides privileged persistence without registry modification.",
    mitre_techniques: &["T1546.013"],
    fields: PERSIST_CMD_FIELDS,
};

// ── Credentials ───────────────────────────────────────────────────────────────

pub static DPAPI_SYSTEM_MASTERKEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_system_masterkey",
    name: "DPAPI System Master Key",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "DPAPI master keys for the SYSTEM account; used to decrypt SYSTEM-scope secrets \
              such as LSA secrets, service credentials, and scheduled task credentials.",
    mitre_techniques: &["T1555.004"],
    fields: FILE_PATH_FIELDS,
};

pub static DPAPI_CREDHIST: ArtifactDescriptor = ArtifactDescriptor {
    id: "dpapi_credhist",
    name: "DPAPI CREDHIST File",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Protect\CREDHIST"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Chain of previous DPAPI master key derivation entries; enables decryption of \
              secrets encrypted with old passwords after a password change.",
    mitre_techniques: &["T1555.004"],
    fields: FILE_PATH_FIELDS,
};

pub static CHROME_COOKIES: ArtifactDescriptor = ArtifactDescriptor {
    id: "chrome_cookies",
    name: "Chrome/Edge Cookies (SQLite)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "SQLite database of browser session/authentication cookies; adversaries can replay \
              these to bypass MFA and impersonate authenticated sessions (pass-the-cookie).",
    mitre_techniques: &["T1539", "T1185"],
    fields: FILE_PATH_FIELDS,
};

pub static EDGE_WEBCACHE: ArtifactDescriptor = ArtifactDescriptor {
    id: "edge_webcache",
    name: "IE/Edge Legacy WebCacheV01.dat",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "ESE database recording all IE/Edge Legacy web history, downloads, and cached \
              content; reveals browsing patterns and potential data exfiltration URLs.",
    mitre_techniques: &["T1539", "T1217"],
    fields: FILE_PATH_FIELDS,
};

pub static VPN_RAS_PHONEBOOK: ArtifactDescriptor = ArtifactDescriptor {
    id: "vpn_ras_phonebook",
    name: "VPN Credentials — RAS Phonebook",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\Network\Connections\Pbk\rasphone.pbk"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Plain-text INI phonebook storing VPN connection entries including server address \
              and saved credential references; reveals network pivoting paths.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

pub static WINDOWS_HELLO_NGC: ArtifactDescriptor = ArtifactDescriptor {
    id: "windows_hello_ngc",
    name: "Windows Hello / NGC Folder",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Ngc\"),
    scope: DataScope::System,
    os_scope: OsScope::Win10Plus,
    decoder: Decoder::Identity,
    meaning: "Stores Windows Hello credential provider keys (PIN protectors, biometric keys); \
              compromise reveals authentication material bypassing traditional password forensics.",
    mitre_techniques: &["T1555"],
    fields: FILE_PATH_FIELDS,
};

pub static USER_CERT_PRIVATE_KEY: ArtifactDescriptor = ArtifactDescriptor {
    id: "user_cert_private_key",
    name: "User Certificate Private Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"%APPDATA%\Microsoft\SystemCertificates\My\"),
    scope: DataScope::User,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "DPAPI-protected user certificate private keys for code signing, S/MIME, and \
              smart-card emulation; exfiltration enables impersonation and signing of malicious artifacts.",
    mitre_techniques: &["T1552.004"],
    fields: FILE_PATH_FIELDS,
};

pub static MACHINE_CERT_STORE: ArtifactDescriptor = ArtifactDescriptor {
    id: "machine_cert_store",
    name: "Machine Certificate Private Keys",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some(r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"),
    scope: DataScope::System,
    os_scope: OsScope::Win7Plus,
    decoder: Decoder::Identity,
    meaning: "Machine-scope RSA private keys protected by DPAPI SYSTEM; used for TLS mutual \
              auth, code signing, and IPSec — high-value credential exfiltration target.",
    mitre_techniques: &["T1552.004"],
    fields: FILE_PATH_FIELDS,
};

// ── Batch F — Linux extended credentials / execution ─────────────────────────

pub static LINUX_AT_QUEUE: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_at_queue",
    name: "AT Job Queue (/var/spool/at/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/var/spool/at/"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "One-shot delayed execution jobs from the `at` command; each file contains a shell \
              script to run at a specified time, used for stealthy one-shot persistence.",
    mitre_techniques: &["T1053.001"],
    fields: CRON_LINE_FIELDS,
};

pub static LINUX_SSHD_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_sshd_config",
    name: "SSH Daemon Configuration (/etc/ssh/sshd_config)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/ssh/sshd_config"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SSH server config; look for unauthorized AuthorizedKeysFile overrides, \
              ForceCommand bypass, PermitRootLogin yes, or AllowUsers modifications.",
    mitre_techniques: &["T1098.004", "T1021.004"],
    fields: PERSIST_CMD_FIELDS,
};

pub static LINUX_ETC_GROUP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_etc_group",
    name: "Group Accounts (/etc/group)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/etc/group"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Group membership database; cross-reference with /etc/passwd and sudo log to \
              detect unauthorized group additions (e.g., added to `sudo` or `docker` group).",
    mitre_techniques: &["T1087.001", "T1078.003"],
    fields: ACCOUNT_FIELDS,
};

pub static LINUX_GNOME_KEYRING: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gnome_keyring",
    name: "GNOME Keyring (keyrings/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.local/share/keyrings/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GNOME keyring stores WiFi PSK, SSH passphrases, web service passwords, and \
              browser master passwords encrypted with user login credential.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_KDE_KWALLET: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kde_kwallet",
    name: "KDE KWallet (kwalletd/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.local/share/kwalletd/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "KDE wallet encrypted credential store; stores passwords, SSH keys, and browser \
              credentials for KDE applications.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_CHROME_LOGIN_LINUX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_chrome_login_linux",
    name: "Chrome/Chromium Login Data (Linux)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/google-chrome/Default/Login Data"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "SQLite database of saved Chrome passwords on Linux; encryption key stored in \
              GNOME Keyring or plaintext depending on configuration.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_FIREFOX_LOGINS_LINUX: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_firefox_logins_linux",
    name: "Firefox logins.json (Linux)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.mozilla/firefox/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "JSON-encoded saved Firefox credentials protected by NSS (key4.db); \
              can be decrypted with master password or via memory forensics of the Firefox process.",
    mitre_techniques: &["T1555.003"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_UTMP: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_utmp",
    name: "Current Login Sessions (/run/utmp)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("/run/utmp"),
    scope: DataScope::System,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Binary utmp records of currently logged-in users; cross-reference with wtmp \
              to detect sessions not present in persistent logs (anti-forensics via utmp wiper).",
    mitre_techniques: &["T1078"],
    fields: LOG_LINE_FIELDS,
};

pub static LINUX_GCP_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_gcp_credentials",
    name: "GCP Application Default Credentials",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.config/gcloud/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "GCP access tokens and service account keys stored by gcloud CLI; \
              exfiltration enables cloud resource takeover without password.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_AZURE_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_azure_credentials",
    name: "Azure CLI Credentials (~/.azure/)",
    artifact_type: ArtifactType::Directory,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.azure/"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Azure CLI access tokens and service principal credentials; \
              msal_token_cache.json contains active OAuth tokens enabling lateral movement in Azure.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_KUBE_CONFIG: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_kube_config",
    name: "Kubernetes Config (~/.kube/config)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.kube/config"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "kubectl cluster credentials including bearer tokens, client certificates, \
              and cluster API endpoints; enables full cluster takeover if exfiltrated.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_GIT_CREDENTIALS: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_git_credentials",
    name: "Git Credential Store (~/.git-credentials)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.git-credentials"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Plaintext git credential store: URL + username + PAT/password per line; \
              personal access tokens here can access source repositories and CI/CD pipelines.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

pub static LINUX_NETRC: ArtifactDescriptor = ArtifactDescriptor {
    id: "linux_netrc",
    name: "Netrc Credential File (~/.netrc)",
    artifact_type: ArtifactType::File,
    hive: None,
    key_path: "",
    value_name: None,
    file_path: Some("~/.netrc"),
    scope: DataScope::User,
    os_scope: OsScope::Linux,
    decoder: Decoder::Identity,
    meaning: "Auto-authentication file for ftp, curl, and legacy tools; stores plaintext \
              hostname/login/password triplets, often forgotten and highly sensitive.",
    mitre_techniques: &["T1552.001"],
    fields: FILE_PATH_FIELDS,
};

// ── Global catalog ───────────────────────────────────────────────────────────

/// The global forensic artifact catalog containing all known artifact descriptors.
pub static CATALOG: ForensicCatalog = ForensicCatalog::new(&[
    USERASSIST_EXE,
    USERASSIST_FOLDER,
    RUN_KEY_HKLM_RUN,
    RUN_KEY_HKCU_RUN,
    RUN_KEY_HKCU_RUNONCE,
    RUN_KEY_HKLM_RUNONCE,
    TYPED_URLS,
    TYPED_URLS_TIME,
    PCA_APPLAUNCH_DIC,
    IFEO_DEBUGGER,
    SHELLBAGS_USER,
    AMCACHE_APP_FILE,
    SHIMCACHE,
    BAM_USER,
    DAM_USER,
    SAM_USERS,
    LSA_SECRETS,
    DCC2_CACHE,
    MRU_RECENT_DOCS,
    USB_ENUM,
    MUICACHE,
    APPINIT_DLLS,
    WINLOGON_USERINIT,
    SCREENSAVER_EXE,
    // Batch C — Windows persistence
    WINLOGON_SHELL,
    SERVICES_IMAGEPATH,
    ACTIVE_SETUP_HKLM,
    ACTIVE_SETUP_HKCU,
    COM_HIJACK_CLSID_HKCU,
    APPCERT_DLLS,
    BOOT_EXECUTE,
    LSA_SECURITY_PKGS,
    LSA_AUTH_PKGS,
    PRINT_MONITORS,
    TIME_PROVIDERS,
    NETSH_HELPER_DLLS,
    BROWSER_HELPER_OBJECTS,
    STARTUP_FOLDER_USER,
    STARTUP_FOLDER_SYSTEM,
    SCHEDULED_TASKS_DIR,
    WDIGEST_CACHING,
    // Batch C — Windows execution evidence
    WORDWHEEL_QUERY,
    OPENSAVE_MRU,
    LASTVISITED_MRU,
    PREFETCH_DIR,
    SRUM_DB,
    WINDOWS_TIMELINE,
    POWERSHELL_HISTORY,
    RECYCLE_BIN,
    THUMBCACHE,
    SEARCH_DB_USER,
    // Batch C — Windows credentials
    DPAPI_MASTERKEY_USER,
    DPAPI_CRED_USER,
    DPAPI_CRED_ROAMING,
    WINDOWS_VAULT_USER,
    WINDOWS_VAULT_SYSTEM,
    RDP_CLIENT_SERVERS,
    RDP_CLIENT_DEFAULT,
    NTDS_DIT,
    CHROME_LOGIN_DATA,
    FIREFOX_LOGINS,
    WIFI_PROFILES,
    // Batch D — Linux cron / init persistence
    LINUX_CRONTAB_SYSTEM,
    LINUX_CRON_D,
    LINUX_CRON_PERIODIC,
    LINUX_USER_CRONTAB,
    LINUX_ANACRONTAB,
    // Batch D — Linux systemd persistence
    LINUX_SYSTEMD_SYSTEM_UNIT,
    LINUX_SYSTEMD_USER_UNIT,
    LINUX_SYSTEMD_TIMER,
    // Batch D — Linux SysV init
    LINUX_RC_LOCAL,
    LINUX_INIT_D,
    // Batch D — Linux shell startup persistence
    LINUX_BASHRC_USER,
    LINUX_BASH_PROFILE_USER,
    LINUX_PROFILE_USER,
    LINUX_ZSHRC_USER,
    LINUX_PROFILE_SYSTEM,
    LINUX_PROFILE_D,
    // Batch D — Linux dynamic linker hijack
    LINUX_LD_SO_PRELOAD,
    LINUX_LD_SO_CONF_D,
    // Batch D — Linux SSH persistence
    LINUX_SSH_AUTHORIZED_KEYS,
    // Batch D — Linux auth / privilege escalation
    LINUX_PAM_D,
    LINUX_SUDOERS_D,
    LINUX_MODULES_LOAD_D,
    LINUX_MOTD_D,
    LINUX_UDEV_RULES_D,
    // Batch D — Linux execution evidence
    LINUX_BASH_HISTORY,
    LINUX_ZSH_HISTORY,
    LINUX_WTMP,
    LINUX_BTMP,
    LINUX_LASTLOG,
    LINUX_AUTH_LOG,
    LINUX_JOURNAL_DIR,
    // Batch D — Linux credentials
    LINUX_PASSWD,
    LINUX_SHADOW,
    LINUX_SSH_PRIVATE_KEY,
    LINUX_SSH_KNOWN_HOSTS,
    LINUX_GNUPG_PRIVATE,
    LINUX_AWS_CREDENTIALS,
    LINUX_DOCKER_CONFIG,
    // Batch E — Windows execution evidence
    LNK_FILES,
    JUMP_LIST_AUTO,
    JUMP_LIST_CUSTOM,
    EVTX_DIR,
    USN_JOURNAL,
    // Batch E — Windows persistence
    WMI_MOF_DIR,
    BITS_DB,
    WMI_SUBSCRIPTIONS,
    LOGON_SCRIPTS,
    WINSOCK_LSP,
    APPSHIM_DB,
    PASSWORD_FILTER_DLL,
    OFFICE_NORMAL_DOTM,
    POWERSHELL_PROFILE_ALL,
    // Batch E — Windows credentials
    DPAPI_SYSTEM_MASTERKEY,
    DPAPI_CREDHIST,
    CHROME_COOKIES,
    EDGE_WEBCACHE,
    VPN_RAS_PHONEBOOK,
    WINDOWS_HELLO_NGC,
    USER_CERT_PRIVATE_KEY,
    MACHINE_CERT_STORE,
    // Batch F — Linux extended
    LINUX_AT_QUEUE,
    LINUX_SSHD_CONFIG,
    LINUX_ETC_GROUP,
    LINUX_GNOME_KEYRING,
    LINUX_KDE_KWALLET,
    LINUX_CHROME_LOGIN_LINUX,
    LINUX_FIREFOX_LOGINS_LINUX,
    LINUX_UTMP,
    LINUX_GCP_CREDENTIALS,
    LINUX_AZURE_CREDENTIALS,
    LINUX_KUBE_CONFIG,
    LINUX_GIT_CREDENTIALS,
    LINUX_NETRC,
]);

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FILETIME conversion ──────────────────────────────────────────────

    #[test]
    fn filetime_zero_returns_none() {
        assert_eq!(filetime_to_iso8601(0), None);
    }

    #[test]
    fn filetime_before_unix_epoch_returns_none() {
        // 1600-01-01 is before the Unix epoch offset.
        assert_eq!(filetime_to_iso8601(1), None);
    }

    #[test]
    fn filetime_unix_epoch_is_1970() {
        // Exactly the Unix epoch: 1970-01-01T00:00:00Z
        let ft: u64 = 116_444_736_000_000_000;
        assert_eq!(
            filetime_to_iso8601(ft),
            Some("1970-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn filetime_known_date_2023() {
        // 2023-01-15T10:30:00Z
        // Unix timestamp: 1673778600
        // FILETIME = 1673778600 * 10_000_000 + 116_444_736_000_000_000
        let unix_ts: u64 = 1_673_778_600;
        let ft = unix_ts * 10_000_000 + 116_444_736_000_000_000;
        assert_eq!(
            filetime_to_iso8601(ft),
            Some("2023-01-15T10:30:00Z".to_string())
        );
    }

    // ── ROT13 ────────────────────────────────────────────────────────────

    #[test]
    fn rot13_roundtrip() {
        let s = "Hello, World!";
        assert_eq!(rot13(&rot13(s)), s);
    }

    #[test]
    fn rot13_known_value() {
        assert_eq!(rot13("URYYB"), "HELLO");
    }

    #[test]
    fn rot13_numbers_unchanged() {
        assert_eq!(rot13("12345"), "12345");
    }

    // ── Catalog queries ──────────────────────────────────────────────────

    #[test]
    fn catalog_has_entries() {
        assert!(!CATALOG.list().is_empty());
        assert_eq!(CATALOG.list().len(), 135);
    }

    #[test]
    fn catalog_by_id_userassist() {
        let desc = CATALOG.by_id("userassist_exe").unwrap();
        assert_eq!(desc.name, "UserAssist (EXE)");
        assert_eq!(desc.hive, Some(HiveTarget::NtUser));
        assert_eq!(desc.scope, DataScope::User);
    }

    #[test]
    fn catalog_by_id_missing_returns_none() {
        assert!(CATALOG.by_id("nonexistent").is_none());
    }

    #[test]
    fn catalog_filter_by_hive_ntuser() {
        let q = ArtifactQuery {
            hive: Some(HiveTarget::NtUser),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.len() >= 2); // userassist + typed_urls
        assert!(results.iter().all(|d| d.hive == Some(HiveTarget::NtUser)));
    }

    #[test]
    fn catalog_filter_by_scope_system() {
        let q = ArtifactQuery {
            scope: Some(DataScope::System),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.iter().all(|d| d.scope == DataScope::System));
    }

    #[test]
    fn catalog_filter_by_mitre_technique() {
        let q = ArtifactQuery {
            mitre_technique: Some("T1547.001"),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(!results.is_empty());
        assert!(results.iter().all(|d| d.mitre_techniques.contains(&"T1547.001")));
    }

    #[test]
    fn catalog_filter_by_artifact_type_file() {
        let q = ArtifactQuery {
            artifact_type: Some(ArtifactType::File),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        // Multiple File artifacts now exist (PCA, SRUM, Timeline, PowerShell history,
        // NTDS.dit, Chrome Login Data, Firefox logins, Windows Search DB).
        assert!(!results.is_empty());
        // PCA must still be present.
        assert!(results.iter().any(|d| d.id == "pca_applaunch_dic"));
    }

    #[test]
    fn catalog_filter_empty_query_returns_all() {
        let q = ArtifactQuery::default();
        assert_eq!(CATALOG.filter(&q).len(), CATALOG.list().len());
    }

    #[test]
    fn catalog_filter_by_id() {
        let q = ArtifactQuery {
            id: Some("typed_urls"),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "typed_urls");
    }

    #[test]
    fn catalog_filter_combined_scope_and_hive() {
        let q = ArtifactQuery {
            scope: Some(DataScope::User),
            hive: Some(HiveTarget::NtUser),
            ..Default::default()
        };
        let results = CATALOG.filter(&q);
        assert!(results.len() >= 2);
    }

    // ── Decoder: Identity ────────────────────────────────────────────────

    #[test]
    fn decode_identity_utf8() {
        let rec = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "MyApp", b"C:\\Program Files\\app.exe")
            .unwrap();
        assert_eq!(rec.artifact_id, "run_key_hklm");
        assert_eq!(
            rec.fields,
            vec![(
                "value",
                ArtifactValue::Text("C:\\Program Files\\app.exe".to_string())
            )]
        );
    }

    #[test]
    fn decode_identity_empty_raw() {
        let rec = CATALOG.decode(&RUN_KEY_HKLM_RUN, "", b"").unwrap();
        assert_eq!(
            rec.fields,
            vec![("value", ArtifactValue::Text(String::new()))]
        );
    }

    #[test]
    fn decode_identity_invalid_utf8() {
        let err = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "", &[0xFF, 0xFE, 0x80])
            .unwrap_err();
        assert_eq!(err, DecodeError::InvalidUtf8);
    }

    // ── Decoder: Rot13NameWithBinaryValue (UserAssist) ───────────────────

    #[test]
    fn decode_userassist_valid() {
        // Build a 72-byte UserAssist binary value:
        // bytes 4-7: run_count = 5
        // bytes 8-11: focus_count = 3
        // bytes 12-15: focus_duration_ms = 10000
        // bytes 60-67: FILETIME for 2023-01-15T10:30:00Z
        let mut raw = vec![0u8; 72];
        raw[4..8].copy_from_slice(&5u32.to_le_bytes());
        raw[8..12].copy_from_slice(&3u32.to_le_bytes());
        raw[12..16].copy_from_slice(&10000u32.to_le_bytes());
        let ft: u64 = 1_673_778_600 * 10_000_000 + 116_444_736_000_000_000;
        raw[60..68].copy_from_slice(&ft.to_le_bytes());

        let rot13_name = rot13("C:\\Program Files\\notepad.exe");
        let rec = CATALOG.decode(&USERASSIST_EXE, &rot13_name, &raw).unwrap();

        assert_eq!(rec.artifact_id, "userassist_exe");
        assert_eq!(rec.scope, DataScope::User);
        assert_eq!(
            rec.fields[0],
            (
                "program",
                ArtifactValue::Text("C:\\Program Files\\notepad.exe".to_string())
            )
        );
        assert_eq!(
            rec.fields[1],
            ("run_count", ArtifactValue::UnsignedInt(5))
        );
        assert_eq!(
            rec.fields[2],
            ("focus_count", ArtifactValue::UnsignedInt(3))
        );
        assert_eq!(
            rec.fields[3],
            ("focus_duration_ms", ArtifactValue::UnsignedInt(10000))
        );
        assert_eq!(
            rec.fields[4],
            (
                "last_run",
                ArtifactValue::Timestamp("2023-01-15T10:30:00Z".to_string())
            )
        );
        assert_eq!(
            rec.timestamp,
            Some("2023-01-15T10:30:00Z".to_string())
        );
    }

    #[test]
    fn decode_userassist_buffer_too_short() {
        let raw = vec![0u8; 16]; // need at least 68 for last_run field
        let err = CATALOG
            .decode(&USERASSIST_EXE, "test", &raw)
            .unwrap_err();
        match err {
            DecodeError::FieldOutOfBounds { field, .. } => {
                assert_eq!(field, "last_run");
            }
            other => panic!("expected FieldOutOfBounds, got: {other:?}"),
        }
    }

    #[test]
    fn decode_userassist_zero_filetime() {
        // All zeros: FILETIME at offset 60 is zero -> Null
        let raw = vec![0u8; 72];
        let rec = CATALOG.decode(&USERASSIST_EXE, "grfg", &raw).unwrap();
        assert_eq!(rec.fields[4], ("last_run", ArtifactValue::Null));
        assert_eq!(rec.timestamp, None);
    }

    // ── Decoder: PipeDelimited ───────────────────────────────────────────

    #[test]
    fn decode_pipe_delimited_from_name() {
        let rec = CATALOG
            .decode(
                &PCA_APPLAUNCH_DIC,
                r"C:\Windows\notepad.exe|2023-01-15 10:30:00",
                b"",
            )
            .unwrap();
        assert_eq!(rec.artifact_id, "pca_applaunch_dic");
        assert_eq!(
            rec.fields[0],
            (
                "exe_path",
                ArtifactValue::Text(r"C:\Windows\notepad.exe".to_string())
            )
        );
        assert_eq!(
            rec.fields[1],
            (
                "timestamp",
                ArtifactValue::Text("2023-01-15 10:30:00".to_string())
            )
        );
    }

    #[test]
    fn decode_pipe_delimited_fewer_fields_than_schema() {
        // Only one field in the pipe string, but schema expects two.
        let rec = CATALOG
            .decode(&PCA_APPLAUNCH_DIC, r"C:\app.exe", b"")
            .unwrap();
        assert_eq!(
            rec.fields[0],
            ("exe_path", ArtifactValue::Text(r"C:\app.exe".to_string()))
        );
        // Second field should be Null (missing).
        assert_eq!(rec.fields[1], ("timestamp", ArtifactValue::Null));
    }

    #[test]
    fn decode_pipe_delimited_from_raw_when_name_empty() {
        let raw = b"C:\\tool.exe|2024-06-01";
        let rec = CATALOG.decode(&PCA_APPLAUNCH_DIC, "", raw).unwrap();
        assert_eq!(
            rec.fields[0],
            (
                "exe_path",
                ArtifactValue::Text("C:\\tool.exe".to_string())
            )
        );
    }

    // ── Decoder: DwordLe ─────────────────────────────────────────────────

    #[test]
    fn decode_dword_le() {
        // Build a minimal descriptor with DwordLe decoder.
        static DWORD_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_dword",
            name: "Test DWORD",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::DwordLe,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let raw = 42u32.to_le_bytes();
        let rec = CATALOG.decode(&DWORD_DESC, "val", &raw).unwrap();
        assert_eq!(rec.fields, vec![("value", ArtifactValue::UnsignedInt(42))]);
    }

    #[test]
    fn decode_dword_le_too_short() {
        static DWORD_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_dword2",
            name: "Test DWORD 2",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::DwordLe,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let err = CATALOG.decode(&DWORD_DESC, "v", &[1, 2]).unwrap_err();
        assert_eq!(
            err,
            DecodeError::BufferTooShort {
                expected: 4,
                actual: 2
            }
        );
    }

    // ── Decoder: Utf16Le ─────────────────────────────────────────────────

    #[test]
    fn decode_utf16le() {
        static UTF16_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_utf16",
            name: "Test UTF-16",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::Utf16Le,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        // "Hi" in UTF-16LE + NUL terminator
        let raw: &[u8] = &[0x48, 0x00, 0x69, 0x00, 0x00, 0x00];
        let rec = CATALOG.decode(&UTF16_DESC, "", raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![("value", ArtifactValue::Text("Hi".to_string()))]
        );
    }

    #[test]
    fn decode_utf16le_odd_length() {
        static UTF16_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_utf16_odd",
            name: "Test UTF-16 odd",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::Utf16Le,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let err = CATALOG.decode(&UTF16_DESC, "", &[0x48, 0x00, 0x69]).unwrap_err();
        assert_eq!(err, DecodeError::InvalidUtf16);
    }

    // ── Decoder: MultiSz ─────────────────────────────────────────────────

    #[test]
    fn decode_multi_sz() {
        static MSZ_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_msz",
            name: "Test MultiSz",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::MultiSz,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        // "AB\0CD\0\0" in UTF-16LE
        let raw: &[u8] = &[
            0x41, 0x00, 0x42, 0x00, // "AB"
            0x00, 0x00, // NUL separator
            0x43, 0x00, 0x44, 0x00, // "CD"
            0x00, 0x00, // NUL terminator
            0x00, 0x00, // double NUL
        ];
        let rec = CATALOG.decode(&MSZ_DESC, "", raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "values",
                ArtifactValue::List(vec![
                    ArtifactValue::Text("AB".to_string()),
                    ArtifactValue::Text("CD".to_string()),
                ])
            )]
        );
    }

    #[test]
    fn decode_multi_sz_empty() {
        static MSZ_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_msz_empty",
            name: "Test MultiSz empty",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::MultiSz,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let rec = CATALOG.decode(&MSZ_DESC, "", &[]).unwrap();
        assert_eq!(
            rec.fields,
            vec![("values", ArtifactValue::List(vec![]))]
        );
    }

    // ── Decoder: MruListEx ───────────────────────────────────────────────

    #[test]
    fn decode_mrulistex() {
        static MRU_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_mru",
            name: "Test MRUListEx",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::MruListEx,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        // [2, 0, 1, 0xFFFFFFFF]
        let mut raw = Vec::new();
        raw.extend_from_slice(&2u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let rec = CATALOG.decode(&MRU_DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "indices",
                ArtifactValue::List(vec![
                    ArtifactValue::UnsignedInt(2),
                    ArtifactValue::UnsignedInt(0),
                    ArtifactValue::UnsignedInt(1),
                ])
            )]
        );
    }

    #[test]
    fn decode_mrulistex_empty() {
        static MRU_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_mru_empty",
            name: "Test MRUListEx empty",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::MruListEx,
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let rec = CATALOG.decode(&MRU_DESC, "", &[]).unwrap();
        assert_eq!(
            rec.fields,
            vec![("indices", ArtifactValue::List(vec![]))]
        );
    }

    // ── Decoder: FiletimeAt ──────────────────────────────────────────────

    #[test]
    fn decode_filetime_at() {
        static FT_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_ft",
            name: "Test FiletimeAt",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::FiletimeAt { offset: 0 },
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let ft: u64 = 116_444_736_000_000_000; // Unix epoch
        let raw = ft.to_le_bytes();
        let rec = CATALOG.decode(&FT_DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "timestamp",
                ArtifactValue::Timestamp("1970-01-01T00:00:00Z".to_string())
            )]
        );
        assert_eq!(rec.timestamp, Some("1970-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn decode_filetime_at_buffer_too_short() {
        static FT_DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_ft_short",
            name: "Test FiletimeAt short",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::NtUser),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::User,
            os_scope: OsScope::All,
            decoder: Decoder::FiletimeAt { offset: 4 },
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let err = CATALOG.decode(&FT_DESC, "", &[0; 8]).unwrap_err();
        assert_eq!(
            err,
            DecodeError::BufferTooShort {
                expected: 12,
                actual: 8
            }
        );
    }

    // ── UID generation ───────────────────────────────────────────────────

    #[test]
    fn uid_registry_with_name() {
        let rec = CATALOG
            .decode(&RUN_KEY_HKLM_RUN, "MyApp", b"cmd.exe")
            .unwrap();
        assert!(rec.uid.starts_with("winreg://HKLM\\SOFTWARE/"));
        assert!(rec.uid.contains("MyApp"));
    }

    #[test]
    fn uid_file_artifact() {
        let rec = CATALOG
            .decode(&PCA_APPLAUNCH_DIC, "line1", b"")
            .unwrap();
        assert!(rec.uid.starts_with("file://"));
        assert!(rec.uid.contains("AppLaunch.dic"));
    }

    // ── DecodeError Display ──────────────────────────────────────────────

    #[test]
    fn decode_error_display_buffer_too_short() {
        let e = DecodeError::BufferTooShort {
            expected: 8,
            actual: 4,
        };
        assert_eq!(e.to_string(), "buffer too short: need 8 bytes, got 4");
    }

    #[test]
    fn decode_error_display_field_out_of_bounds() {
        let e = DecodeError::FieldOutOfBounds {
            field: "last_run",
            offset: 60,
            size: 8,
            buf_len: 16,
        };
        assert!(e.to_string().contains("last_run"));
    }

    // ── ArtifactDescriptor field coverage ────────────────────────────────

    #[test]
    fn userassist_descriptor_has_correct_metadata() {
        assert_eq!(USERASSIST_EXE.id, "userassist_exe");
        assert_eq!(USERASSIST_EXE.hive, Some(HiveTarget::NtUser));
        assert_eq!(USERASSIST_EXE.scope, DataScope::User);
        assert_eq!(USERASSIST_EXE.os_scope, OsScope::Win7Plus);
        assert!(!USERASSIST_EXE.mitre_techniques.is_empty());
        assert!(!USERASSIST_EXE.fields.is_empty());
        assert!(USERASSIST_EXE.key_path.contains("UserAssist"));
    }

    #[test]
    fn pca_descriptor_has_correct_metadata() {
        assert_eq!(PCA_APPLAUNCH_DIC.id, "pca_applaunch_dic");
        assert_eq!(PCA_APPLAUNCH_DIC.artifact_type, ArtifactType::File);
        assert_eq!(PCA_APPLAUNCH_DIC.hive, None);
        assert_eq!(PCA_APPLAUNCH_DIC.os_scope, OsScope::Win11_22H2);
        assert!(PCA_APPLAUNCH_DIC.file_path.is_some());
    }

    #[test]
    fn run_key_descriptor_has_correct_metadata() {
        assert_eq!(RUN_KEY_HKLM_RUN.scope, DataScope::System);
        assert!(RUN_KEY_HKLM_RUN.mitre_techniques.contains(&"T1547.001"));
    }

    // ── ArtifactRecord confidence default ────────────────────────────────

    #[test]
    fn decoded_record_has_default_confidence() {
        let rec = CATALOG.decode(&RUN_KEY_HKLM_RUN, "x", b"y").unwrap();
        assert!((rec.confidence - 1.0).abs() < f32::EPSILON);
    }

    // ── BinaryField edge cases ───────────────────────────────────────────

    #[test]
    fn binary_record_exact_size_boundary() {
        // A record with a single U32Le at offset 0 -- exactly 4 bytes.
        static FIELDS: &[BinaryField] = &[BinaryField {
            name: "val",
            offset: 0,
            field_type: BinaryFieldType::U32Le,
            description: "test",
        }];
        static DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_exact",
            name: "Test exact",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::BinaryRecord(FIELDS),
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let raw = 99u32.to_le_bytes();
        let rec = CATALOG.decode(&DESC, "", &raw).unwrap();
        assert_eq!(rec.fields, vec![("val", ArtifactValue::UnsignedInt(99))]);
    }

    #[test]
    fn binary_record_bytes_field() {
        static FIELDS: &[BinaryField] = &[BinaryField {
            name: "header",
            offset: 0,
            field_type: BinaryFieldType::Bytes { len: 4 },
            description: "test header",
        }];
        static DESC: ArtifactDescriptor = ArtifactDescriptor {
            id: "test_bytes",
            name: "Test bytes",
            artifact_type: ArtifactType::RegistryValue,
            hive: Some(HiveTarget::HklmSoftware),
            key_path: "Test",
            value_name: None,
            file_path: None,
            scope: DataScope::System,
            os_scope: OsScope::All,
            decoder: Decoder::BinaryRecord(FIELDS),
            meaning: "test",
            mitre_techniques: &[],
            fields: &[],
        };
        let raw = [0xDE, 0xAD, 0xBE, 0xEF];
        let rec = CATALOG.decode(&DESC, "", &raw).unwrap();
        assert_eq!(
            rec.fields,
            vec![(
                "header",
                ArtifactValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
            )]
        );
    }
}

// ── Tests for new batch-A/B descriptors ──────────────────────────────────────

#[cfg(test)]
mod tests_new_descriptors {
    use super::*;

    // ── Run key variants ─────────────────────────────────────────────────

    #[test]
    fn run_key_hkcu_run_metadata() {
        assert_eq!(RUN_KEY_HKCU_RUN.id, "run_key_hkcu");
        assert_eq!(RUN_KEY_HKCU_RUN.hive, Some(HiveTarget::NtUser));
        assert_eq!(RUN_KEY_HKCU_RUN.scope, DataScope::User);
        assert!(RUN_KEY_HKCU_RUN.mitre_techniques.contains(&"T1547.001"));
        assert!(RUN_KEY_HKCU_RUN.key_path.contains("Run"));
    }

    #[test]
    fn run_key_hkcu_runonce_metadata() {
        assert_eq!(RUN_KEY_HKCU_RUNONCE.id, "run_key_hkcu_once");
        assert_eq!(RUN_KEY_HKCU_RUNONCE.hive, Some(HiveTarget::NtUser));
        assert_eq!(RUN_KEY_HKCU_RUNONCE.scope, DataScope::User);
        assert!(RUN_KEY_HKCU_RUNONCE.key_path.contains("RunOnce"));
    }

    #[test]
    fn run_key_hklm_runonce_metadata() {
        assert_eq!(RUN_KEY_HKLM_RUNONCE.id, "run_key_hklm_once");
        assert_eq!(RUN_KEY_HKLM_RUNONCE.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(RUN_KEY_HKLM_RUNONCE.scope, DataScope::System);
        assert!(RUN_KEY_HKLM_RUNONCE.key_path.contains("RunOnce"));
    }

    // ── IFEO ─────────────────────────────────────────────────────────────

    #[test]
    fn ifeo_debugger_metadata() {
        assert_eq!(IFEO_DEBUGGER.id, "ifeo_debugger");
        assert_eq!(IFEO_DEBUGGER.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(IFEO_DEBUGGER.scope, DataScope::System);
        assert!(IFEO_DEBUGGER.mitre_techniques.contains(&"T1546.012"));
        assert!(IFEO_DEBUGGER.key_path.contains("Image File Execution Options"));
    }

    // ── UserAssist folder GUID ────────────────────────────────────────────

    #[test]
    fn userassist_folder_metadata() {
        assert_eq!(USERASSIST_FOLDER.id, "userassist_folder");
        assert_eq!(USERASSIST_FOLDER.hive, Some(HiveTarget::NtUser));
        assert_eq!(USERASSIST_FOLDER.scope, DataScope::User);
        assert!(USERASSIST_FOLDER.key_path.contains("UserAssist"));
    }

    // ── Shellbags ────────────────────────────────────────────────────────

    #[test]
    fn shellbags_user_metadata() {
        assert_eq!(SHELLBAGS_USER.id, "shellbags_user");
        assert_eq!(SHELLBAGS_USER.hive, Some(HiveTarget::UsrClass));
        assert_eq!(SHELLBAGS_USER.scope, DataScope::User);
        assert!(SHELLBAGS_USER.mitre_techniques.contains(&"T1083"));
        assert!(SHELLBAGS_USER.key_path.contains("Shell"));
    }

    // ── Amcache ──────────────────────────────────────────────────────────

    #[test]
    fn amcache_app_file_metadata() {
        assert_eq!(AMCACHE_APP_FILE.id, "amcache_app_file");
        assert_eq!(AMCACHE_APP_FILE.hive, Some(HiveTarget::Amcache));
        assert_eq!(AMCACHE_APP_FILE.scope, DataScope::System);
        assert!(AMCACHE_APP_FILE.mitre_techniques.contains(&"T1218"));
    }

    // ── ShimCache ────────────────────────────────────────────────────────

    #[test]
    fn shimcache_metadata() {
        assert_eq!(SHIMCACHE.id, "shimcache");
        assert_eq!(SHIMCACHE.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(SHIMCACHE.scope, DataScope::System);
        assert!(SHIMCACHE.mitre_techniques.contains(&"T1218"));
        assert!(SHIMCACHE.key_path.contains("AppCompatCache"));
    }

    // ── BAM / DAM ────────────────────────────────────────────────────────

    #[test]
    fn bam_user_metadata() {
        assert_eq!(BAM_USER.id, "bam_user");
        assert_eq!(BAM_USER.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(BAM_USER.scope, DataScope::Mixed);
        assert_eq!(BAM_USER.os_scope, OsScope::Win10Plus);
        assert!(BAM_USER.key_path.contains("bam"));
    }

    #[test]
    fn dam_user_metadata() {
        assert_eq!(DAM_USER.id, "dam_user");
        assert_eq!(DAM_USER.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(DAM_USER.scope, DataScope::Mixed);
        assert_eq!(DAM_USER.os_scope, OsScope::Win10Plus);
        assert!(DAM_USER.key_path.contains("dam"));
    }

    // ── SAM ──────────────────────────────────────────────────────────────

    #[test]
    fn sam_users_metadata() {
        assert_eq!(SAM_USERS.id, "sam_users");
        assert_eq!(SAM_USERS.hive, Some(HiveTarget::HklmSam));
        assert_eq!(SAM_USERS.scope, DataScope::System);
        assert!(SAM_USERS.key_path.contains("Users"));
        assert!(SAM_USERS.mitre_techniques.contains(&"T1003.002"));
    }

    // ── LSA ──────────────────────────────────────────────────────────────

    #[test]
    fn lsa_secrets_metadata() {
        assert_eq!(LSA_SECRETS.id, "lsa_secrets");
        assert_eq!(LSA_SECRETS.hive, Some(HiveTarget::HklmSecurity));
        assert_eq!(LSA_SECRETS.scope, DataScope::System);
        assert!(LSA_SECRETS.key_path.contains("Secrets"));
        assert!(LSA_SECRETS.mitre_techniques.contains(&"T1003.004"));
    }

    #[test]
    fn dcc2_cache_metadata() {
        assert_eq!(DCC2_CACHE.id, "dcc2_cache");
        assert_eq!(DCC2_CACHE.hive, Some(HiveTarget::HklmSecurity));
        assert_eq!(DCC2_CACHE.scope, DataScope::System);
        assert!(DCC2_CACHE.mitre_techniques.contains(&"T1003.005"));
    }

    // ── TypedURLsTime ────────────────────────────────────────────────────

    #[test]
    fn typed_urls_time_metadata() {
        assert_eq!(TYPED_URLS_TIME.id, "typed_urls_time");
        assert_eq!(TYPED_URLS_TIME.hive, Some(HiveTarget::NtUser));
        assert_eq!(TYPED_URLS_TIME.scope, DataScope::User);
        assert!(TYPED_URLS_TIME.key_path.contains("TypedURLsTime"));
    }

    // ── MRU RecentDocs ───────────────────────────────────────────────────

    #[test]
    fn mru_recent_docs_metadata() {
        assert_eq!(MRU_RECENT_DOCS.id, "mru_recent_docs");
        assert_eq!(MRU_RECENT_DOCS.hive, Some(HiveTarget::NtUser));
        assert_eq!(MRU_RECENT_DOCS.scope, DataScope::User);
        assert!(MRU_RECENT_DOCS.key_path.contains("RecentDocs"));
    }

    // ── USB ──────────────────────────────────────────────────────────────

    #[test]
    fn usb_enum_metadata() {
        assert_eq!(USB_ENUM.id, "usb_enum");
        assert_eq!(USB_ENUM.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(USB_ENUM.scope, DataScope::System);
        assert!(USB_ENUM.mitre_techniques.contains(&"T1200"));
        assert!(USB_ENUM.key_path.contains("USBSTOR"));
    }

    // ── MUICache ─────────────────────────────────────────────────────────

    #[test]
    fn muicache_metadata() {
        assert_eq!(MUICACHE.id, "muicache");
        assert_eq!(MUICACHE.hive, Some(HiveTarget::UsrClass));
        assert_eq!(MUICACHE.scope, DataScope::User);
        assert!(MUICACHE.key_path.contains("MuiCache"));
    }

    // ── AppInit DLLs ─────────────────────────────────────────────────────

    #[test]
    fn appinit_dlls_metadata() {
        assert_eq!(APPINIT_DLLS.id, "appinit_dlls");
        assert_eq!(APPINIT_DLLS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(APPINIT_DLLS.scope, DataScope::System);
        assert!(APPINIT_DLLS.mitre_techniques.contains(&"T1546.010"));
        assert!(APPINIT_DLLS.key_path.contains("Windows NT"));
    }

    // ── Winlogon ─────────────────────────────────────────────────────────

    #[test]
    fn winlogon_userinit_metadata() {
        assert_eq!(WINLOGON_USERINIT.id, "winlogon_userinit");
        assert_eq!(WINLOGON_USERINIT.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(WINLOGON_USERINIT.scope, DataScope::System);
        assert!(WINLOGON_USERINIT.mitre_techniques.contains(&"T1547.004"));
        assert!(WINLOGON_USERINIT.key_path.contains("Winlogon"));
    }

    // ── Screensaver ──────────────────────────────────────────────────────

    #[test]
    fn screensaver_exe_metadata() {
        assert_eq!(SCREENSAVER_EXE.id, "screensaver_exe");
        assert_eq!(SCREENSAVER_EXE.hive, Some(HiveTarget::NtUser));
        assert_eq!(SCREENSAVER_EXE.scope, DataScope::User);
        assert!(SCREENSAVER_EXE.mitre_techniques.contains(&"T1546.002"));
        assert!(SCREENSAVER_EXE.key_path.contains("Desktop"));
    }

    // ── CATALOG completeness ──────────────────────────────────────────────

    #[test]
    fn catalog_contains_all_new_descriptors() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "run_key_hkcu",
            "run_key_hkcu_once",
            "run_key_hklm_once",
            "ifeo_debugger",
            "userassist_folder",
            "shellbags_user",
            "amcache_app_file",
            "shimcache",
            "bam_user",
            "dam_user",
            "sam_users",
            "lsa_secrets",
            "dcc2_cache",
            "typed_urls_time",
            "mru_recent_docs",
            "usb_enum",
            "muicache",
            "appinit_dlls",
            "winlogon_userinit",
            "screensaver_exe",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }
}

// ── Tests for Batch C (Windows persistence / execution / credential) ──────────

#[cfg(test)]
mod tests_batch_c {
    use super::*;

    // ── Windows persistence ───────────────────────────────────────────────

    #[test] fn winlogon_shell_md() {
        assert_eq!(WINLOGON_SHELL.id, "winlogon_shell");
        assert_eq!(WINLOGON_SHELL.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(WINLOGON_SHELL.scope, DataScope::System);
        assert!(WINLOGON_SHELL.mitre_techniques.contains(&"T1547.004"));
        assert!(WINLOGON_SHELL.key_path.contains("Winlogon"));
    }
    #[test] fn services_imagepath_md() {
        assert_eq!(SERVICES_IMAGEPATH.id, "services_imagepath");
        assert_eq!(SERVICES_IMAGEPATH.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(SERVICES_IMAGEPATH.scope, DataScope::System);
        assert!(SERVICES_IMAGEPATH.mitre_techniques.contains(&"T1543.003"));
    }
    #[test] fn active_setup_hklm_md() {
        assert_eq!(ACTIVE_SETUP_HKLM.id, "active_setup_hklm");
        assert_eq!(ACTIVE_SETUP_HKLM.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(ACTIVE_SETUP_HKLM.scope, DataScope::System);
        assert!(ACTIVE_SETUP_HKLM.mitre_techniques.contains(&"T1547.014"));
    }
    #[test] fn active_setup_hkcu_md() {
        assert_eq!(ACTIVE_SETUP_HKCU.id, "active_setup_hkcu");
        assert_eq!(ACTIVE_SETUP_HKCU.hive, Some(HiveTarget::NtUser));
        assert_eq!(ACTIVE_SETUP_HKCU.scope, DataScope::User);
    }
    #[test] fn com_hijack_clsid_hkcu_md() {
        assert_eq!(COM_HIJACK_CLSID_HKCU.id, "com_hijack_clsid_hkcu");
        assert_eq!(COM_HIJACK_CLSID_HKCU.hive, Some(HiveTarget::UsrClass));
        assert_eq!(COM_HIJACK_CLSID_HKCU.scope, DataScope::User);
        assert!(COM_HIJACK_CLSID_HKCU.mitre_techniques.contains(&"T1546.015"));
    }
    #[test] fn appcert_dlls_md() {
        assert_eq!(APPCERT_DLLS.id, "appcert_dlls");
        assert_eq!(APPCERT_DLLS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(APPCERT_DLLS.scope, DataScope::System);
        assert!(APPCERT_DLLS.mitre_techniques.contains(&"T1546.009"));
    }
    #[test] fn boot_execute_md() {
        assert_eq!(BOOT_EXECUTE.id, "boot_execute");
        assert_eq!(BOOT_EXECUTE.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(BOOT_EXECUTE.scope, DataScope::System);
        assert!(BOOT_EXECUTE.mitre_techniques.contains(&"T1547.001"));
        assert!(BOOT_EXECUTE.key_path.contains("Session Manager"));
    }
    #[test] fn lsa_security_pkgs_md() {
        assert_eq!(LSA_SECURITY_PKGS.id, "lsa_security_pkgs");
        assert_eq!(LSA_SECURITY_PKGS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(LSA_SECURITY_PKGS.scope, DataScope::System);
        assert!(LSA_SECURITY_PKGS.mitre_techniques.contains(&"T1547.005"));
    }
    #[test] fn lsa_auth_pkgs_md() {
        assert_eq!(LSA_AUTH_PKGS.id, "lsa_auth_pkgs");
        assert_eq!(LSA_AUTH_PKGS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(LSA_AUTH_PKGS.scope, DataScope::System);
        assert!(LSA_AUTH_PKGS.mitre_techniques.contains(&"T1547.002"));
    }
    #[test] fn print_monitors_md() {
        assert_eq!(PRINT_MONITORS.id, "print_monitors");
        assert_eq!(PRINT_MONITORS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(PRINT_MONITORS.scope, DataScope::System);
        assert!(PRINT_MONITORS.mitre_techniques.contains(&"T1547.010"));
    }
    #[test] fn time_providers_md() {
        assert_eq!(TIME_PROVIDERS.id, "time_providers");
        assert_eq!(TIME_PROVIDERS.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(TIME_PROVIDERS.scope, DataScope::System);
        assert!(TIME_PROVIDERS.mitre_techniques.contains(&"T1547.003"));
    }
    #[test] fn netsh_helper_dlls_md() {
        assert_eq!(NETSH_HELPER_DLLS.id, "netsh_helper_dlls");
        assert_eq!(NETSH_HELPER_DLLS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(NETSH_HELPER_DLLS.scope, DataScope::System);
        assert!(NETSH_HELPER_DLLS.mitre_techniques.contains(&"T1546.007"));
    }
    #[test] fn browser_helper_objects_md() {
        assert_eq!(BROWSER_HELPER_OBJECTS.id, "browser_helper_objects");
        assert_eq!(BROWSER_HELPER_OBJECTS.hive, Some(HiveTarget::HklmSoftware));
        assert_eq!(BROWSER_HELPER_OBJECTS.scope, DataScope::System);
        assert!(BROWSER_HELPER_OBJECTS.mitre_techniques.contains(&"T1176"));
    }
    #[test] fn startup_folder_user_md() {
        assert_eq!(STARTUP_FOLDER_USER.id, "startup_folder_user");
        assert_eq!(STARTUP_FOLDER_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(STARTUP_FOLDER_USER.scope, DataScope::User);
        assert!(STARTUP_FOLDER_USER.mitre_techniques.contains(&"T1547.001"));
    }
    #[test] fn startup_folder_system_md() {
        assert_eq!(STARTUP_FOLDER_SYSTEM.id, "startup_folder_system");
        assert_eq!(STARTUP_FOLDER_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(STARTUP_FOLDER_SYSTEM.scope, DataScope::System);
        assert!(STARTUP_FOLDER_SYSTEM.mitre_techniques.contains(&"T1547.001"));
    }
    #[test] fn scheduled_tasks_dir_md() {
        assert_eq!(SCHEDULED_TASKS_DIR.id, "scheduled_tasks_dir");
        assert_eq!(SCHEDULED_TASKS_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(SCHEDULED_TASKS_DIR.scope, DataScope::System);
        assert!(SCHEDULED_TASKS_DIR.mitre_techniques.contains(&"T1053.005"));
    }
    #[test] fn wdigest_caching_md() {
        assert_eq!(WDIGEST_CACHING.id, "wdigest_caching");
        assert_eq!(WDIGEST_CACHING.hive, Some(HiveTarget::HklmSystem));
        assert_eq!(WDIGEST_CACHING.scope, DataScope::System);
        assert!(WDIGEST_CACHING.mitre_techniques.contains(&"T1003.001"));
    }

    // ── Windows execution evidence ────────────────────────────────────────

    #[test] fn wordwheel_query_md() {
        assert_eq!(WORDWHEEL_QUERY.id, "wordwheel_query");
        assert_eq!(WORDWHEEL_QUERY.hive, Some(HiveTarget::NtUser));
        assert_eq!(WORDWHEEL_QUERY.scope, DataScope::User);
        assert!(WORDWHEEL_QUERY.key_path.contains("WordWheelQuery"));
    }
    #[test] fn opensave_mru_md() {
        assert_eq!(OPENSAVE_MRU.id, "opensave_mru");
        assert_eq!(OPENSAVE_MRU.hive, Some(HiveTarget::NtUser));
        assert_eq!(OPENSAVE_MRU.scope, DataScope::User);
        assert!(OPENSAVE_MRU.key_path.contains("OpenSaveMRU"));
    }
    #[test] fn lastvisited_mru_md() {
        assert_eq!(LASTVISITED_MRU.id, "lastvisited_mru");
        assert_eq!(LASTVISITED_MRU.hive, Some(HiveTarget::NtUser));
        assert_eq!(LASTVISITED_MRU.scope, DataScope::User);
        assert!(LASTVISITED_MRU.key_path.contains("LastVisitedMRU"));
    }
    #[test] fn prefetch_dir_md() {
        assert_eq!(PREFETCH_DIR.id, "prefetch_dir");
        assert_eq!(PREFETCH_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(PREFETCH_DIR.scope, DataScope::System);
        assert!(PREFETCH_DIR.mitre_techniques.contains(&"T1204.002"));
    }
    #[test] fn srum_db_md() {
        assert_eq!(SRUM_DB.id, "srum_db");
        assert_eq!(SRUM_DB.artifact_type, ArtifactType::File);
        assert_eq!(SRUM_DB.scope, DataScope::System);
        assert!(SRUM_DB.os_scope == OsScope::Win8Plus);
    }
    #[test] fn windows_timeline_md() {
        assert_eq!(WINDOWS_TIMELINE.id, "windows_timeline");
        assert_eq!(WINDOWS_TIMELINE.artifact_type, ArtifactType::File);
        assert_eq!(WINDOWS_TIMELINE.scope, DataScope::User);
        assert_eq!(WINDOWS_TIMELINE.os_scope, OsScope::Win10Plus);
    }
    #[test] fn powershell_history_md() {
        assert_eq!(POWERSHELL_HISTORY.id, "powershell_history");
        assert_eq!(POWERSHELL_HISTORY.artifact_type, ArtifactType::File);
        assert_eq!(POWERSHELL_HISTORY.scope, DataScope::User);
        assert!(POWERSHELL_HISTORY.mitre_techniques.contains(&"T1059.001"));
    }
    #[test] fn recycle_bin_md() {
        assert_eq!(RECYCLE_BIN.id, "recycle_bin");
        assert_eq!(RECYCLE_BIN.artifact_type, ArtifactType::Directory);
        assert_eq!(RECYCLE_BIN.scope, DataScope::User);
        assert!(RECYCLE_BIN.mitre_techniques.contains(&"T1070.004"));
    }
    #[test] fn thumbcache_md() {
        assert_eq!(THUMBCACHE.id, "thumbcache");
        assert_eq!(THUMBCACHE.artifact_type, ArtifactType::Directory);
        assert_eq!(THUMBCACHE.scope, DataScope::User);
    }
    #[test] fn search_db_user_md() {
        assert_eq!(SEARCH_DB_USER.id, "search_db_user");
        assert_eq!(SEARCH_DB_USER.artifact_type, ArtifactType::File);
        assert_eq!(SEARCH_DB_USER.scope, DataScope::System);
    }

    // ── Windows credentials ───────────────────────────────────────────────

    #[test] fn dpapi_masterkey_user_md() {
        assert_eq!(DPAPI_MASTERKEY_USER.id, "dpapi_masterkey_user");
        assert_eq!(DPAPI_MASTERKEY_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_MASTERKEY_USER.scope, DataScope::User);
        assert!(DPAPI_MASTERKEY_USER.mitre_techniques.contains(&"T1555.004"));
    }
    #[test] fn dpapi_cred_user_md() {
        assert_eq!(DPAPI_CRED_USER.id, "dpapi_cred_user");
        assert_eq!(DPAPI_CRED_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_CRED_USER.scope, DataScope::User);
    }
    #[test] fn dpapi_cred_roaming_md() {
        assert_eq!(DPAPI_CRED_ROAMING.id, "dpapi_cred_roaming");
        assert_eq!(DPAPI_CRED_ROAMING.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_CRED_ROAMING.scope, DataScope::User);
    }
    #[test] fn windows_vault_user_md() {
        assert_eq!(WINDOWS_VAULT_USER.id, "windows_vault_user");
        assert_eq!(WINDOWS_VAULT_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_VAULT_USER.scope, DataScope::User);
        assert!(WINDOWS_VAULT_USER.mitre_techniques.contains(&"T1555.004"));
    }
    #[test] fn windows_vault_system_md() {
        assert_eq!(WINDOWS_VAULT_SYSTEM.id, "windows_vault_system");
        assert_eq!(WINDOWS_VAULT_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_VAULT_SYSTEM.scope, DataScope::System);
    }
    #[test] fn rdp_client_servers_md() {
        assert_eq!(RDP_CLIENT_SERVERS.id, "rdp_client_servers");
        assert_eq!(RDP_CLIENT_SERVERS.hive, Some(HiveTarget::NtUser));
        assert_eq!(RDP_CLIENT_SERVERS.scope, DataScope::User);
        assert!(RDP_CLIENT_SERVERS.mitre_techniques.contains(&"T1021.001"));
    }
    #[test] fn rdp_client_default_md() {
        assert_eq!(RDP_CLIENT_DEFAULT.id, "rdp_client_default");
        assert_eq!(RDP_CLIENT_DEFAULT.hive, Some(HiveTarget::NtUser));
        assert_eq!(RDP_CLIENT_DEFAULT.scope, DataScope::User);
        assert!(RDP_CLIENT_DEFAULT.mitre_techniques.contains(&"T1021.001"));
    }
    #[test] fn ntds_dit_md() {
        assert_eq!(NTDS_DIT.id, "ntds_dit");
        assert_eq!(NTDS_DIT.artifact_type, ArtifactType::File);
        assert_eq!(NTDS_DIT.scope, DataScope::System);
        assert!(NTDS_DIT.mitre_techniques.contains(&"T1003.003"));
    }
    #[test] fn chrome_login_data_md() {
        assert_eq!(CHROME_LOGIN_DATA.id, "chrome_login_data");
        assert_eq!(CHROME_LOGIN_DATA.artifact_type, ArtifactType::File);
        assert_eq!(CHROME_LOGIN_DATA.scope, DataScope::User);
        assert!(CHROME_LOGIN_DATA.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn firefox_logins_md() {
        assert_eq!(FIREFOX_LOGINS.id, "firefox_logins");
        assert_eq!(FIREFOX_LOGINS.artifact_type, ArtifactType::File);
        assert_eq!(FIREFOX_LOGINS.scope, DataScope::User);
        assert!(FIREFOX_LOGINS.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn wifi_profiles_md() {
        assert_eq!(WIFI_PROFILES.id, "wifi_profiles");
        assert_eq!(WIFI_PROFILES.artifact_type, ArtifactType::Directory);
        assert_eq!(WIFI_PROFILES.scope, DataScope::System);
        assert!(WIFI_PROFILES.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch C) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_c() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "winlogon_shell", "services_imagepath", "active_setup_hklm",
            "active_setup_hkcu", "com_hijack_clsid_hkcu", "appcert_dlls",
            "boot_execute", "lsa_security_pkgs", "lsa_auth_pkgs",
            "print_monitors", "time_providers", "netsh_helper_dlls",
            "browser_helper_objects", "startup_folder_user", "startup_folder_system",
            "scheduled_tasks_dir", "wdigest_caching", "wordwheel_query",
            "opensave_mru", "lastvisited_mru", "prefetch_dir", "srum_db",
            "windows_timeline", "powershell_history", "recycle_bin", "thumbcache",
            "search_db_user", "dpapi_masterkey_user", "dpapi_cred_user",
            "dpapi_cred_roaming", "windows_vault_user", "windows_vault_system",
            "rdp_client_servers", "rdp_client_default", "ntds_dit",
            "chrome_login_data", "firefox_logins", "wifi_profiles",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }
}

// ── Tests for Batch D (Linux persistence / execution / credential) ────────────

#[cfg(test)]
mod tests_batch_d {
    use super::*;

    // ── Linux persistence: cron ───────────────────────────────────────────

    #[test] fn linux_crontab_system_md() {
        assert_eq!(LINUX_CRONTAB_SYSTEM.id, "linux_crontab_system");
        assert_eq!(LINUX_CRONTAB_SYSTEM.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_CRONTAB_SYSTEM.scope, DataScope::System);
        assert_eq!(LINUX_CRONTAB_SYSTEM.os_scope, OsScope::Linux);
        assert!(LINUX_CRONTAB_SYSTEM.mitre_techniques.contains(&"T1053.003"));
    }
    #[test] fn linux_cron_d_md() {
        assert_eq!(LINUX_CRON_D.id, "linux_cron_d");
        assert_eq!(LINUX_CRON_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_CRON_D.scope, DataScope::System);
        assert_eq!(LINUX_CRON_D.os_scope, OsScope::Linux);
    }
    #[test] fn linux_cron_periodic_md() {
        assert_eq!(LINUX_CRON_PERIODIC.id, "linux_cron_periodic");
        assert_eq!(LINUX_CRON_PERIODIC.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_CRON_PERIODIC.scope, DataScope::System);
    }
    #[test] fn linux_user_crontab_md() {
        assert_eq!(LINUX_USER_CRONTAB.id, "linux_user_crontab");
        assert_eq!(LINUX_USER_CRONTAB.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_USER_CRONTAB.scope, DataScope::User);
        assert!(LINUX_USER_CRONTAB.mitre_techniques.contains(&"T1053.003"));
    }
    #[test] fn linux_anacrontab_md() {
        assert_eq!(LINUX_ANACRONTAB.id, "linux_anacrontab");
        assert_eq!(LINUX_ANACRONTAB.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ANACRONTAB.scope, DataScope::System);
    }

    // ── Linux persistence: systemd ────────────────────────────────────────

    #[test] fn linux_systemd_system_unit_md() {
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.id, "linux_systemd_system_unit");
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.scope, DataScope::System);
        assert_eq!(LINUX_SYSTEMD_SYSTEM_UNIT.os_scope, OsScope::LinuxSystemd);
        assert!(LINUX_SYSTEMD_SYSTEM_UNIT.mitre_techniques.contains(&"T1543.002"));
    }
    #[test] fn linux_systemd_user_unit_md() {
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.id, "linux_systemd_user_unit");
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.scope, DataScope::User);
        assert_eq!(LINUX_SYSTEMD_USER_UNIT.os_scope, OsScope::LinuxSystemd);
    }
    #[test] fn linux_systemd_timer_md() {
        assert_eq!(LINUX_SYSTEMD_TIMER.id, "linux_systemd_timer");
        assert_eq!(LINUX_SYSTEMD_TIMER.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SYSTEMD_TIMER.os_scope, OsScope::LinuxSystemd);
        assert!(LINUX_SYSTEMD_TIMER.mitre_techniques.contains(&"T1053.006"));
    }

    // ── Linux persistence: init / rc.local ───────────────────────────────

    #[test] fn linux_rc_local_md() {
        assert_eq!(LINUX_RC_LOCAL.id, "linux_rc_local");
        assert_eq!(LINUX_RC_LOCAL.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_RC_LOCAL.scope, DataScope::System);
        assert!(LINUX_RC_LOCAL.mitre_techniques.contains(&"T1037.004"));
    }
    #[test] fn linux_init_d_md() {
        assert_eq!(LINUX_INIT_D.id, "linux_init_d");
        assert_eq!(LINUX_INIT_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_INIT_D.scope, DataScope::System);
    }

    // ── Linux persistence: shell startup ─────────────────────────────────

    #[test] fn linux_bashrc_user_md() {
        assert_eq!(LINUX_BASHRC_USER.id, "linux_bashrc_user");
        assert_eq!(LINUX_BASHRC_USER.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BASHRC_USER.scope, DataScope::User);
        assert!(LINUX_BASHRC_USER.mitre_techniques.contains(&"T1546.004"));
    }
    #[test] fn linux_bash_profile_user_md() {
        assert_eq!(LINUX_BASH_PROFILE_USER.id, "linux_bash_profile_user");
        assert_eq!(LINUX_BASH_PROFILE_USER.scope, DataScope::User);
        assert!(LINUX_BASH_PROFILE_USER.mitre_techniques.contains(&"T1546.004"));
    }
    #[test] fn linux_profile_user_md() {
        assert_eq!(LINUX_PROFILE_USER.id, "linux_profile_user");
        assert_eq!(LINUX_PROFILE_USER.scope, DataScope::User);
    }
    #[test] fn linux_zshrc_user_md() {
        assert_eq!(LINUX_ZSHRC_USER.id, "linux_zshrc_user");
        assert_eq!(LINUX_ZSHRC_USER.scope, DataScope::User);
        assert!(LINUX_ZSHRC_USER.mitre_techniques.contains(&"T1546.004"));
    }
    #[test] fn linux_profile_system_md() {
        assert_eq!(LINUX_PROFILE_SYSTEM.id, "linux_profile_system");
        assert_eq!(LINUX_PROFILE_SYSTEM.scope, DataScope::System);
    }
    #[test] fn linux_profile_d_md() {
        assert_eq!(LINUX_PROFILE_D.id, "linux_profile_d");
        assert_eq!(LINUX_PROFILE_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_PROFILE_D.scope, DataScope::System);
    }

    // ── Linux persistence: LD_PRELOAD / linker ────────────────────────────

    #[test] fn linux_ld_so_preload_md() {
        assert_eq!(LINUX_LD_SO_PRELOAD.id, "linux_ld_so_preload");
        assert_eq!(LINUX_LD_SO_PRELOAD.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_LD_SO_PRELOAD.scope, DataScope::System);
        assert!(LINUX_LD_SO_PRELOAD.mitre_techniques.contains(&"T1574.006"));
    }
    #[test] fn linux_ld_so_conf_d_md() {
        assert_eq!(LINUX_LD_SO_CONF_D.id, "linux_ld_so_conf_d");
        assert_eq!(LINUX_LD_SO_CONF_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_LD_SO_CONF_D.scope, DataScope::System);
    }

    // ── Linux persistence: SSH ────────────────────────────────────────────

    #[test] fn linux_ssh_authorized_keys_md() {
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.id, "linux_ssh_authorized_keys");
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSH_AUTHORIZED_KEYS.scope, DataScope::User);
        assert!(LINUX_SSH_AUTHORIZED_KEYS.mitre_techniques.contains(&"T1098.004"));
    }

    // ── Linux persistence: PAM / sudo / kernel ────────────────────────────

    #[test] fn linux_pam_d_md() {
        assert_eq!(LINUX_PAM_D.id, "linux_pam_d");
        assert_eq!(LINUX_PAM_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_PAM_D.scope, DataScope::System);
        assert!(LINUX_PAM_D.mitre_techniques.contains(&"T1556.003"));
    }
    #[test] fn linux_sudoers_d_md() {
        assert_eq!(LINUX_SUDOERS_D.id, "linux_sudoers_d");
        assert_eq!(LINUX_SUDOERS_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_SUDOERS_D.scope, DataScope::System);
        assert!(LINUX_SUDOERS_D.mitre_techniques.contains(&"T1548.003"));
    }
    #[test] fn linux_modules_load_d_md() {
        assert_eq!(LINUX_MODULES_LOAD_D.id, "linux_modules_load_d");
        assert_eq!(LINUX_MODULES_LOAD_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_MODULES_LOAD_D.scope, DataScope::System);
        assert!(LINUX_MODULES_LOAD_D.mitre_techniques.contains(&"T1547.006"));
    }
    #[test] fn linux_motd_d_md() {
        assert_eq!(LINUX_MOTD_D.id, "linux_motd_d");
        assert_eq!(LINUX_MOTD_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_MOTD_D.scope, DataScope::System);
    }
    #[test] fn linux_udev_rules_d_md() {
        assert_eq!(LINUX_UDEV_RULES_D.id, "linux_udev_rules_d");
        assert_eq!(LINUX_UDEV_RULES_D.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_UDEV_RULES_D.scope, DataScope::System);
        assert!(LINUX_UDEV_RULES_D.mitre_techniques.contains(&"T1546"));
    }

    // ── Linux execution evidence ──────────────────────────────────────────

    #[test] fn linux_bash_history_md() {
        assert_eq!(LINUX_BASH_HISTORY.id, "linux_bash_history");
        assert_eq!(LINUX_BASH_HISTORY.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BASH_HISTORY.scope, DataScope::User);
        assert!(LINUX_BASH_HISTORY.mitre_techniques.contains(&"T1059.004"));
    }
    #[test] fn linux_zsh_history_md() {
        assert_eq!(LINUX_ZSH_HISTORY.id, "linux_zsh_history");
        assert_eq!(LINUX_ZSH_HISTORY.scope, DataScope::User);
    }
    #[test] fn linux_wtmp_md() {
        assert_eq!(LINUX_WTMP.id, "linux_wtmp");
        assert_eq!(LINUX_WTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_WTMP.scope, DataScope::System);
        assert!(LINUX_WTMP.mitre_techniques.contains(&"T1078"));
    }
    #[test] fn linux_btmp_md() {
        assert_eq!(LINUX_BTMP.id, "linux_btmp");
        assert_eq!(LINUX_BTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_BTMP.scope, DataScope::System);
    }
    #[test] fn linux_lastlog_md() {
        assert_eq!(LINUX_LASTLOG.id, "linux_lastlog");
        assert_eq!(LINUX_LASTLOG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_LASTLOG.scope, DataScope::System);
    }
    #[test] fn linux_auth_log_md() {
        assert_eq!(LINUX_AUTH_LOG.id, "linux_auth_log");
        assert_eq!(LINUX_AUTH_LOG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_AUTH_LOG.scope, DataScope::System);
        assert!(LINUX_AUTH_LOG.mitre_techniques.contains(&"T1078"));
    }
    #[test] fn linux_journal_dir_md() {
        assert_eq!(LINUX_JOURNAL_DIR.id, "linux_journal_dir");
        assert_eq!(LINUX_JOURNAL_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_JOURNAL_DIR.os_scope, OsScope::LinuxSystemd);
    }

    // ── Linux credentials ─────────────────────────────────────────────────

    #[test] fn linux_passwd_md() {
        assert_eq!(LINUX_PASSWD.id, "linux_passwd");
        assert_eq!(LINUX_PASSWD.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_PASSWD.scope, DataScope::System);
        assert!(LINUX_PASSWD.mitre_techniques.contains(&"T1087.001"));
    }
    #[test] fn linux_shadow_md() {
        assert_eq!(LINUX_SHADOW.id, "linux_shadow");
        assert_eq!(LINUX_SHADOW.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SHADOW.scope, DataScope::System);
        assert!(LINUX_SHADOW.mitre_techniques.contains(&"T1003.008"));
    }
    #[test] fn linux_ssh_private_key_md() {
        assert_eq!(LINUX_SSH_PRIVATE_KEY.id, "linux_ssh_private_key");
        assert_eq!(LINUX_SSH_PRIVATE_KEY.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSH_PRIVATE_KEY.scope, DataScope::User);
        assert!(LINUX_SSH_PRIVATE_KEY.mitre_techniques.contains(&"T1552.004"));
    }
    #[test] fn linux_ssh_known_hosts_md() {
        assert_eq!(LINUX_SSH_KNOWN_HOSTS.id, "linux_ssh_known_hosts");
        assert_eq!(LINUX_SSH_KNOWN_HOSTS.scope, DataScope::User);
        assert!(LINUX_SSH_KNOWN_HOSTS.mitre_techniques.contains(&"T1021.004"));
    }
    #[test] fn linux_gnupg_private_md() {
        assert_eq!(LINUX_GNUPG_PRIVATE.id, "linux_gnupg_private");
        assert_eq!(LINUX_GNUPG_PRIVATE.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GNUPG_PRIVATE.scope, DataScope::User);
        assert!(LINUX_GNUPG_PRIVATE.mitre_techniques.contains(&"T1552.004"));
    }
    #[test] fn linux_aws_credentials_md() {
        assert_eq!(LINUX_AWS_CREDENTIALS.id, "linux_aws_credentials");
        assert_eq!(LINUX_AWS_CREDENTIALS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_AWS_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_AWS_CREDENTIALS.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn linux_docker_config_md() {
        assert_eq!(LINUX_DOCKER_CONFIG.id, "linux_docker_config");
        assert_eq!(LINUX_DOCKER_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_DOCKER_CONFIG.scope, DataScope::User);
        assert!(LINUX_DOCKER_CONFIG.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch D) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_d() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_crontab_system", "linux_cron_d", "linux_cron_periodic",
            "linux_user_crontab", "linux_anacrontab",
            "linux_systemd_system_unit", "linux_systemd_user_unit", "linux_systemd_timer",
            "linux_rc_local", "linux_init_d",
            "linux_bashrc_user", "linux_bash_profile_user", "linux_profile_user",
            "linux_zshrc_user", "linux_profile_system", "linux_profile_d",
            "linux_ld_so_preload", "linux_ld_so_conf_d",
            "linux_ssh_authorized_keys",
            "linux_pam_d", "linux_sudoers_d", "linux_modules_load_d",
            "linux_motd_d", "linux_udev_rules_d",
            "linux_bash_history", "linux_zsh_history",
            "linux_wtmp", "linux_btmp", "linux_lastlog",
            "linux_auth_log", "linux_journal_dir",
            "linux_passwd", "linux_shadow",
            "linux_ssh_private_key", "linux_ssh_known_hosts",
            "linux_gnupg_private", "linux_aws_credentials", "linux_docker_config",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch E — Windows execution / persistence / credential (RED)
    // ═══════════════════════════════════════════════════════════════════════

    // ── Windows execution evidence ────────────────────────────────────────

    #[test] fn lnk_files_md() {
        assert_eq!(LNK_FILES.id, "lnk_files");
        assert_eq!(LNK_FILES.artifact_type, ArtifactType::Directory);
        assert_eq!(LNK_FILES.scope, DataScope::User);
        assert!(LNK_FILES.mitre_techniques.contains(&"T1547.009"));
    }
    #[test] fn jump_list_auto_md() {
        assert_eq!(JUMP_LIST_AUTO.id, "jump_list_auto");
        assert_eq!(JUMP_LIST_AUTO.artifact_type, ArtifactType::Directory);
        assert_eq!(JUMP_LIST_AUTO.scope, DataScope::User);
        assert!(JUMP_LIST_AUTO.mitre_techniques.contains(&"T1547.009"));
    }
    #[test] fn jump_list_custom_md() {
        assert_eq!(JUMP_LIST_CUSTOM.id, "jump_list_custom");
        assert_eq!(JUMP_LIST_CUSTOM.artifact_type, ArtifactType::Directory);
        assert_eq!(JUMP_LIST_CUSTOM.scope, DataScope::User);
        assert!(JUMP_LIST_CUSTOM.mitre_techniques.contains(&"T1547.009"));
    }
    #[test] fn evtx_dir_md() {
        assert_eq!(EVTX_DIR.id, "evtx_dir");
        assert_eq!(EVTX_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(EVTX_DIR.scope, DataScope::System);
        assert!(EVTX_DIR.mitre_techniques.contains(&"T1070.001"));
    }
    #[test] fn usn_journal_md() {
        assert_eq!(USN_JOURNAL.id, "usn_journal");
        assert_eq!(USN_JOURNAL.artifact_type, ArtifactType::File);
        assert_eq!(USN_JOURNAL.scope, DataScope::System);
        assert_eq!(USN_JOURNAL.os_scope, OsScope::Win7Plus);
    }

    // ── Windows persistence ───────────────────────────────────────────────

    #[test] fn wmi_mof_dir_md() {
        assert_eq!(WMI_MOF_DIR.id, "wmi_mof_dir");
        assert_eq!(WMI_MOF_DIR.artifact_type, ArtifactType::Directory);
        assert_eq!(WMI_MOF_DIR.scope, DataScope::System);
        assert!(WMI_MOF_DIR.mitre_techniques.contains(&"T1546.003"));
    }
    #[test] fn bits_db_md() {
        assert_eq!(BITS_DB.id, "bits_db");
        assert_eq!(BITS_DB.artifact_type, ArtifactType::Directory);
        assert_eq!(BITS_DB.scope, DataScope::System);
        assert!(BITS_DB.mitre_techniques.contains(&"T1197"));
    }
    #[test] fn wmi_subscriptions_md() {
        assert_eq!(WMI_SUBSCRIPTIONS.id, "wmi_subscriptions");
        assert_eq!(WMI_SUBSCRIPTIONS.artifact_type, ArtifactType::RegistryKey);
        assert_eq!(WMI_SUBSCRIPTIONS.scope, DataScope::System);
        assert!(WMI_SUBSCRIPTIONS.mitre_techniques.contains(&"T1546.003"));
    }
    #[test] fn logon_scripts_md() {
        assert_eq!(LOGON_SCRIPTS.id, "logon_scripts");
        assert_eq!(LOGON_SCRIPTS.artifact_type, ArtifactType::RegistryValue);
        assert_eq!(LOGON_SCRIPTS.scope, DataScope::User);
        assert!(LOGON_SCRIPTS.mitre_techniques.contains(&"T1037.001"));
    }
    #[test] fn winsock_lsp_md() {
        assert_eq!(WINSOCK_LSP.id, "winsock_lsp");
        assert_eq!(WINSOCK_LSP.artifact_type, ArtifactType::RegistryKey);
        assert_eq!(WINSOCK_LSP.scope, DataScope::System);
        assert!(WINSOCK_LSP.mitre_techniques.contains(&"T1547.010"));
    }
    #[test] fn appshim_db_md() {
        assert_eq!(APPSHIM_DB.id, "appshim_db");
        assert_eq!(APPSHIM_DB.artifact_type, ArtifactType::Directory);
        assert_eq!(APPSHIM_DB.scope, DataScope::System);
        assert!(APPSHIM_DB.mitre_techniques.contains(&"T1546.011"));
    }
    #[test] fn password_filter_dll_md() {
        assert_eq!(PASSWORD_FILTER_DLL.id, "password_filter_dll");
        assert_eq!(PASSWORD_FILTER_DLL.artifact_type, ArtifactType::RegistryValue);
        assert_eq!(PASSWORD_FILTER_DLL.scope, DataScope::System);
        assert!(PASSWORD_FILTER_DLL.mitre_techniques.contains(&"T1556.002"));
    }
    #[test] fn office_normal_dotm_md() {
        assert_eq!(OFFICE_NORMAL_DOTM.id, "office_normal_dotm");
        assert_eq!(OFFICE_NORMAL_DOTM.artifact_type, ArtifactType::File);
        assert_eq!(OFFICE_NORMAL_DOTM.scope, DataScope::User);
        assert!(OFFICE_NORMAL_DOTM.mitre_techniques.contains(&"T1137.001"));
    }
    #[test] fn powershell_profile_all_md() {
        assert_eq!(POWERSHELL_PROFILE_ALL.id, "powershell_profile_all");
        assert_eq!(POWERSHELL_PROFILE_ALL.artifact_type, ArtifactType::File);
        assert_eq!(POWERSHELL_PROFILE_ALL.scope, DataScope::System);
        assert!(POWERSHELL_PROFILE_ALL.mitre_techniques.contains(&"T1546.013"));
    }

    // ── Windows credentials ───────────────────────────────────────────────

    #[test] fn dpapi_system_masterkey_md() {
        assert_eq!(DPAPI_SYSTEM_MASTERKEY.id, "dpapi_system_masterkey");
        assert_eq!(DPAPI_SYSTEM_MASTERKEY.artifact_type, ArtifactType::Directory);
        assert_eq!(DPAPI_SYSTEM_MASTERKEY.scope, DataScope::System);
        assert!(DPAPI_SYSTEM_MASTERKEY.mitre_techniques.contains(&"T1555.004"));
    }
    #[test] fn dpapi_credhist_md() {
        assert_eq!(DPAPI_CREDHIST.id, "dpapi_credhist");
        assert_eq!(DPAPI_CREDHIST.artifact_type, ArtifactType::File);
        assert_eq!(DPAPI_CREDHIST.scope, DataScope::User);
        assert!(DPAPI_CREDHIST.mitre_techniques.contains(&"T1555.004"));
    }
    #[test] fn chrome_cookies_md() {
        assert_eq!(CHROME_COOKIES.id, "chrome_cookies");
        assert_eq!(CHROME_COOKIES.artifact_type, ArtifactType::File);
        assert_eq!(CHROME_COOKIES.scope, DataScope::User);
        assert!(CHROME_COOKIES.mitre_techniques.contains(&"T1539"));
    }
    #[test] fn edge_webcache_md() {
        assert_eq!(EDGE_WEBCACHE.id, "edge_webcache");
        assert_eq!(EDGE_WEBCACHE.artifact_type, ArtifactType::Directory);
        assert_eq!(EDGE_WEBCACHE.scope, DataScope::User);
        assert!(EDGE_WEBCACHE.mitre_techniques.contains(&"T1539"));
    }
    #[test] fn vpn_ras_phonebook_md() {
        assert_eq!(VPN_RAS_PHONEBOOK.id, "vpn_ras_phonebook");
        assert_eq!(VPN_RAS_PHONEBOOK.artifact_type, ArtifactType::File);
        assert_eq!(VPN_RAS_PHONEBOOK.scope, DataScope::User);
        assert!(VPN_RAS_PHONEBOOK.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn windows_hello_ngc_md() {
        assert_eq!(WINDOWS_HELLO_NGC.id, "windows_hello_ngc");
        assert_eq!(WINDOWS_HELLO_NGC.artifact_type, ArtifactType::Directory);
        assert_eq!(WINDOWS_HELLO_NGC.scope, DataScope::System);
        assert!(WINDOWS_HELLO_NGC.mitre_techniques.contains(&"T1555"));
    }
    #[test] fn user_cert_private_key_md() {
        assert_eq!(USER_CERT_PRIVATE_KEY.id, "user_cert_private_key");
        assert_eq!(USER_CERT_PRIVATE_KEY.artifact_type, ArtifactType::Directory);
        assert_eq!(USER_CERT_PRIVATE_KEY.scope, DataScope::User);
        assert!(USER_CERT_PRIVATE_KEY.mitre_techniques.contains(&"T1552.004"));
    }
    #[test] fn machine_cert_store_md() {
        assert_eq!(MACHINE_CERT_STORE.id, "machine_cert_store");
        assert_eq!(MACHINE_CERT_STORE.artifact_type, ArtifactType::Directory);
        assert_eq!(MACHINE_CERT_STORE.scope, DataScope::System);
        assert!(MACHINE_CERT_STORE.mitre_techniques.contains(&"T1552.004"));
    }

    // ── CATALOG completeness (batch E) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_e() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "lnk_files", "jump_list_auto", "jump_list_custom",
            "evtx_dir", "usn_journal",
            "wmi_mof_dir", "bits_db", "wmi_subscriptions",
            "logon_scripts", "winsock_lsp", "appshim_db",
            "password_filter_dll", "office_normal_dotm", "powershell_profile_all",
            "dpapi_system_masterkey", "dpapi_credhist",
            "chrome_cookies", "edge_webcache", "vpn_ras_phonebook",
            "windows_hello_ngc", "user_cert_private_key", "machine_cert_store",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch F — Linux extended credential / execution artifacts (RED)
    // ═══════════════════════════════════════════════════════════════════════

    #[test] fn linux_at_queue_md() {
        assert_eq!(LINUX_AT_QUEUE.id, "linux_at_queue");
        assert_eq!(LINUX_AT_QUEUE.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_AT_QUEUE.scope, DataScope::System);
        assert!(LINUX_AT_QUEUE.mitre_techniques.contains(&"T1053.001"));
    }
    #[test] fn linux_sshd_config_md() {
        assert_eq!(LINUX_SSHD_CONFIG.id, "linux_sshd_config");
        assert_eq!(LINUX_SSHD_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_SSHD_CONFIG.scope, DataScope::System);
        assert!(LINUX_SSHD_CONFIG.mitre_techniques.contains(&"T1098.004"));
    }
    #[test] fn linux_etc_group_md() {
        assert_eq!(LINUX_ETC_GROUP.id, "linux_etc_group");
        assert_eq!(LINUX_ETC_GROUP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ETC_GROUP.scope, DataScope::System);
        assert!(LINUX_ETC_GROUP.mitre_techniques.contains(&"T1087.001"));
    }
    #[test] fn linux_gnome_keyring_md() {
        assert_eq!(LINUX_GNOME_KEYRING.id, "linux_gnome_keyring");
        assert_eq!(LINUX_GNOME_KEYRING.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GNOME_KEYRING.scope, DataScope::User);
        assert!(LINUX_GNOME_KEYRING.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn linux_kde_kwallet_md() {
        assert_eq!(LINUX_KDE_KWALLET.id, "linux_kde_kwallet");
        assert_eq!(LINUX_KDE_KWALLET.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_KDE_KWALLET.scope, DataScope::User);
        assert!(LINUX_KDE_KWALLET.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn linux_chrome_login_linux_md() {
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.id, "linux_chrome_login_linux");
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_CHROME_LOGIN_LINUX.scope, DataScope::User);
        assert!(LINUX_CHROME_LOGIN_LINUX.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn linux_firefox_logins_linux_md() {
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.id, "linux_firefox_logins_linux");
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_FIREFOX_LOGINS_LINUX.scope, DataScope::User);
        assert!(LINUX_FIREFOX_LOGINS_LINUX.mitre_techniques.contains(&"T1555.003"));
    }
    #[test] fn linux_utmp_md() {
        assert_eq!(LINUX_UTMP.id, "linux_utmp");
        assert_eq!(LINUX_UTMP.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_UTMP.scope, DataScope::System);
        assert!(LINUX_UTMP.mitre_techniques.contains(&"T1078"));
    }
    #[test] fn linux_gcp_credentials_md() {
        assert_eq!(LINUX_GCP_CREDENTIALS.id, "linux_gcp_credentials");
        assert_eq!(LINUX_GCP_CREDENTIALS.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_GCP_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_GCP_CREDENTIALS.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn linux_azure_credentials_md() {
        assert_eq!(LINUX_AZURE_CREDENTIALS.id, "linux_azure_credentials");
        assert_eq!(LINUX_AZURE_CREDENTIALS.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_AZURE_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_AZURE_CREDENTIALS.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn linux_kube_config_md() {
        assert_eq!(LINUX_KUBE_CONFIG.id, "linux_kube_config");
        assert_eq!(LINUX_KUBE_CONFIG.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_KUBE_CONFIG.scope, DataScope::User);
        assert!(LINUX_KUBE_CONFIG.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn linux_git_credentials_md() {
        assert_eq!(LINUX_GIT_CREDENTIALS.id, "linux_git_credentials");
        assert_eq!(LINUX_GIT_CREDENTIALS.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_GIT_CREDENTIALS.scope, DataScope::User);
        assert!(LINUX_GIT_CREDENTIALS.mitre_techniques.contains(&"T1552.001"));
    }
    #[test] fn linux_netrc_md() {
        assert_eq!(LINUX_NETRC.id, "linux_netrc");
        assert_eq!(LINUX_NETRC.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_NETRC.scope, DataScope::User);
        assert!(LINUX_NETRC.mitre_techniques.contains(&"T1552.001"));
    }

    // ── CATALOG completeness (batch F) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_f() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_at_queue", "linux_sshd_config", "linux_etc_group",
            "linux_gnome_keyring", "linux_kde_kwallet",
            "linux_chrome_login_linux", "linux_firefox_logins_linux",
            "linux_utmp",
            "linux_gcp_credentials", "linux_azure_credentials",
            "linux_kube_config", "linux_git_credentials", "linux_netrc",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Batch G — LinuxPersist-sourced artifacts (RED)
    // Source: https://github.com/GuyEldad/LinuxPersist
    // ═══════════════════════════════════════════════════════════════════════

    #[test] fn linux_etc_environment_md() {
        assert_eq!(LINUX_ETC_ENVIRONMENT.id, "linux_etc_environment");
        assert_eq!(LINUX_ETC_ENVIRONMENT.artifact_type, ArtifactType::File);
        assert_eq!(LINUX_ETC_ENVIRONMENT.scope, DataScope::System);
        assert!(LINUX_ETC_ENVIRONMENT.mitre_techniques.contains(&"T1546.004"));
    }
    #[test] fn linux_xdg_autostart_user_md() {
        assert_eq!(LINUX_XDG_AUTOSTART_USER.id, "linux_xdg_autostart_user");
        assert_eq!(LINUX_XDG_AUTOSTART_USER.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_XDG_AUTOSTART_USER.scope, DataScope::User);
        assert!(LINUX_XDG_AUTOSTART_USER.mitre_techniques.contains(&"T1547.014"));
    }
    #[test] fn linux_xdg_autostart_system_md() {
        assert_eq!(LINUX_XDG_AUTOSTART_SYSTEM.id, "linux_xdg_autostart_system");
        assert_eq!(LINUX_XDG_AUTOSTART_SYSTEM.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_XDG_AUTOSTART_SYSTEM.scope, DataScope::System);
        assert!(LINUX_XDG_AUTOSTART_SYSTEM.mitre_techniques.contains(&"T1547.014"));
    }
    #[test] fn linux_networkmanager_dispatcher_md() {
        assert_eq!(LINUX_NETWORKMANAGER_DISPATCHER.id, "linux_networkmanager_dispatcher");
        assert_eq!(LINUX_NETWORKMANAGER_DISPATCHER.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_NETWORKMANAGER_DISPATCHER.scope, DataScope::System);
        assert!(LINUX_NETWORKMANAGER_DISPATCHER.mitre_techniques.contains(&"T1547.013"));
    }
    #[test] fn linux_apt_hooks_md() {
        assert_eq!(LINUX_APT_HOOKS.id, "linux_apt_hooks");
        assert_eq!(LINUX_APT_HOOKS.artifact_type, ArtifactType::Directory);
        assert_eq!(LINUX_APT_HOOKS.scope, DataScope::System);
        assert_eq!(LINUX_APT_HOOKS.os_scope, OsScope::LinuxDebian);
        assert!(LINUX_APT_HOOKS.mitre_techniques.contains(&"T1546.004"));
    }

    // ── CATALOG completeness (batch G) ────────────────────────────────────

    #[test]
    fn catalog_contains_batch_g() {
        let ids: Vec<&str> = CATALOG.list().iter().map(|d| d.id).collect();
        for expected in &[
            "linux_etc_environment",
            "linux_xdg_autostart_user",
            "linux_xdg_autostart_system",
            "linux_networkmanager_dispatcher",
            "linux_apt_hooks",
        ] {
            assert!(ids.contains(expected), "CATALOG missing: {expected}");
        }
    }
}
