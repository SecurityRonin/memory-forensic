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

/// Minimum Windows version required for the artifact to exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsScope {
    All,
    Win7Plus,
    Win8Plus,
    Win10Plus,
    Win11Plus,
    Win11_22H2,
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
        assert_eq!(CATALOG.list().len(), 24);
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
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "pca_applaunch_dic");
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
