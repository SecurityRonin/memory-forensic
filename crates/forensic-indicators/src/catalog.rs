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
        &[]
    }

    /// Look up a descriptor by its `id` field.
    pub fn by_id(&self, _id: &str) -> Option<&ArtifactDescriptor> {
        None
    }

    /// Return all descriptors matching the given query. Every `Some` field in
    /// the query must match; `None` fields are wildcards.
    pub fn filter(&self, _query: &ArtifactQuery) -> Vec<&ArtifactDescriptor> {
        vec![]
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
        _descriptor: &ArtifactDescriptor,
        _name: &str,
        _raw: &[u8],
    ) -> Result<ArtifactRecord, DecodeError> {
        Err(DecodeError::UnsupportedDecoder("stub"))
    }
}

// ── Decode implementation ────────────────────────────────────────────────────

/// ROT13-decode an ASCII string: rotate A-Z and a-z by 13, leave other chars.
fn rot13(_s: &str) -> String {
    String::new()
}

/// Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO 8601 UTC.
///
/// Returns `None` for zero or negative Unix epoch values.
fn filetime_to_iso8601(_ft: u64) -> Option<String> {
    None
}

/// Read a u16 LE at `offset`, returning 0 if out of bounds.
fn read_u16_le(_data: &[u8], _offset: usize) -> u16 {
    0
}

/// Read a u32 LE at `offset`, returning 0 if out of bounds.
fn read_u32_le(_data: &[u8], _offset: usize) -> u32 {
    0
}

/// Read a u64 LE at `offset`, returning 0 if out of bounds.
fn read_u64_le(_data: &[u8], _offset: usize) -> u64 {
    0
}

/// Read an i32 LE at `offset`, returning 0 if out of bounds.
fn read_i32_le(_data: &[u8], _offset: usize) -> i32 {
    0
}

/// Read an i64 LE at `offset`, returning 0 if out of bounds.
fn read_i64_le(_data: &[u8], _offset: usize) -> i64 {
    0
}

/// Decode a single [`BinaryField`] from a raw buffer into an [`ArtifactValue`].
fn decode_binary_field(_field: &BinaryField, _raw: &[u8]) -> Result<ArtifactValue, DecodeError> {
    Err(DecodeError::UnsupportedDecoder("stub"))
}

/// Build the default UID for a registry artifact.
fn build_registry_uid(_descriptor: &ArtifactDescriptor, _name: &str) -> String {
    String::new()
}

/// Build the default UID for a file artifact.
fn build_file_uid(_descriptor: &ArtifactDescriptor, _name: &str) -> String {
    String::new()
}

/// Decode a slice of [`BinaryField`]s from raw bytes, returning field values
/// and the first FILETIME timestamp encountered (if any).
#[allow(clippy::type_complexity)]
fn decode_binary_fields(
    _binary_fields: &[BinaryField],
    _raw: &[u8],
) -> Result<(Vec<(&'static str, ArtifactValue)>, Option<String>), DecodeError> {
    Ok((vec![], None))
}

/// Core decode function: routes to the appropriate decoder variant.
#[allow(clippy::too_many_lines)]
fn decode_artifact(
    _descriptor: &ArtifactDescriptor,
    _name: &str,
    _raw: &[u8],
) -> Result<ArtifactRecord, DecodeError> {
    Err(DecodeError::UnsupportedDecoder("stub"))
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

// ── Global catalog ───────────────────────────────────────────────────────────

/// The global forensic artifact catalog containing all known artifact descriptors.
pub static CATALOG: ForensicCatalog = ForensicCatalog::new(&[
    USERASSIST_EXE,
    RUN_KEY_HKLM_RUN,
    TYPED_URLS,
    PCA_APPLAUNCH_DIC,
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
        assert_eq!(CATALOG.list().len(), 4);
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
