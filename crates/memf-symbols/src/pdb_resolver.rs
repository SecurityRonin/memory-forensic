//! PDB symbol resolver.
//!
//! Provides struct layout and symbol resolution from Windows PDB files.
//! The [`PdbResolver`] implements [`SymbolResolver`] with backend name `"PDB"`.

use std::collections::HashMap;
use std::path::Path;

use crate::{FieldInfo, StructInfo, SymbolResolver};

/// PDB identification info (GUID + age).
#[derive(Debug, Clone)]
pub struct PdbInfo {
    /// PDB GUID as hex string with dashes (e.g., "1B72224D-37B8-1792-2820-0ED8994498B2").
    pub guid: String,
    /// PDB age counter.
    pub age: u32,
}

/// Parsed struct from a PDB file, before conversion to StructInfo.
#[derive(Debug, Clone)]
pub struct PdbStruct {
    /// Struct/class name.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// Fields with offsets and type names.
    pub fields: Vec<PdbField>,
}

/// A field within a parsed PDB struct.
#[derive(Debug, Clone)]
pub struct PdbField {
    /// Field name.
    pub name: String,
    /// Byte offset within the struct.
    pub offset: u64,
    /// Type name (e.g., "unsigned long", "_LIST_ENTRY", "*_EPROCESS").
    pub type_name: String,
}

/// A symbol (global variable or function) from a PDB file.
#[derive(Debug, Clone)]
pub struct PdbSymbol {
    /// Symbol name.
    pub name: String,
    /// Relative Virtual Address.
    pub rva: u32,
}

/// Pre-parsed PDB data -- the testable boundary between PDB parsing and resolution.
#[derive(Debug, Clone, Default)]
pub struct PdbParsedData {
    /// Parsed struct definitions.
    pub structs: Vec<PdbStruct>,
    /// Parsed symbols.
    pub symbols: Vec<PdbSymbol>,
}

/// Parse a PDB from a source implementing the required traits.
fn parse_pdb<'s, S: pdb::Source<'s> + 's>(
    _source: S,
) -> crate::Result<(PdbParsedData, Option<PdbInfo>)> {
    // Stub: will be implemented in GREEN phase
    Err(crate::Error::Pdb("not yet implemented".into()))
}

/// PDB symbol resolver.
///
/// Provides struct layout and symbol resolution from Windows PDB files.
/// Implements [`SymbolResolver`] with backend name `"PDB"`.
#[derive(Debug)]
pub struct PdbResolver {
    structs: HashMap<String, StructInfo>,
    symbols: HashMap<String, u64>,
    pdb_info: Option<PdbInfo>,
}

impl PdbResolver {
    /// Build a resolver from pre-parsed PDB data.
    ///
    /// This is the primary constructor for testing -- it takes already-extracted
    /// struct/symbol data and converts to the SymbolResolver format.
    pub fn from_parsed(data: PdbParsedData) -> Self {
        let mut structs = HashMap::new();
        for s in data.structs {
            let mut fields = HashMap::new();
            for f in s.fields {
                fields.insert(
                    f.name,
                    FieldInfo {
                        offset: f.offset,
                        type_name: f.type_name,
                    },
                );
            }
            structs.insert(
                s.name,
                StructInfo {
                    size: s.size,
                    fields,
                },
            );
        }
        let symbols = data
            .symbols
            .into_iter()
            .map(|s| (s.name, u64::from(s.rva)))
            .collect();
        Self {
            structs,
            symbols,
            pdb_info: None,
        }
    }

    /// Parse a PDB file from a filesystem path.
    pub fn from_path(path: &Path) -> crate::Result<Self> {
        let file = std::fs::File::open(path)?;
        let (data, info) = parse_pdb(file)?;
        let mut resolver = Self::from_parsed(data);
        resolver.pdb_info = info;
        Ok(resolver)
    }

    /// Parse a PDB from in-memory bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let cursor = std::io::Cursor::new(bytes.to_vec());
        let (data, info) = parse_pdb(cursor)?;
        let mut resolver = Self::from_parsed(data);
        resolver.pdb_info = info;
        Ok(resolver)
    }

    /// Return PDB identification info, if available.
    pub fn pdb_info(&self) -> Option<&PdbInfo> {
        self.pdb_info.as_ref()
    }

    /// Return the number of structs loaded.
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }

    /// Return the number of symbols loaded.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

impl SymbolResolver for PdbResolver {
    fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u64> {
        self.structs
            .get(struct_name)?
            .fields
            .get(field_name)
            .map(|f| f.offset)
    }

    fn struct_size(&self, struct_name: &str) -> Option<u64> {
        self.structs.get(struct_name).map(|s| s.size)
    }

    fn symbol_address(&self, symbol_name: &str) -> Option<u64> {
        self.symbols.get(symbol_name).copied()
    }

    fn struct_info(&self, struct_name: &str) -> Option<StructInfo> {
        self.structs.get(struct_name).cloned()
    }

    fn backend_name(&self) -> &str {
        "PDB"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_single_struct_data() -> PdbParsedData {
        PdbParsedData {
            structs: vec![PdbStruct {
                name: "_EPROCESS".into(),
                size: 2048,
                fields: vec![
                    PdbField {
                        name: "UniqueProcessId".into(),
                        offset: 0x440,
                        type_name: "pointer".into(),
                    },
                    PdbField {
                        name: "ActiveProcessLinks".into(),
                        offset: 0x448,
                        type_name: "_LIST_ENTRY".into(),
                    },
                ],
            }],
            symbols: vec![],
        }
    }

    #[test]
    fn from_parsed_single_struct() {
        let resolver = PdbResolver::from_parsed(make_single_struct_data());
        assert_eq!(resolver.struct_size("_EPROCESS"), Some(2048));
        assert_eq!(
            resolver.field_offset("_EPROCESS", "UniqueProcessId"),
            Some(0x440)
        );
        assert_eq!(
            resolver.field_offset("_EPROCESS", "ActiveProcessLinks"),
            Some(0x448)
        );
        assert_eq!(resolver.struct_count(), 1);
    }

    #[test]
    fn from_parsed_multiple_structs() {
        let data = PdbParsedData {
            structs: vec![
                PdbStruct {
                    name: "_EPROCESS".into(),
                    size: 2048,
                    fields: vec![PdbField {
                        name: "Pcb".into(),
                        offset: 0,
                        type_name: "_KPROCESS".into(),
                    }],
                },
                PdbStruct {
                    name: "_KPROCESS".into(),
                    size: 896,
                    fields: vec![PdbField {
                        name: "DirectoryTableBase".into(),
                        offset: 0x28,
                        type_name: "unsigned long".into(),
                    }],
                },
            ],
            symbols: vec![],
        };
        let resolver = PdbResolver::from_parsed(data);
        assert_eq!(resolver.struct_size("_EPROCESS"), Some(2048));
        assert_eq!(resolver.struct_size("_KPROCESS"), Some(896));
        assert_eq!(
            resolver.field_offset("_KPROCESS", "DirectoryTableBase"),
            Some(0x28)
        );
        assert_eq!(resolver.struct_count(), 2);
    }

    #[test]
    fn from_parsed_symbols() {
        let data = PdbParsedData {
            structs: vec![],
            symbols: vec![
                PdbSymbol {
                    name: "PsActiveProcessHead".into(),
                    rva: 0x400000,
                },
                PdbSymbol {
                    name: "PsLoadedModuleList".into(),
                    rva: 0x410000,
                },
                PdbSymbol {
                    name: "KdDebuggerDataBlock".into(),
                    rva: 0x420000,
                },
            ],
        };
        let resolver = PdbResolver::from_parsed(data);
        assert_eq!(
            resolver.symbol_address("PsActiveProcessHead"),
            Some(0x400000)
        );
        assert_eq!(
            resolver.symbol_address("PsLoadedModuleList"),
            Some(0x410000)
        );
        assert_eq!(
            resolver.symbol_address("KdDebuggerDataBlock"),
            Some(0x420000)
        );
        assert_eq!(resolver.symbol_count(), 3);
    }

    #[test]
    fn from_parsed_empty() {
        let data = PdbParsedData::default();
        let resolver = PdbResolver::from_parsed(data);
        assert_eq!(resolver.struct_count(), 0);
        assert_eq!(resolver.symbol_count(), 0);
    }

    #[test]
    fn struct_info_returns_all_fields() {
        let resolver = PdbResolver::from_parsed(make_single_struct_data());
        let info = resolver
            .struct_info("_EPROCESS")
            .expect("struct should exist");
        assert_eq!(info.size, 2048);
        assert_eq!(info.fields.len(), 2);
        assert_eq!(info.fields["UniqueProcessId"].offset, 0x440);
        assert_eq!(info.fields["UniqueProcessId"].type_name, "pointer");
        assert_eq!(info.fields["ActiveProcessLinks"].offset, 0x448);
        assert_eq!(info.fields["ActiveProcessLinks"].type_name, "_LIST_ENTRY");
    }

    #[test]
    fn unknown_struct_returns_none() {
        let resolver = PdbResolver::from_parsed(make_single_struct_data());
        assert_eq!(resolver.field_offset("_NONEXISTENT", "foo"), None);
        assert_eq!(resolver.struct_size("_NONEXISTENT"), None);
        assert!(resolver.struct_info("_NONEXISTENT").is_none());
    }

    #[test]
    fn unknown_field_returns_none() {
        let resolver = PdbResolver::from_parsed(make_single_struct_data());
        assert_eq!(resolver.field_offset("_EPROCESS", "NonexistentField"), None);
    }

    #[test]
    fn unknown_symbol_returns_none() {
        let data = PdbParsedData {
            structs: vec![],
            symbols: vec![PdbSymbol {
                name: "PsActiveProcessHead".into(),
                rva: 0x400000,
            }],
        };
        let resolver = PdbResolver::from_parsed(data);
        assert_eq!(resolver.symbol_address("NonexistentSymbol"), None);
    }

    #[test]
    fn backend_name_is_pdb() {
        let resolver = PdbResolver::from_parsed(PdbParsedData::default());
        assert_eq!(resolver.backend_name(), "PDB");
    }

    #[test]
    fn dyn_dispatch_works() {
        let resolver = PdbResolver::from_parsed(make_single_struct_data());
        let dyn_resolver: &dyn SymbolResolver = &resolver;
        assert_eq!(dyn_resolver.backend_name(), "PDB");
        assert_eq!(dyn_resolver.struct_size("_EPROCESS"), Some(2048));
        assert_eq!(
            dyn_resolver.field_offset("_EPROCESS", "UniqueProcessId"),
            Some(0x440)
        );
    }

    // ── PDB file reader tests (Task 3) ──────────────────────────────────

    #[test]
    fn from_bytes_invalid_data() {
        let garbage = b"This is definitely not a PDB file!!!!";
        let err = PdbResolver::from_bytes(garbage).unwrap_err();
        assert!(
            matches!(err, crate::Error::Pdb(_)),
            "expected Pdb error, got: {err:?}"
        );
    }

    #[test]
    fn from_bytes_empty() {
        let err = PdbResolver::from_bytes(&[]).unwrap_err();
        // Could be Pdb or Io depending on implementation — both are acceptable
        assert!(
            matches!(err, crate::Error::Pdb(_) | crate::Error::Io(_)),
            "expected Pdb or Io error, got: {err:?}"
        );
    }

    #[test]
    fn from_path_nonexistent() {
        let err =
            PdbResolver::from_path(Path::new("/tmp/this_pdb_file_does_not_exist_12345.pdb"))
                .unwrap_err();
        assert!(
            matches!(err, crate::Error::Io(_)),
            "expected Io error, got: {err:?}"
        );
    }

    #[test]
    fn from_path_not_pdb() {
        // Write garbage to a temp file and try to parse it as PDB
        let dir = std::env::temp_dir().join("memf_test_not_pdb");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("garbage.pdb");
        std::fs::write(&path, b"NOT A PDB FILE AT ALL").unwrap();

        let err = PdbResolver::from_path(&path).unwrap_err();
        assert!(
            matches!(err, crate::Error::Pdb(_)),
            "expected Pdb error, got: {err:?}"
        );

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn pdb_info_none_for_from_parsed() {
        let resolver = PdbResolver::from_parsed(PdbParsedData::default());
        assert!(
            resolver.pdb_info().is_none(),
            "from_parsed() should set pdb_info to None"
        );
    }

    #[test]
    fn pdb_error_from_impl() {
        // Trigger a real pdb::Error by parsing garbage — the From impl should convert it
        let cursor = std::io::Cursor::new(vec![0u8; 32]);
        let pdb_result = pdb::PDB::open(cursor);
        assert!(pdb_result.is_err(), "garbage should fail PDB parsing");
        let pdb_err = pdb_result.unwrap_err();
        let our_err: crate::Error = pdb_err.into();
        assert!(
            matches!(our_err, crate::Error::Pdb(ref msg) if !msg.is_empty()),
            "expected non-empty Pdb error, got: {our_err:?}"
        );
    }

    #[test]
    #[ignore]
    fn from_path_real_pdb() {
        // Integration test: requires a real PDB file at /tmp/test.pdb
        let path = Path::new("/tmp/test.pdb");
        if !path.exists() {
            eprintln!("Skipping: /tmp/test.pdb not found");
            return;
        }
        let resolver = PdbResolver::from_path(path).expect("should parse real PDB");
        assert!(
            resolver.struct_count() > 0,
            "real PDB should have structs, got 0"
        );
        assert!(
            resolver.symbol_count() > 0,
            "real PDB should have symbols, got 0"
        );
        // pdb_info should be populated for real PDBs
        let info = resolver.pdb_info().expect("real PDB should have pdb_info");
        assert!(!info.guid.is_empty(), "GUID should not be empty");
        assert!(info.age > 0, "age should be > 0");
        eprintln!("PDB info: GUID={}, age={}", info.guid, info.age);
        eprintln!(
            "Parsed {} structs, {} symbols",
            resolver.struct_count(),
            resolver.symbol_count()
        );
    }

    #[test]
    fn from_parsed_windows_kernel() {
        // Realistic _EPROCESS with Windows 10 22H2 offsets
        let data = PdbParsedData {
            structs: vec![
                PdbStruct {
                    name: "_EPROCESS".into(),
                    size: 2048,
                    fields: vec![
                        PdbField {
                            name: "UniqueProcessId".into(),
                            offset: 0x440,
                            type_name: "pointer".into(),
                        },
                        PdbField {
                            name: "ActiveProcessLinks".into(),
                            offset: 0x448,
                            type_name: "_LIST_ENTRY".into(),
                        },
                        PdbField {
                            name: "ImageFileName".into(),
                            offset: 0x5A8,
                            type_name: "char".into(),
                        },
                        PdbField {
                            name: "Pcb".into(),
                            offset: 0x0,
                            type_name: "_KPROCESS".into(),
                        },
                        PdbField {
                            name: "InheritedFromUniqueProcessId".into(),
                            offset: 0x540,
                            type_name: "pointer".into(),
                        },
                    ],
                },
                PdbStruct {
                    name: "_LIST_ENTRY".into(),
                    size: 16,
                    fields: vec![
                        PdbField {
                            name: "Flink".into(),
                            offset: 0,
                            type_name: "pointer".into(),
                        },
                        PdbField {
                            name: "Blink".into(),
                            offset: 8,
                            type_name: "pointer".into(),
                        },
                    ],
                },
            ],
            symbols: vec![
                PdbSymbol {
                    name: "PsActiveProcessHead".into(),
                    rva: 0x400000,
                },
                PdbSymbol {
                    name: "PsInitialSystemProcess".into(),
                    rva: 0x430000,
                },
            ],
        };
        let resolver = PdbResolver::from_parsed(data);

        // Verify _EPROCESS offsets match Win10 22H2
        assert_eq!(
            resolver.field_offset("_EPROCESS", "UniqueProcessId"),
            Some(0x440)
        );
        assert_eq!(
            resolver.field_offset("_EPROCESS", "ActiveProcessLinks"),
            Some(0x448)
        );
        assert_eq!(
            resolver.field_offset("_EPROCESS", "ImageFileName"),
            Some(0x5A8)
        );
        assert_eq!(resolver.field_offset("_EPROCESS", "Pcb"), Some(0x0));
        assert_eq!(
            resolver.field_offset("_EPROCESS", "InheritedFromUniqueProcessId"),
            Some(0x540)
        );

        // Verify _LIST_ENTRY
        assert_eq!(resolver.struct_size("_LIST_ENTRY"), Some(16));
        assert_eq!(resolver.field_offset("_LIST_ENTRY", "Flink"), Some(0));
        assert_eq!(resolver.field_offset("_LIST_ENTRY", "Blink"), Some(8));

        // Verify symbols
        assert_eq!(
            resolver.symbol_address("PsActiveProcessHead"),
            Some(0x400000)
        );
        assert_eq!(
            resolver.symbol_address("PsInitialSystemProcess"),
            Some(0x430000)
        );
    }
}
