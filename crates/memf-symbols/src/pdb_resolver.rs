//! PDB symbol resolver.
//!
//! Provides struct layout and symbol resolution from Windows PDB files.
//! The [`PdbResolver`] implements [`SymbolResolver`] with backend name `"PDB"`.

use std::collections::HashMap;

use crate::{FieldInfo, StructInfo, SymbolResolver};

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

/// PDB symbol resolver.
///
/// Provides struct layout and symbol resolution from Windows PDB files.
/// Implements [`SymbolResolver`] with backend name `"PDB"`.
#[derive(Debug)]
pub struct PdbResolver {
    structs: HashMap<String, StructInfo>,
    symbols: HashMap<String, u64>,
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
        Self { structs, symbols }
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
