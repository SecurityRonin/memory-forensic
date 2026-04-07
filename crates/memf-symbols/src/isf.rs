//! ISF JSON (Volatility 3-compatible) symbol resolver.
//!
//! Parses the JSON format used by Volatility 3's symbol tables:
//! <https://volatility3.readthedocs.io/en/latest/symbol-tables.html>

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::{FieldInfo, Result, StructInfo, SymbolResolver};

/// ISF JSON symbol resolver.
#[derive(Debug, Clone)]
pub struct IsfResolver {
    structs: HashMap<String, StructInfo>,
    symbols: HashMap<String, u64>,
}

#[derive(Deserialize)]
struct IsfDocument {
    #[serde(default)]
    #[allow(dead_code)]
    base_types: HashMap<String, IsfBaseType>,
    #[serde(default)]
    user_types: HashMap<String, IsfUserType>,
    #[serde(default)]
    symbols: HashMap<String, IsfSymbol>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct IsfBaseType {
    size: u64,
    #[serde(default)]
    signed: bool,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    endian: String,
}

#[derive(Deserialize)]
struct IsfUserType {
    size: u64,
    #[serde(default)]
    fields: HashMap<String, IsfField>,
}

#[derive(Deserialize)]
struct IsfField {
    offset: u64,
    #[serde(rename = "type", default)]
    field_type: Option<IsfFieldType>,
}

#[derive(Deserialize)]
struct IsfFieldType {
    #[serde(default)]
    #[allow(dead_code)]
    kind: String,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct IsfSymbol {
    address: u64,
}

impl IsfResolver {
    /// Parse an ISF JSON document from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let doc: IsfDocument = serde_json::from_slice(data)?;
        Ok(Self::from_document(doc))
    }

    /// Parse an ISF JSON document from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Parse an ISF JSON document from a `serde_json::Value`.
    pub fn from_value(value: &serde_json::Value) -> Result<Self> {
        let doc: IsfDocument = serde_json::from_value(value.clone())?;
        Ok(Self::from_document(doc))
    }

    fn from_document(doc: IsfDocument) -> Self {
        let mut structs = HashMap::new();

        for (name, user_type) in doc.user_types {
            let mut fields = HashMap::new();
            for (fname, field) in user_type.fields {
                let type_name = field
                    .field_type
                    .as_ref()
                    .map(|t| t.name.clone())
                    .unwrap_or_default();
                fields.insert(
                    fname,
                    FieldInfo {
                        offset: field.offset,
                        type_name,
                    },
                );
            }
            structs.insert(
                name,
                StructInfo {
                    size: user_type.size,
                    fields,
                },
            );
        }

        let symbols: HashMap<String, u64> = doc
            .symbols
            .into_iter()
            .map(|(name, sym)| (name, sym.address))
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

impl SymbolResolver for IsfResolver {
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
        "ISF JSON"
    }

    fn clone_boxed(&self) -> Box<dyn SymbolResolver> {
        Box::new(self.clone())
    }
}

/// Search for ISF JSON symbol files in standard locations.
///
/// Search order:
/// 1. `explicit_path` if provided (file or directory)
/// 2. `$MEMF_SYMBOLS_PATH` environment variable (colon-separated list of directories)
/// 3. `~/.memf/symbols/` default directory
///
/// Returns all `.json` files found, sorted by name.
pub fn discover_isf_files(explicit_path: Option<&Path>) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();

    if let Some(path) = explicit_path {
        if path.is_file() {
            files.push(path.to_path_buf());
            return files;
        }
        if path.is_dir() {
            collect_json_files(path, &mut files);
            files.sort();
            return files;
        }
    }

    if let Ok(env_path) = std::env::var("MEMF_SYMBOLS_PATH") {
        for dir in env_path.split(':') {
            let p = Path::new(dir);
            if p.is_dir() {
                collect_json_files(p, &mut files);
            }
        }
        if !files.is_empty() {
            files.sort();
            return files;
        }
    }

    if let Some(home) = home_dir() {
        let default_dir = home.join(".memf").join("symbols");
        if default_dir.is_dir() {
            collect_json_files(&default_dir, &mut files);
        }
    }

    files.sort();
    files
}

fn collect_json_files(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") && path.is_file() {
                files.push(path);
            }
        }
    }
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME").map(std::path::PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::IsfBuilder;

    #[test]
    fn resolve_field_offset() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        assert_eq!(resolver.field_offset("task_struct", "pid"), Some(1128));
        assert_eq!(resolver.field_offset("task_struct", "comm"), Some(1248));
        assert_eq!(resolver.field_offset("task_struct", "nonexistent"), None);
        assert_eq!(resolver.field_offset("nonexistent", "pid"), None);
    }

    #[test]
    fn resolve_struct_size() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        assert_eq!(resolver.struct_size("task_struct"), Some(9024));
        assert_eq!(resolver.struct_size("list_head"), Some(16));
        assert_eq!(resolver.struct_size("nonexistent"), None);
    }

    #[test]
    fn resolve_symbol_address() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        assert_eq!(
            resolver.symbol_address("init_task"),
            Some(0xFFFF_FFFF_8260_0000)
        );
        assert_eq!(resolver.symbol_address("nonexistent"), None);
    }

    #[test]
    fn struct_info_returns_all_fields() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();

        let info = resolver.struct_info("task_struct").unwrap();
        assert_eq!(info.size, 9024);
        assert!(info.fields.contains_key("pid"));
        assert!(info.fields.contains_key("comm"));
        assert!(info.fields.contains_key("tasks"));
        assert!(info.fields.contains_key("mm"));
    }

    #[test]
    fn backend_name() {
        let json = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        assert_eq!(resolver.backend_name(), "ISF JSON");
    }

    #[test]
    fn from_bytes_roundtrip() {
        let bytes = IsfBuilder::linux_process_preset().build_bytes();
        let resolver = IsfResolver::from_bytes(&bytes).unwrap();
        assert!(resolver.struct_count() >= 3);
        assert!(resolver.symbol_count() >= 2);
    }

    #[test]
    fn empty_document_ok() {
        let json = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        assert_eq!(resolver.struct_count(), 0);
        assert_eq!(resolver.symbol_count(), 0);
    }

    #[test]
    fn invalid_json_is_error() {
        let result = IsfResolver::from_bytes(b"not json");
        assert!(result.is_err());
    }

    #[test]
    fn dyn_dispatch_works() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let dyn_ref: &dyn SymbolResolver = &resolver;
        assert_eq!(dyn_ref.field_offset("task_struct", "pid"), Some(1128));
        assert_eq!(dyn_ref.backend_name(), "ISF JSON");
    }

    #[test]
    fn discover_explicit_file() {
        let bytes = IsfBuilder::new().build_bytes();
        let dir = std::env::temp_dir().join("memf_test_isf_discover");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.json");
        std::fs::write(&file, &bytes).unwrap();

        let found = discover_isf_files(Some(&file));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0], file);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_explicit_dir() {
        let dir = std::env::temp_dir().join("memf_test_isf_discover_dir");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.json"), b"{}").unwrap();
        std::fs::write(dir.join("b.json"), b"{}").unwrap();
        std::fs::write(dir.join("c.txt"), b"not json").unwrap();

        let found = discover_isf_files(Some(&dir));
        assert_eq!(found.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn discover_nonexistent_returns_empty() {
        let found = discover_isf_files(Some(Path::new("/nonexistent/path")));
        assert!(found.is_empty());
    }

    #[test]
    fn from_path_roundtrip() {
        let bytes = IsfBuilder::linux_process_preset().build_bytes();
        let path = std::env::temp_dir().join("memf_test_isf_from_path.json");
        std::fs::write(&path, &bytes).unwrap();
        let resolver = IsfResolver::from_path(&path).unwrap();
        assert!(resolver.struct_count() >= 3);
        assert!(resolver.symbol_count() >= 2);
        assert_eq!(resolver.field_offset("task_struct", "pid"), Some(1128));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn struct_info_returns_none_for_unknown() {
        let json = IsfBuilder::linux_process_preset().build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        assert!(resolver.struct_info("completely_unknown_struct").is_none());
    }
}
