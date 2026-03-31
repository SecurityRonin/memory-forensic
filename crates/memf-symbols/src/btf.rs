//! BTF (BPF Type Format) symbol resolver.
//!
//! Parses the BTF section from a vmlinux binary or raw BTF data.
//! BTF provides struct layouts and type information but NOT symbol addresses.
//!
//! Reference: <https://www.kernel.org/doc/html/latest/bpf/btf.html>

use std::collections::HashMap;
use std::path::Path;

use crate::{Error, FieldInfo, Result, StructInfo, SymbolResolver};

/// BTF header magic: 0xEB9F (little-endian).
const BTF_MAGIC: u16 = 0xEB9F;

/// BTF header size (version 1).
const BTF_HEADER_SIZE: usize = 24;

/// BTF type kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BtfKind {
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    DataSec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Ptr),
            3 => Some(Self::Array),
            4 => Some(Self::Struct),
            5 => Some(Self::Union),
            6 => Some(Self::Enum),
            7 => Some(Self::Fwd),
            8 => Some(Self::Typedef),
            9 => Some(Self::Volatile),
            10 => Some(Self::Const),
            11 => Some(Self::Restrict),
            12 => Some(Self::Func),
            13 => Some(Self::FuncProto),
            14 => Some(Self::Var),
            15 => Some(Self::DataSec),
            16 => Some(Self::Float),
            17 => Some(Self::DeclTag),
            18 => Some(Self::TypeTag),
            19 => Some(Self::Enum64),
            _ => None,
        }
    }
}

/// BTF symbol resolver.
///
/// Provides struct and type resolution from BTF data.
/// Does NOT provide symbol addresses -- `symbol_address()` always returns `None`.
#[derive(Debug)]
pub struct BtfResolver {
    structs: HashMap<String, StructInfo>,
}

impl BtfResolver {
    /// Parse BTF data from a raw byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        todo!()
    }

    /// Parse BTF from a file path (raw BTF or vmlinux ELF with .BTF section).
    pub fn from_path(path: &Path) -> Result<Self> {
        todo!()
    }

    /// Return the number of structs loaded.
    pub fn struct_count(&self) -> usize {
        todo!()
    }
}

impl SymbolResolver for BtfResolver {
    fn field_offset(&self, struct_name: &str, field_name: &str) -> Option<u64> {
        todo!()
    }

    fn struct_size(&self, struct_name: &str) -> Option<u64> {
        todo!()
    }

    fn symbol_address(&self, _symbol_name: &str) -> Option<u64> {
        todo!()
    }

    fn struct_info(&self, struct_name: &str) -> Option<StructInfo> {
        todo!()
    }

    fn backend_name(&self) -> &str {
        todo!()
    }
}

// ---- Internal parsing helpers ----

#[derive(Debug)]
struct BtfType {
    name_off: u32,
    kind: BtfKind,
    size: u32,
    members: Vec<BtfMember>,
}

#[derive(Debug)]
struct BtfMember {
    name_off: u32,
    type_id: u32,
    offset_bytes: u32,
}

fn parse_type_section(data: &[u8]) -> Result<Vec<BtfType>> {
    todo!()
}

fn read_btf_string(str_section: &[u8], offset: u32) -> String {
    todo!()
}

fn resolve_type_name(types: &[BtfType], str_section: &[u8], type_id: u32) -> String {
    todo!()
}

fn extract_btf_from_elf(data: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

fn extract_btf_from_elf64(data: &[u8]) -> Result<Vec<u8>> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic BTF blob for testing.
    fn build_test_btf() -> Vec<u8> {
        let mut buf = Vec::new();

        // String section: "\0int\0task_struct\0pid\0state\0"
        let strings: Vec<u8> = b"\0int\0task_struct\0pid\0state\0".to_vec();
        // Offsets: int=1, task_struct=5, pid=17, state=21

        let mut types = Vec::new();

        // Type 1: int (kind=1, size=4, vlen=0)
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&(1u32 << 24).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes()); // INT encoding

        // Type 2: task_struct (kind=4, size=16, vlen=2)
        types.extend_from_slice(&5u32.to_le_bytes());
        types.extend_from_slice(&((4u32 << 24) | 2).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());

        // Member 1: pid at bit offset 0, type_id=1
        types.extend_from_slice(&17u32.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());

        // Member 2: state at bit offset 64 (= byte 8), type_id=1
        types.extend_from_slice(&21u32.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());

        let type_off = 0u32;
        let type_len = types.len() as u32;
        let str_off = type_len;
        let str_len = strings.len() as u32;

        buf.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        buf.push(1);
        buf.push(0);
        buf.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        buf.extend_from_slice(&type_off.to_le_bytes());
        buf.extend_from_slice(&type_len.to_le_bytes());
        buf.extend_from_slice(&str_off.to_le_bytes());
        buf.extend_from_slice(&str_len.to_le_bytes());

        buf.extend_from_slice(&types);
        buf.extend_from_slice(&strings);

        buf
    }

    #[test]
    fn parse_btf_header() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();
        assert!(resolver.struct_count() >= 1);
    }

    #[test]
    fn resolve_struct_from_btf() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();

        assert_eq!(resolver.struct_size("task_struct"), Some(16));
        assert_eq!(resolver.field_offset("task_struct", "pid"), Some(0));
        assert_eq!(resolver.field_offset("task_struct", "state"), Some(8));
    }

    #[test]
    fn btf_has_no_symbol_addresses() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();
        assert_eq!(resolver.symbol_address("anything"), None);
    }

    #[test]
    fn btf_backend_name() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();
        assert_eq!(resolver.backend_name(), "BTF");
    }

    #[test]
    fn btf_bad_magic() {
        let mut btf = build_test_btf();
        btf[0] = 0xFF;
        btf[1] = 0xFF;
        let err = BtfResolver::from_bytes(&btf).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn btf_too_short() {
        let err = BtfResolver::from_bytes(&[0xEB, 0x9F]).unwrap_err();
        assert!(matches!(err, Error::Malformed(_)));
    }

    #[test]
    fn btf_struct_info() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();
        let info = resolver.struct_info("task_struct").unwrap();
        assert_eq!(info.size, 16);
        assert!(info.fields.contains_key("pid"));
        assert!(info.fields.contains_key("state"));
    }

    #[test]
    fn btf_dyn_dispatch() {
        let btf = build_test_btf();
        let resolver = BtfResolver::from_bytes(&btf).unwrap();
        let dyn_ref: &dyn SymbolResolver = &resolver;
        assert_eq!(dyn_ref.field_offset("task_struct", "pid"), Some(0));
        assert_eq!(dyn_ref.symbol_address("anything"), None);
    }
}
