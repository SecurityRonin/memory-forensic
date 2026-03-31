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
        if data.len() < BTF_HEADER_SIZE {
            return Err(Error::Malformed("BTF data too short for header".into()));
        }

        let magic = u16::from_le_bytes(data[0..2].try_into().unwrap());
        if magic != BTF_MAGIC {
            return Err(Error::Malformed(format!(
                "bad BTF magic: expected 0x{BTF_MAGIC:04X}, got 0x{magic:04X}"
            )));
        }

        let version = data[2];
        if version != 1 {
            return Err(Error::Malformed(format!(
                "unsupported BTF version: {version}"
            )));
        }

        let _hdr_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let type_off = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let type_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let str_off = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let str_len = u32::from_le_bytes(data[20..24].try_into().unwrap()) as usize;

        let type_start = BTF_HEADER_SIZE + type_off;
        let type_end = type_start + type_len;
        let str_start = BTF_HEADER_SIZE + str_off;
        let str_end = str_start + str_len;

        if type_end > data.len() || str_end > data.len() {
            return Err(Error::Malformed("BTF sections exceed data length".into()));
        }

        let type_section = &data[type_start..type_end];
        let str_section = &data[str_start..str_end];

        let types = parse_type_section(type_section)?;

        let mut structs = HashMap::new();
        for ty in &types {
            if ty.kind == BtfKind::Struct || ty.kind == BtfKind::Union {
                let name = read_btf_string(str_section, ty.name_off);
                if name.is_empty() {
                    continue;
                }

                let mut fields = HashMap::new();
                for member in &ty.members {
                    let fname = read_btf_string(str_section, member.name_off);
                    if fname.is_empty() {
                        continue;
                    }
                    let type_name = resolve_type_name(&types, str_section, member.type_id);
                    fields.insert(
                        fname,
                        FieldInfo {
                            offset: u64::from(member.offset_bytes),
                            type_name,
                        },
                    );
                }

                structs.insert(
                    name,
                    StructInfo {
                        size: u64::from(ty.size),
                        fields,
                    },
                );
            }
        }

        Ok(Self { structs })
    }

    /// Parse BTF from a file path (raw BTF or vmlinux ELF with .BTF section).
    pub fn from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;

        if data.len() >= 4 && &data[0..4] == b"\x7FELF" {
            let btf_section = extract_btf_from_elf(&data)?;
            Self::from_bytes(&btf_section)
        } else {
            Self::from_bytes(&data)
        }
    }

    /// Return the number of structs loaded.
    pub fn struct_count(&self) -> usize {
        self.structs.len()
    }
}

impl SymbolResolver for BtfResolver {
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

    fn symbol_address(&self, _symbol_name: &str) -> Option<u64> {
        None // BTF does not contain symbol addresses
    }

    fn struct_info(&self, struct_name: &str) -> Option<StructInfo> {
        self.structs.get(struct_name).cloned()
    }

    fn backend_name(&self) -> &str {
        "BTF"
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
    let mut types = Vec::new();
    types.push(BtfType {
        name_off: 0,
        kind: BtfKind::Void,
        size: 0,
        members: Vec::new(),
    });

    let mut pos = 0;
    while pos + 12 <= data.len() {
        let name_off = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let info = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
        let size_or_type = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
        pos += 12;

        let kind_val = ((info >> 24) & 0x1F) as u8;
        let vlen = (info & 0xFFFF) as usize;

        let kind = BtfKind::from_u8(kind_val).unwrap_or(BtfKind::Void);

        let mut members = Vec::new();

        match kind {
            BtfKind::Struct | BtfKind::Union => {
                for _ in 0..vlen {
                    if pos + 12 > data.len() {
                        return Err(Error::Malformed("truncated BTF struct member".into()));
                    }
                    let m_name_off = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let m_type_id = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
                    let m_offset = u32::from_le_bytes(data[pos + 8..pos + 12].try_into().unwrap());
                    pos += 12;

                    // BTF member offsets are always in bits; convert to bytes.
                    // When kind_flag is set, offsets can be bitfield-level,
                    // but we still store byte granularity here.
                    let offset_bytes = m_offset / 8;

                    members.push(BtfMember {
                        name_off: m_name_off,
                        type_id: m_type_id,
                        offset_bytes,
                    });
                }
            }
            BtfKind::Enum | BtfKind::FuncProto => {
                pos += vlen * 8;
            }
            BtfKind::Enum64 | BtfKind::DataSec => {
                pos += vlen * 12;
            }
            BtfKind::Array => {
                pos += 12;
            }
            BtfKind::Int | BtfKind::Var | BtfKind::DeclTag => {
                pos += 4;
            }
            _ => {}
        }

        types.push(BtfType {
            name_off,
            kind,
            size: size_or_type,
            members,
        });
    }

    Ok(types)
}

fn read_btf_string(str_section: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= str_section.len() {
        return String::new();
    }
    let end = str_section[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(str_section.len(), |p| start + p);
    String::from_utf8_lossy(&str_section[start..end]).into_owned()
}

fn resolve_type_name(types: &[BtfType], str_section: &[u8], type_id: u32) -> String {
    let id = type_id as usize;
    if id >= types.len() {
        return "unknown".into();
    }
    let ty = &types[id];
    match ty.kind {
        BtfKind::Void => "void".into(),
        BtfKind::Ptr => {
            let pointee = resolve_type_name(types, str_section, ty.size);
            format!("*{pointee}")
        }
        BtfKind::Typedef | BtfKind::Volatile | BtfKind::Const | BtfKind::Restrict => {
            resolve_type_name(types, str_section, ty.size)
        }
        _ => {
            let name = read_btf_string(str_section, ty.name_off);
            if name.is_empty() {
                format!("{:?}", ty.kind)
            } else {
                name
            }
        }
    }
}

fn extract_btf_from_elf(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 64 {
        return Err(Error::Malformed("ELF too short".into()));
    }

    let is_64bit = data[4] == 2;
    let is_le = data[5] == 1;

    if !is_le {
        return Err(Error::Malformed("only little-endian ELF supported".into()));
    }

    if is_64bit {
        extract_btf_from_elf64(data)
    } else {
        Err(Error::Malformed("only 64-bit ELF supported for BTF".into()))
    }
}

fn extract_btf_from_elf64(data: &[u8]) -> Result<Vec<u8>> {
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap()) as usize;

    if e_shoff == 0 || e_shentsize < 64 || e_shnum == 0 {
        return Err(Error::Malformed("no ELF section headers".into()));
    }

    let shstr_off = e_shoff + e_shstrndx * e_shentsize;
    if shstr_off + 64 > data.len() {
        return Err(Error::Malformed(
            "section header string table out of bounds".into(),
        ));
    }
    let shstr_offset =
        u64::from_le_bytes(data[shstr_off + 24..shstr_off + 32].try_into().unwrap()) as usize;
    let shstr_size =
        u64::from_le_bytes(data[shstr_off + 32..shstr_off + 40].try_into().unwrap()) as usize;

    if shstr_offset + shstr_size > data.len() {
        return Err(Error::Malformed(
            "section string table data out of bounds".into(),
        ));
    }
    let shstrtab = &data[shstr_offset..shstr_offset + shstr_size];

    for i in 0..e_shnum {
        let sh_off = e_shoff + i * e_shentsize;
        if sh_off + 64 > data.len() {
            break;
        }
        let sh_name = u32::from_le_bytes(data[sh_off..sh_off + 4].try_into().unwrap());
        let name = read_btf_string(shstrtab, sh_name);
        if name == ".BTF" {
            let sh_offset =
                u64::from_le_bytes(data[sh_off + 24..sh_off + 32].try_into().unwrap()) as usize;
            let sh_size =
                u64::from_le_bytes(data[sh_off + 32..sh_off + 40].try_into().unwrap()) as usize;
            if sh_offset + sh_size > data.len() {
                return Err(Error::Malformed(".BTF section data out of bounds".into()));
            }
            return Ok(data[sh_offset..sh_offset + sh_size].to_vec());
        }
    }

    Err(Error::Malformed("no .BTF section found in ELF".into()))
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
