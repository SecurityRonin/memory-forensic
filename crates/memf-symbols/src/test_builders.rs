//! Test builders for synthetic symbol tables.

use serde_json::{json, Value};
use std::collections::HashMap;

/// Builds a minimal ISF JSON document for testing.
#[derive(Default)]
pub struct IsfBuilder {
    structs: HashMap<String, IsfStruct>,
    symbols: HashMap<String, u64>,
    base_types: HashMap<String, (u64, bool)>,
}

struct IsfStruct {
    size: u64,
    fields: Vec<(String, u64, String)>, // (name, offset, type_name)
}

impl IsfBuilder {
    /// Create a new builder with common base types pre-registered.
    pub fn new() -> Self {
        let mut b = Self::default();
        b.base_types.insert("int".into(), (4, true));
        b.base_types.insert("unsigned int".into(), (4, false));
        b.base_types.insert("long".into(), (8, true));
        b.base_types.insert("unsigned long".into(), (8, false));
        b.base_types.insert("short".into(), (2, true));
        b.base_types.insert("unsigned short".into(), (2, false));
        b.base_types.insert("char".into(), (1, true));
        b.base_types.insert("unsigned char".into(), (1, false));
        b.base_types.insert("pointer".into(), (8, false));
        b
    }

    /// Add a struct type with its total size.
    pub fn add_struct(mut self, name: &str, size: u64) -> Self {
        self.structs.insert(
            name.into(),
            IsfStruct {
                size,
                fields: Vec::new(),
            },
        );
        self
    }

    /// Add a field to a struct.
    pub fn add_field(
        mut self,
        struct_name: &str,
        field_name: &str,
        offset: u64,
        type_name: &str,
    ) -> Self {
        self.structs
            .get_mut(struct_name)
            .unwrap_or_else(|| panic!("struct {struct_name} not found"))
            .fields
            .push((field_name.into(), offset, type_name.into()));
        self
    }

    /// Add a kernel symbol with its virtual address.
    pub fn add_symbol(mut self, name: &str, address: u64) -> Self {
        self.symbols.insert(name.into(), address);
        self
    }

    /// Build the ISF JSON as a `serde_json::Value`.
    pub fn build_json(&self) -> Value {
        let mut base_types = serde_json::Map::new();
        for (name, (size, signed)) in &self.base_types {
            base_types.insert(
                name.clone(),
                json!({
                    "size": size,
                    "signed": signed,
                    "kind": "int",
                    "endian": "little"
                }),
            );
        }

        let mut user_types = serde_json::Map::new();
        for (name, s) in &self.structs {
            let mut fields = serde_json::Map::new();
            for (fname, offset, tname) in &s.fields {
                fields.insert(
                    fname.clone(),
                    json!({
                        "offset": offset,
                        "type": {
                            "kind": "base",
                            "name": tname
                        }
                    }),
                );
            }
            user_types.insert(
                name.clone(),
                json!({
                    "size": s.size,
                    "fields": fields
                }),
            );
        }

        let mut symbols = serde_json::Map::new();
        for (name, addr) in &self.symbols {
            symbols.insert(name.clone(), json!({ "address": addr }));
        }

        json!({
            "metadata": {
                "format": "6.2.0",
                "producer": {
                    "name": "memf-test",
                    "version": "0.1.0"
                }
            },
            "base_types": base_types,
            "user_types": user_types,
            "enums": {},
            "symbols": symbols
        })
    }

    /// Build the ISF JSON as a byte vector (UTF-8 encoded).
    pub fn build_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&self.build_json()).expect("JSON serialization")
    }

    /// Build a minimal ISF JSON for Windows kernel analysis tests.
    ///
    /// Includes common NT kernel structures with realistic field offsets
    /// matching a typical Windows 10 22H2 kernel (ntkrnlmp.pdb).
    pub fn windows_kernel_preset() -> Self {
        Self::new()
            // _EPROCESS — Windows process object
            .add_struct("_EPROCESS", 2048)
            .add_field("_EPROCESS", "UniqueProcessId", 0x440, "pointer")
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x448, "_LIST_ENTRY")
            .add_field("_EPROCESS", "ImageFileName", 0x5A8, "char")
            .add_field("_EPROCESS", "Pcb", 0x0, "_KPROCESS")
            .add_field(
                "_EPROCESS",
                "InheritedFromUniqueProcessId",
                0x540,
                "pointer",
            )
            .add_field("_EPROCESS", "ObjectTable", 0x570, "pointer")
            .add_field("_EPROCESS", "Token", 0x4B8, "_EX_FAST_REF")
            .add_field("_EPROCESS", "Peb", 0x550, "pointer")
            .add_field("_EPROCESS", "VadRoot", 0x7D8, "_RTL_AVL_TREE")
            .add_field("_EPROCESS", "CreateTime", 0x430, "_LARGE_INTEGER")
            .add_field("_EPROCESS", "ExitTime", 0x438, "_LARGE_INTEGER")
            // _KPROCESS
            .add_struct("_KPROCESS", 896)
            .add_field("_KPROCESS", "DirectoryTableBase", 0x28, "unsigned long")
            .add_field("_KPROCESS", "ThreadListHead", 0x30, "_LIST_ENTRY")
            // _KTHREAD
            .add_struct("_KTHREAD", 1536)
            .add_field("_KTHREAD", "ThreadListEntry", 0x2F8, "_LIST_ENTRY")
            .add_field("_KTHREAD", "Teb", 0xF0, "pointer")
            .add_field("_KTHREAD", "Process", 0x220, "pointer")
            .add_field("_KTHREAD", "Win32StartAddress", 0x680, "pointer")
            .add_field("_KTHREAD", "CreateTime", 0x688, "_LARGE_INTEGER")
            // _ETHREAD
            .add_struct("_ETHREAD", 2048)
            .add_field("_ETHREAD", "Tcb", 0x0, "_KTHREAD")
            .add_field("_ETHREAD", "Cid", 0x620, "_CLIENT_ID")
            .add_field("_ETHREAD", "ThreadListEntry", 0x6B8, "_LIST_ENTRY")
            // _LIST_ENTRY
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            // _UNICODE_STRING
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            // _PEB
            .add_struct("_PEB", 2048)
            .add_field("_PEB", "ImageBaseAddress", 0x10, "pointer")
            .add_field("_PEB", "Ldr", 0x18, "pointer")
            .add_field("_PEB", "ProcessParameters", 0x20, "pointer")
            .add_field("_PEB", "BeingDebugged", 0x02, "unsigned char")
            // _CLIENT_ID
            .add_struct("_CLIENT_ID", 16)
            .add_field("_CLIENT_ID", "UniqueProcess", 0, "pointer")
            .add_field("_CLIENT_ID", "UniqueThread", 8, "pointer")
            // Kernel symbols
            .add_symbol("PsActiveProcessHead", 0xFFFFF805_5A400000)
            .add_symbol("PsLoadedModuleList", 0xFFFFF805_5A410000)
            .add_symbol("KdDebuggerDataBlock", 0xFFFFF805_5A420000)
            .add_symbol("PsInitialSystemProcess", 0xFFFFF805_5A430000)
            .add_symbol("KeNumberProcessors", 0xFFFFF805_5A440000)
    }

    /// Build a minimal ISF JSON for Linux process walking tests.
    pub fn linux_process_preset() -> Self {
        Self::new()
            .add_struct("task_struct", 9024)
            .add_field("task_struct", "pid", 1128, "int")
            .add_field("task_struct", "comm", 1248, "char")
            .add_field("task_struct", "tasks", 1160, "list_head")
            .add_field("task_struct", "mm", 1176, "pointer")
            .add_field("task_struct", "real_parent", 1192, "pointer")
            .add_field("task_struct", "state", 0, "long")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_struct("mm_struct", 2048)
            .add_field("mm_struct", "pgd", 80, "pointer")
            .add_symbol("init_task", 0xFFFF_FFFF_8260_0000)
            .add_symbol("linux_banner", 0xFFFF_FFFF_8200_0000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_produces_valid_json() {
        let json = IsfBuilder::new()
            .add_struct("task_struct", 100)
            .add_field("task_struct", "pid", 8, "int")
            .add_symbol("init_task", 0xFFFF_0000)
            .build_json();

        assert_eq!(json["metadata"]["format"], "6.2.0");
        assert_eq!(json["user_types"]["task_struct"]["size"], 100);
        assert_eq!(
            json["user_types"]["task_struct"]["fields"]["pid"]["offset"],
            8
        );
        assert_eq!(json["symbols"]["init_task"]["address"], 0xFFFF_0000u64);
    }

    #[test]
    fn linux_preset_has_required_fields() {
        let json = IsfBuilder::linux_process_preset().build_json();

        let ts = &json["user_types"]["task_struct"];
        assert_eq!(ts["size"], 9024);
        assert!(ts["fields"]["pid"]["offset"].is_number());
        assert!(ts["fields"]["comm"]["offset"].is_number());
        assert!(ts["fields"]["tasks"]["offset"].is_number());
        assert!(ts["fields"]["mm"]["offset"].is_number());

        let lh = &json["user_types"]["list_head"];
        assert_eq!(lh["size"], 16);

        assert!(json["symbols"]["init_task"]["address"].is_number());
        assert!(json["symbols"]["linux_banner"]["address"].is_number());
    }

    #[test]
    fn windows_kernel_preset_has_required_structures() {
        let json = IsfBuilder::windows_kernel_preset().build_json();
        let ep = &json["user_types"]["_EPROCESS"];
        assert_eq!(ep["size"], 2048);
        assert!(ep["fields"]["UniqueProcessId"]["offset"].is_number());
        assert!(ep["fields"]["ActiveProcessLinks"]["offset"].is_number());
        assert!(ep["fields"]["ImageFileName"]["offset"].is_number());
        let le = &json["user_types"]["_LIST_ENTRY"];
        assert_eq!(le["size"], 16);
        assert!(json["symbols"]["PsActiveProcessHead"]["address"].is_number());
        assert!(json["symbols"]["PsLoadedModuleList"]["address"].is_number());
    }

    #[test]
    fn windows_kernel_preset_has_driver_structs() {
        let json = IsfBuilder::windows_kernel_preset().build_json();

        // _KLDR_DATA_TABLE_ENTRY for driver walking
        let kldr = &json["user_types"]["_KLDR_DATA_TABLE_ENTRY"];
        assert_eq!(kldr["size"], 256);
        assert_eq!(kldr["fields"]["InLoadOrderLinks"]["offset"], 0);
        assert_eq!(kldr["fields"]["DllBase"]["offset"], 48);
        assert_eq!(kldr["fields"]["SizeOfImage"]["offset"], 64);
        assert_eq!(kldr["fields"]["FullDllName"]["offset"], 72);
        assert_eq!(kldr["fields"]["BaseDllName"]["offset"], 88);
    }

    #[test]
    fn windows_kernel_preset_has_ldr_structs() {
        let json = IsfBuilder::windows_kernel_preset().build_json();

        // _PEB_LDR_DATA
        let peb_ldr = &json["user_types"]["_PEB_LDR_DATA"];
        assert_eq!(peb_ldr["size"], 64);
        assert_eq!(peb_ldr["fields"]["Length"]["offset"], 0);
        assert_eq!(peb_ldr["fields"]["Initialized"]["offset"], 4);
        assert_eq!(peb_ldr["fields"]["InLoadOrderModuleList"]["offset"], 16);

        // _LDR_DATA_TABLE_ENTRY
        let ldr = &json["user_types"]["_LDR_DATA_TABLE_ENTRY"];
        assert_eq!(ldr["size"], 256);
        assert_eq!(ldr["fields"]["InLoadOrderLinks"]["offset"], 0);
        assert_eq!(ldr["fields"]["DllBase"]["offset"], 48);
        assert_eq!(ldr["fields"]["SizeOfImage"]["offset"], 64);
        assert_eq!(ldr["fields"]["FullDllName"]["offset"], 72);
        assert_eq!(ldr["fields"]["BaseDllName"]["offset"], 88);
    }

    #[test]
    fn build_bytes_is_valid_json() {
        let bytes = IsfBuilder::linux_process_preset().build_bytes();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["metadata"]["format"].is_string());
    }
}
