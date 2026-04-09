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
    #[allow(clippy::too_many_lines)]
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
            // _KLDR_DATA_TABLE_ENTRY for driver walking
            .add_struct("_KLDR_DATA_TABLE_ENTRY", 256)
            .add_field(
                "_KLDR_DATA_TABLE_ENTRY",
                "InLoadOrderLinks",
                0,
                "_LIST_ENTRY",
            )
            .add_field("_KLDR_DATA_TABLE_ENTRY", "DllBase", 48, "pointer")
            .add_field("_KLDR_DATA_TABLE_ENTRY", "SizeOfImage", 64, "unsigned int")
            .add_field(
                "_KLDR_DATA_TABLE_ENTRY",
                "FullDllName",
                72,
                "_UNICODE_STRING",
            )
            .add_field(
                "_KLDR_DATA_TABLE_ENTRY",
                "BaseDllName",
                88,
                "_UNICODE_STRING",
            )
            // _PEB_LDR_DATA for DLL walking
            .add_struct("_PEB_LDR_DATA", 64)
            .add_field("_PEB_LDR_DATA", "Length", 0, "unsigned int")
            .add_field("_PEB_LDR_DATA", "Initialized", 4, "unsigned char")
            .add_field("_PEB_LDR_DATA", "InLoadOrderModuleList", 16, "_LIST_ENTRY")
            .add_field(
                "_PEB_LDR_DATA",
                "InMemoryOrderModuleList",
                32,
                "_LIST_ENTRY",
            )
            .add_field(
                "_PEB_LDR_DATA",
                "InInitializationOrderModuleList",
                48,
                "_LIST_ENTRY",
            )
            // _LDR_DATA_TABLE_ENTRY for DLL list entries
            .add_struct("_LDR_DATA_TABLE_ENTRY", 256)
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "InLoadOrderLinks",
                0,
                "_LIST_ENTRY",
            )
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "InMemoryOrderLinks",
                16,
                "_LIST_ENTRY",
            )
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "InInitializationOrderLinks",
                32,
                "_LIST_ENTRY",
            )
            .add_field("_LDR_DATA_TABLE_ENTRY", "DllBase", 48, "pointer")
            .add_field("_LDR_DATA_TABLE_ENTRY", "SizeOfImage", 64, "unsigned int")
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "FullDllName",
                72,
                "_UNICODE_STRING",
            )
            .add_field(
                "_LDR_DATA_TABLE_ENTRY",
                "BaseDllName",
                88,
                "_UNICODE_STRING",
            )
            // _RTL_USER_PROCESS_PARAMETERS (accessed via PEB.ProcessParameters)
            .add_struct("_RTL_USER_PROCESS_PARAMETERS", 1024)
            .add_field(
                "_RTL_USER_PROCESS_PARAMETERS",
                "ImagePathName",
                0x60,
                "_UNICODE_STRING",
            )
            .add_field(
                "_RTL_USER_PROCESS_PARAMETERS",
                "CommandLine",
                0x70,
                "_UNICODE_STRING",
            )
            .add_field(
                "_RTL_USER_PROCESS_PARAMETERS",
                "Environment",
                0x80,
                "pointer",
            )
            // _DRIVER_OBJECT (for IRP hook detection)
            .add_struct("_DRIVER_OBJECT", 336)
            .add_field("_DRIVER_OBJECT", "DriverStart", 0x18, "pointer")
            .add_field("_DRIVER_OBJECT", "DriverSize", 0x20, "unsigned int")
            .add_field("_DRIVER_OBJECT", "DriverName", 0x38, "_UNICODE_STRING")
            .add_field("_DRIVER_OBJECT", "MajorFunction", 0x70, "pointer")
            // _KSERVICE_TABLE_DESCRIPTOR (SSDT)
            .add_struct("_KSERVICE_TABLE_DESCRIPTOR", 32)
            .add_field("_KSERVICE_TABLE_DESCRIPTOR", "Base", 0x0, "pointer")
            .add_field("_KSERVICE_TABLE_DESCRIPTOR", "Limit", 0x10, "unsigned int")
            // _RTL_AVL_TREE (VAD root)
            .add_struct("_RTL_AVL_TREE", 8)
            .add_field("_RTL_AVL_TREE", "Root", 0x0, "pointer")
            // _MMVAD_SHORT (VAD entry)
            .add_struct("_MMVAD_SHORT", 80)
            .add_field("_MMVAD_SHORT", "Left", 0x0, "pointer")
            .add_field("_MMVAD_SHORT", "Right", 0x8, "pointer")
            .add_field("_MMVAD_SHORT", "StartingVpn", 0x18, "unsigned long")
            .add_field("_MMVAD_SHORT", "EndingVpn", 0x20, "unsigned long")
            .add_field("_MMVAD_SHORT", "Flags", 0x30, "unsigned int")
            // _TOKEN (process token)
            .add_struct("_TOKEN", 256)
            .add_field("_TOKEN", "Privileges", 0x40, "_SEP_TOKEN_PRIVILEGES")
            .add_field("_TOKEN", "UserAndGroupCount", 0x88, "unsigned int")
            .add_field("_TOKEN", "UserAndGroups", 0x90, "pointer")
            // _SID_AND_ATTRIBUTES (token user/group entry)
            .add_struct("_SID_AND_ATTRIBUTES", 16)
            .add_field("_SID_AND_ATTRIBUTES", "Sid", 0x0, "pointer")
            .add_field("_SID_AND_ATTRIBUTES", "Attributes", 0x8, "unsigned int")
            // _SID (security identifier)
            .add_struct("_SID", 16)
            .add_field("_SID", "Revision", 0x0, "unsigned char")
            .add_field("_SID", "SubAuthorityCount", 0x1, "unsigned char")
            .add_field("_SID", "IdentifierAuthority", 0x2, "array")
            .add_field("_SID", "SubAuthority", 0x8, "array")
            // _SEP_TOKEN_PRIVILEGES
            .add_struct("_SEP_TOKEN_PRIVILEGES", 24)
            .add_field("_SEP_TOKEN_PRIVILEGES", "Present", 0x0, "unsigned long")
            .add_field("_SEP_TOKEN_PRIVILEGES", "Enabled", 0x8, "unsigned long")
            .add_field(
                "_SEP_TOKEN_PRIVILEGES",
                "EnabledByDefault",
                0x10,
                "unsigned long",
            )
            // _HANDLE_TABLE (per-process handle table)
            .add_struct("_HANDLE_TABLE", 256)
            .add_field("_HANDLE_TABLE", "TableCode", 0x08, "unsigned long")
            .add_field(
                "_HANDLE_TABLE",
                "NextHandleNeedingPool",
                0x3C,
                "unsigned int",
            )
            // _HANDLE_TABLE_ENTRY (16 bytes per handle slot)
            .add_struct("_HANDLE_TABLE_ENTRY", 16)
            .add_field(
                "_HANDLE_TABLE_ENTRY",
                "ObjectPointerBits",
                0x0,
                "unsigned long",
            )
            .add_field(
                "_HANDLE_TABLE_ENTRY",
                "GrantedAccessBits",
                0x8,
                "unsigned int",
            )
            // _OBJECT_HEADER (precedes every kernel object)
            .add_struct("_OBJECT_HEADER", 56)
            .add_field("_OBJECT_HEADER", "TypeIndex", 0x18, "unsigned char")
            .add_field("_OBJECT_HEADER", "InfoMask", 0x1a, "unsigned char")
            .add_field("_OBJECT_HEADER", "Body", 0x30, "unsigned char")
            // _OBJECT_TYPE (kernel object type descriptor)
            .add_struct("_OBJECT_TYPE", 216)
            .add_field("_OBJECT_TYPE", "Name", 0x10, "_UNICODE_STRING")
            .add_field("_OBJECT_TYPE", "Index", 0xC8, "unsigned char")
            // _OBJECT_DIRECTORY (kernel namespace directory, 37-bucket hash table)
            .add_struct("_OBJECT_DIRECTORY", 336)
            .add_field("_OBJECT_DIRECTORY", "HashBuckets", 0, "pointer")
            // _OBJECT_DIRECTORY_ENTRY (hash bucket chain entry)
            .add_struct("_OBJECT_DIRECTORY_ENTRY", 24)
            .add_field("_OBJECT_DIRECTORY_ENTRY", "ChainLink", 0, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "Object", 8, "pointer")
            .add_field("_OBJECT_DIRECTORY_ENTRY", "HashValue", 0x10, "unsigned int")
            // _OBJECT_HEADER_NAME_INFO (optional header with object name)
            .add_struct("_OBJECT_HEADER_NAME_INFO", 32)
            .add_field("_OBJECT_HEADER_NAME_INFO", "Directory", 0, "pointer")
            .add_field("_OBJECT_HEADER_NAME_INFO", "Name", 0x10, "_UNICODE_STRING")
            // _KMUTANT (kernel mutex/mutant object body)
            .add_struct("_KMUTANT", 56)
            .add_field("_KMUTANT", "OwnerThread", 0x28, "pointer")
            .add_field("_KMUTANT", "Abandoned", 0x30, "unsigned char")
            .add_field("_KMUTANT", "ApcDisable", 0x31, "unsigned char")
            // _FILE_OBJECT (kernel file object)
            .add_struct("_FILE_OBJECT", 216)
            .add_field("_FILE_OBJECT", "DeviceObject", 0x08, "pointer")
            .add_field("_FILE_OBJECT", "Flags", 0x44, "unsigned int")
            .add_field("_FILE_OBJECT", "FileName", 0x58, "_UNICODE_STRING")
            .add_field("_FILE_OBJECT", "CurrentByteOffset", 0x70, "unsigned long")
            .add_field("_FILE_OBJECT", "SharedRead", 0x78, "unsigned char")
            .add_field("_FILE_OBJECT", "SharedWrite", 0x79, "unsigned char")
            .add_field("_FILE_OBJECT", "SharedDelete", 0x7A, "unsigned char")
            .add_field("_FILE_OBJECT", "DeletePending", 0x48, "unsigned char")
            .add_field("_FILE_OBJECT", "ReadAccess", 0x49, "unsigned char")
            .add_field("_FILE_OBJECT", "WriteAccess", 0x4A, "unsigned char")
            // _DEVICE_OBJECT (kernel device object, for device name chain)
            .add_struct("_DEVICE_OBJECT", 344)
            .add_field("_DEVICE_OBJECT", "DriverObject", 0x08, "pointer")
            .add_field("_DEVICE_OBJECT", "DeviceType", 0x34, "unsigned int")
            // _CMHIVE (registry hive container)
            // Layout based on Windows 10 22H2:
            //   Hive (_HHIVE) at offset 0x0
            //   FileFullPath (_UNICODE_STRING) at offset 0x70
            //   FileUserName (_UNICODE_STRING) at offset 0x80
            //   HiveList (_LIST_ENTRY) at offset 0x300
            .add_struct("_CMHIVE", 0x600)
            .add_field("_CMHIVE", "Hive", 0x0, "_HHIVE")
            .add_field("_CMHIVE", "FileFullPath", 0x70, "_UNICODE_STRING")
            .add_field("_CMHIVE", "FileUserName", 0x80, "_UNICODE_STRING")
            .add_field("_CMHIVE", "HiveList", 0x300, "_LIST_ENTRY")
            // _HHIVE (core hive data)
            //   BaseBlock pointer at offset 0x28
            //   Storage[0] (_DUAL, Stable) at offset 0x38
            //   Storage[1] (_DUAL, Volatile) at offset 0x58
            .add_struct("_HHIVE", 0x600)
            .add_field("_HHIVE", "BaseBlock", 0x28, "pointer")
            .add_field("_HHIVE", "Storage", 0x38, "_DUAL")
            // _DUAL (hive storage descriptor)
            //   Length at offset 0x0
            .add_struct("_DUAL", 0x20)
            .add_field("_DUAL", "Length", 0x0, "unsigned int")
            // Kernel symbols
            .add_symbol("CmpHiveListHead", 0xFFFFF805_5A4B0000)
            .add_symbol("ObTypeIndexTable", 0xFFFFF805_5A490000)
            .add_symbol("PsActiveProcessHead", 0xFFFFF805_5A400000)
            .add_symbol("PsLoadedModuleList", 0xFFFFF805_5A410000)
            .add_symbol("KdDebuggerDataBlock", 0xFFFFF805_5A420000)
            .add_symbol("PsInitialSystemProcess", 0xFFFFF805_5A430000)
            .add_symbol("KeNumberProcessors", 0xFFFFF805_5A440000)
            .add_symbol("KeServiceDescriptorTable", 0xFFFFF805_5A450000)
            .add_symbol("PspCreateProcessNotifyRoutine", 0xFFFFF805_5A460000)
            .add_symbol("PspCreateThreadNotifyRoutine", 0xFFFFF805_5A470000)
            .add_symbol("PspLoadImageNotifyRoutine", 0xFFFFF805_5A480000)
            .add_symbol("ObpRootDirectoryObject", 0xFFFFF805_5A4A0000)
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
            .add_symbol("swapper_pg_dir", 0xFFFF_FFFF_8220_0000)
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

    #[test]
    fn linux_preset_has_swapper_pg_dir() {
        let json = IsfBuilder::linux_process_preset().build_json();
        assert!(json["symbols"]["swapper_pg_dir"]["address"].is_number());
    }
}
