//! Windows service record enumeration (svcscan).
//!
//! Enumerates Windows services by walking the doubly-linked list of
//! `_SERVICE_RECORD` structures maintained by the Service Control
//! Manager (`services.exe`). The list head is identified via the
//! `ServiceRecordListHead` symbol inside `services.exe` memory.
//!
//! Each `_SERVICE_RECORD` contains the service name, display name,
//! current state, start type, service type, image path, and the
//! account under which it runs.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::{Result, ServiceInfo, ServiceStartType, ServiceState};

/// Maximum service records to walk before stopping (prevents infinite loops).
const MAX_SERVICE_RECORDS: usize = 10_000;

/// Walk the SCM service record list and return service information.
///
/// `list_head_vaddr` is the virtual address of the `ServiceRecordListHead`
/// symbol (a `_LIST_ENTRY` that is the head of the doubly-linked service
/// record list inside `services.exe`).
///
/// For each `_SERVICE_RECORD`, reads the service name, display name,
/// state, start type, service type, image path, object name, and PID.
pub fn walk_services<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    list_head_vaddr: u64,
) -> Result<Vec<ServiceInfo>> {
    let entries = reader.walk_list_with(
        list_head_vaddr,
        "_LIST_ENTRY",
        "Flink",
        "_SERVICE_RECORD",
        "ServiceList",
    )?;

    let mut results = Vec::new();

    for (i, entry_addr) in entries.into_iter().enumerate() {
        if i >= MAX_SERVICE_RECORDS {
            break;
        }
        if let Ok(info) = read_service_record(reader, entry_addr) {
            results.push(info);
        }
    }

    Ok(results)
}

/// Read a single `_SERVICE_RECORD` and extract all fields.
fn read_service_record<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    record_addr: u64,
) -> Result<ServiceInfo> {
    // ServiceName: pointer to a _UNICODE_STRING
    let name_ptr: u64 = reader.read_field(record_addr, "_SERVICE_RECORD", "ServiceName")?;
    let name = if name_ptr != 0 {
        read_unicode_string(reader, name_ptr).unwrap_or_default()
    } else {
        String::new()
    };

    // DisplayName: pointer to a _UNICODE_STRING
    let display_ptr: u64 = reader.read_field(record_addr, "_SERVICE_RECORD", "DisplayName")?;
    let display_name = if display_ptr != 0 {
        read_unicode_string(reader, display_ptr).unwrap_or_default()
    } else {
        String::new()
    };

    // ServiceStatus.dwCurrentState (u32)
    let state_raw: u32 = reader.read_field(record_addr, "_SERVICE_RECORD", "CurrentState")?;
    let state = ServiceState::from_raw(state_raw);

    // ServiceStatus.dwServiceType (u32)
    let service_type: u32 = reader.read_field(record_addr, "_SERVICE_RECORD", "ServiceType")?;

    // StartType (u32)
    let start_raw: u32 = reader.read_field(record_addr, "_SERVICE_RECORD", "StartType")?;
    let start_type = ServiceStartType::from_raw(start_raw);

    // ImagePath: pointer to a _UNICODE_STRING
    let image_ptr: u64 = reader.read_field(record_addr, "_SERVICE_RECORD", "ImagePath")?;
    let image_path = if image_ptr != 0 {
        read_unicode_string(reader, image_ptr).unwrap_or_default()
    } else {
        String::new()
    };

    // ObjectName: pointer to a _UNICODE_STRING
    let obj_ptr: u64 = reader.read_field(record_addr, "_SERVICE_RECORD", "ObjectName")?;
    let object_name = if obj_ptr != 0 {
        read_unicode_string(reader, obj_ptr).unwrap_or_default()
    } else {
        String::new()
    };

    // ProcessId (u32)
    let pid: u32 = reader.read_field(record_addr, "_SERVICE_RECORD", "ProcessId")?;

    Ok(ServiceInfo {
        name,
        display_name,
        state,
        start_type,
        service_type,
        image_path,
        object_name,
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServiceStartType, ServiceState};
    use memf_core::object_reader::ObjectReader;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ── _SERVICE_RECORD field offsets (synthetic layout) ──────────────

    /// ServiceList (_LIST_ENTRY) at offset 0x00.
    const SR_SERVICE_LIST: usize = 0x00;
    /// ServiceName (pointer to _UNICODE_STRING) at offset 0x10.
    const SR_SERVICE_NAME: usize = 0x10;
    /// DisplayName (pointer to _UNICODE_STRING) at offset 0x18.
    const SR_DISPLAY_NAME: usize = 0x18;
    /// CurrentState (u32) at offset 0x20.
    const SR_CURRENT_STATE: usize = 0x20;
    /// ServiceType (u32) at offset 0x24.
    const SR_SERVICE_TYPE: usize = 0x24;
    /// StartType (u32) at offset 0x28.
    const SR_START_TYPE: usize = 0x28;
    /// ImagePath (pointer to _UNICODE_STRING) at offset 0x30.
    const SR_IMAGE_PATH: usize = 0x30;
    /// ObjectName (pointer to _UNICODE_STRING) at offset 0x38.
    const SR_OBJECT_NAME: usize = 0x38;
    /// ProcessId (u32) at offset 0x40.
    const SR_PROCESS_ID: usize = 0x40;

    fn make_svc_reader(ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("_SERVICE_RECORD", 0x80)
            .add_field(
                "_SERVICE_RECORD",
                "ServiceList",
                SR_SERVICE_LIST as u64,
                "_LIST_ENTRY",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ServiceName",
                SR_SERVICE_NAME as u64,
                "pointer",
            )
            .add_field(
                "_SERVICE_RECORD",
                "DisplayName",
                SR_DISPLAY_NAME as u64,
                "pointer",
            )
            .add_field(
                "_SERVICE_RECORD",
                "CurrentState",
                SR_CURRENT_STATE as u64,
                "unsigned int",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ServiceType",
                SR_SERVICE_TYPE as u64,
                "unsigned int",
            )
            .add_field(
                "_SERVICE_RECORD",
                "StartType",
                SR_START_TYPE as u64,
                "unsigned int",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ImagePath",
                SR_IMAGE_PATH as u64,
                "pointer",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ObjectName",
                SR_OBJECT_NAME as u64,
                "pointer",
            )
            .add_field(
                "_SERVICE_RECORD",
                "ProcessId",
                SR_PROCESS_ID as u64,
                "unsigned int",
            )
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer")
            .add_struct("_UNICODE_STRING", 16)
            .add_field("_UNICODE_STRING", "Length", 0, "unsigned short")
            .add_field("_UNICODE_STRING", "MaximumLength", 2, "unsigned short")
            .add_field("_UNICODE_STRING", "Buffer", 8, "pointer")
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    /// Encode a Rust string as UTF-16LE bytes.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    /// Write a _UNICODE_STRING header + buffer data into a page.
    ///
    /// `ustr_off` is the offset within `buf` for the _UNICODE_STRING struct.
    /// `data_vaddr` is the virtual address the Buffer pointer should point to.
    /// `data_off` is the offset within `buf` for the actual UTF-16LE data.
    fn write_unicode_string(
        buf: &mut [u8],
        ustr_off: usize,
        data_vaddr: u64,
        data_off: usize,
        text: &str,
    ) {
        let encoded = utf16le(text);
        let length = encoded.len() as u16;
        // Length
        buf[ustr_off..ustr_off + 2].copy_from_slice(&length.to_le_bytes());
        // MaximumLength
        buf[ustr_off + 2..ustr_off + 4].copy_from_slice(&(length + 2).to_le_bytes());
        // Buffer pointer
        buf[ustr_off + 8..ustr_off + 16].copy_from_slice(&data_vaddr.to_le_bytes());
        // Actual string data
        buf[data_off..data_off + encoded.len()].copy_from_slice(&encoded);
    }

    #[test]
    fn service_state_from_raw() {
        assert_eq!(ServiceState::from_raw(1), ServiceState::Stopped);
        assert_eq!(ServiceState::from_raw(2), ServiceState::StartPending);
        assert_eq!(ServiceState::from_raw(3), ServiceState::StopPending);
        assert_eq!(ServiceState::from_raw(4), ServiceState::Running);
        assert_eq!(ServiceState::from_raw(5), ServiceState::ContinuePending);
        assert_eq!(ServiceState::from_raw(6), ServiceState::PausePending);
        assert_eq!(ServiceState::from_raw(7), ServiceState::Paused);
        assert_eq!(ServiceState::from_raw(0), ServiceState::Unknown(0));
        assert_eq!(ServiceState::from_raw(42), ServiceState::Unknown(42));
        assert_eq!(ServiceState::from_raw(255), ServiceState::Unknown(255));
    }

    #[test]
    fn service_state_display() {
        assert_eq!(ServiceState::Stopped.to_string(), "STOPPED");
        assert_eq!(ServiceState::StartPending.to_string(), "START_PENDING");
        assert_eq!(ServiceState::StopPending.to_string(), "STOP_PENDING");
        assert_eq!(ServiceState::Running.to_string(), "RUNNING");
        assert_eq!(
            ServiceState::ContinuePending.to_string(),
            "CONTINUE_PENDING"
        );
        assert_eq!(ServiceState::PausePending.to_string(), "PAUSE_PENDING");
        assert_eq!(ServiceState::Paused.to_string(), "PAUSED");
        assert_eq!(ServiceState::Unknown(99).to_string(), "Unknown(99)");
    }

    #[test]
    fn service_start_type_from_raw() {
        assert_eq!(ServiceStartType::from_raw(0), ServiceStartType::BootStart);
        assert_eq!(
            ServiceStartType::from_raw(1),
            ServiceStartType::SystemStart
        );
        assert_eq!(ServiceStartType::from_raw(2), ServiceStartType::AutoStart);
        assert_eq!(
            ServiceStartType::from_raw(3),
            ServiceStartType::DemandStart
        );
        assert_eq!(ServiceStartType::from_raw(4), ServiceStartType::Disabled);
        assert_eq!(
            ServiceStartType::from_raw(5),
            ServiceStartType::Unknown(5)
        );
        assert_eq!(
            ServiceStartType::from_raw(42),
            ServiceStartType::Unknown(42)
        );
    }

    #[test]
    fn service_start_type_display() {
        assert_eq!(ServiceStartType::BootStart.to_string(), "BOOT_START");
        assert_eq!(ServiceStartType::SystemStart.to_string(), "SYSTEM_START");
        assert_eq!(ServiceStartType::AutoStart.to_string(), "AUTO_START");
        assert_eq!(ServiceStartType::DemandStart.to_string(), "DEMAND_START");
        assert_eq!(ServiceStartType::Disabled.to_string(), "DISABLED");
        assert_eq!(ServiceStartType::Unknown(7).to_string(), "Unknown(7)");
    }

    #[test]
    fn walk_services_empty() {
        // Empty service list: head Flink/Blink point to self
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_paddr: u64 = 0x0080_0000;

        let mut head_page = vec![0u8; 4096];
        // Flink and Blink both point back to head (empty list)
        head_page[0..8].copy_from_slice(&head_vaddr.to_le_bytes());
        head_page[8..16].copy_from_slice(&head_vaddr.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page);

        let reader = make_svc_reader(ptb);
        let services = walk_services(&reader, head_vaddr).unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn walk_single_service() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_paddr: u64 = 0x0080_0000;
        let svc_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let svc_paddr: u64 = 0x0080_1000;
        // String data page for unicode strings
        let str_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let str_paddr: u64 = 0x0080_2000;

        let mut head_page = vec![0u8; 4096];
        let mut svc_page = vec![0u8; 4096];
        let mut str_page = vec![0u8; 4096];

        // Head: Flink -> svc.ServiceList, Blink -> svc.ServiceList
        let svc_list_addr = svc_vaddr + SR_SERVICE_LIST as u64;
        head_page[0..8].copy_from_slice(&svc_list_addr.to_le_bytes());
        head_page[8..16].copy_from_slice(&svc_list_addr.to_le_bytes());

        // svc.ServiceList: Flink -> head, Blink -> head (single entry, circular)
        svc_page[SR_SERVICE_LIST..SR_SERVICE_LIST + 8]
            .copy_from_slice(&head_vaddr.to_le_bytes());
        svc_page[SR_SERVICE_LIST + 8..SR_SERVICE_LIST + 16]
            .copy_from_slice(&head_vaddr.to_le_bytes());

        // ServiceName -> _UNICODE_STRING at str_vaddr + 0x000, data at str_vaddr + 0x100
        let name_ustr_vaddr = str_vaddr;
        svc_page[SR_SERVICE_NAME..SR_SERVICE_NAME + 8]
            .copy_from_slice(&name_ustr_vaddr.to_le_bytes());
        write_unicode_string(
            &mut str_page,
            0x000,
            str_vaddr + 0x100,
            0x100,
            "Dnscache",
        );

        // DisplayName -> _UNICODE_STRING at str_vaddr + 0x200, data at str_vaddr + 0x300
        let disp_ustr_vaddr = str_vaddr + 0x200;
        svc_page[SR_DISPLAY_NAME..SR_DISPLAY_NAME + 8]
            .copy_from_slice(&disp_ustr_vaddr.to_le_bytes());
        write_unicode_string(
            &mut str_page,
            0x200,
            str_vaddr + 0x300,
            0x300,
            "DNS Client",
        );

        // CurrentState = 4 (RUNNING)
        svc_page[SR_CURRENT_STATE..SR_CURRENT_STATE + 4].copy_from_slice(&4u32.to_le_bytes());
        // ServiceType = 0x20 (SERVICE_WIN32_SHARE_PROCESS)
        svc_page[SR_SERVICE_TYPE..SR_SERVICE_TYPE + 4].copy_from_slice(&0x20u32.to_le_bytes());
        // StartType = 2 (AUTO_START)
        svc_page[SR_START_TYPE..SR_START_TYPE + 4].copy_from_slice(&2u32.to_le_bytes());

        // ImagePath -> _UNICODE_STRING at str_vaddr + 0x400, data at str_vaddr + 0x500
        let img_ustr_vaddr = str_vaddr + 0x400;
        svc_page[SR_IMAGE_PATH..SR_IMAGE_PATH + 8]
            .copy_from_slice(&img_ustr_vaddr.to_le_bytes());
        write_unicode_string(
            &mut str_page,
            0x400,
            str_vaddr + 0x500,
            0x500,
            "C:\\Windows\\system32\\svchost.exe -k NetworkService",
        );

        // ObjectName -> _UNICODE_STRING at str_vaddr + 0x700, data at str_vaddr + 0x800
        let obj_ustr_vaddr = str_vaddr + 0x700;
        svc_page[SR_OBJECT_NAME..SR_OBJECT_NAME + 8]
            .copy_from_slice(&obj_ustr_vaddr.to_le_bytes());
        write_unicode_string(
            &mut str_page,
            0x700,
            str_vaddr + 0x800,
            0x800,
            "NT AUTHORITY\\NetworkService",
        );

        // ProcessId = 1084
        svc_page[SR_PROCESS_ID..SR_PROCESS_ID + 4].copy_from_slice(&1084u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(svc_vaddr, svc_paddr, flags::WRITABLE)
            .map_4k(str_vaddr, str_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .write_phys(svc_paddr, &svc_page)
            .write_phys(str_paddr, &str_page);

        let reader = make_svc_reader(ptb);
        let services = walk_services(&reader, head_vaddr).unwrap();

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "Dnscache");
        assert_eq!(services[0].display_name, "DNS Client");
        assert_eq!(services[0].state, ServiceState::Running);
        assert_eq!(services[0].start_type, ServiceStartType::AutoStart);
        assert_eq!(services[0].service_type, 0x20);
        assert!(services[0].image_path.contains("svchost.exe"));
        assert_eq!(services[0].object_name, "NT AUTHORITY\\NetworkService");
        assert_eq!(services[0].pid, 1084);
    }

    #[test]
    fn walk_two_services() {
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_paddr: u64 = 0x0080_0000;
        let svc1_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let svc1_paddr: u64 = 0x0080_1000;
        let svc2_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let svc2_paddr: u64 = 0x0080_2000;
        let str1_vaddr: u64 = 0xFFFF_8000_0010_3000;
        let str1_paddr: u64 = 0x0080_3000;
        let str2_vaddr: u64 = 0xFFFF_8000_0010_4000;
        let str2_paddr: u64 = 0x0080_4000;

        let mut head_page = vec![0u8; 4096];
        let mut svc1_page = vec![0u8; 4096];
        let mut svc2_page = vec![0u8; 4096];
        let mut str1_page = vec![0u8; 4096];
        let mut str2_page = vec![0u8; 4096];

        let svc1_list = svc1_vaddr + SR_SERVICE_LIST as u64;
        let svc2_list = svc2_vaddr + SR_SERVICE_LIST as u64;

        // Head -> svc1 -> svc2 -> head (circular)
        head_page[0..8].copy_from_slice(&svc1_list.to_le_bytes()); // Flink
        head_page[8..16].copy_from_slice(&svc2_list.to_le_bytes()); // Blink

        // svc1.ServiceList: Flink -> svc2, Blink -> head
        svc1_page[SR_SERVICE_LIST..SR_SERVICE_LIST + 8]
            .copy_from_slice(&svc2_list.to_le_bytes());
        svc1_page[SR_SERVICE_LIST + 8..SR_SERVICE_LIST + 16]
            .copy_from_slice(&head_vaddr.to_le_bytes());

        // svc2.ServiceList: Flink -> head, Blink -> svc1
        svc2_page[SR_SERVICE_LIST..SR_SERVICE_LIST + 8]
            .copy_from_slice(&head_vaddr.to_le_bytes());
        svc2_page[SR_SERVICE_LIST + 8..SR_SERVICE_LIST + 16]
            .copy_from_slice(&svc1_list.to_le_bytes());

        // svc1: "Spooler" / "Print Spooler", RUNNING, AUTO_START, type=0x10
        let name1_ustr = str1_vaddr;
        svc1_page[SR_SERVICE_NAME..SR_SERVICE_NAME + 8]
            .copy_from_slice(&name1_ustr.to_le_bytes());
        write_unicode_string(&mut str1_page, 0x000, str1_vaddr + 0x100, 0x100, "Spooler");

        let disp1_ustr = str1_vaddr + 0x200;
        svc1_page[SR_DISPLAY_NAME..SR_DISPLAY_NAME + 8]
            .copy_from_slice(&disp1_ustr.to_le_bytes());
        write_unicode_string(
            &mut str1_page,
            0x200,
            str1_vaddr + 0x300,
            0x300,
            "Print Spooler",
        );

        svc1_page[SR_CURRENT_STATE..SR_CURRENT_STATE + 4].copy_from_slice(&4u32.to_le_bytes());
        svc1_page[SR_SERVICE_TYPE..SR_SERVICE_TYPE + 4].copy_from_slice(&0x10u32.to_le_bytes());
        svc1_page[SR_START_TYPE..SR_START_TYPE + 4].copy_from_slice(&2u32.to_le_bytes());

        let img1_ustr = str1_vaddr + 0x400;
        svc1_page[SR_IMAGE_PATH..SR_IMAGE_PATH + 8]
            .copy_from_slice(&img1_ustr.to_le_bytes());
        write_unicode_string(
            &mut str1_page,
            0x400,
            str1_vaddr + 0x500,
            0x500,
            "C:\\Windows\\system32\\spoolsv.exe",
        );

        let obj1_ustr = str1_vaddr + 0x700;
        svc1_page[SR_OBJECT_NAME..SR_OBJECT_NAME + 8]
            .copy_from_slice(&obj1_ustr.to_le_bytes());
        write_unicode_string(
            &mut str1_page,
            0x700,
            str1_vaddr + 0x800,
            0x800,
            "LocalSystem",
        );

        svc1_page[SR_PROCESS_ID..SR_PROCESS_ID + 4].copy_from_slice(&2048u32.to_le_bytes());

        // svc2: "BITS" / "Background Intelligent Transfer Service", STOPPED, DEMAND_START
        let name2_ustr = str2_vaddr;
        svc2_page[SR_SERVICE_NAME..SR_SERVICE_NAME + 8]
            .copy_from_slice(&name2_ustr.to_le_bytes());
        write_unicode_string(&mut str2_page, 0x000, str2_vaddr + 0x100, 0x100, "BITS");

        let disp2_ustr = str2_vaddr + 0x200;
        svc2_page[SR_DISPLAY_NAME..SR_DISPLAY_NAME + 8]
            .copy_from_slice(&disp2_ustr.to_le_bytes());
        write_unicode_string(
            &mut str2_page,
            0x200,
            str2_vaddr + 0x300,
            0x300,
            "Background Intelligent Transfer Service",
        );

        svc2_page[SR_CURRENT_STATE..SR_CURRENT_STATE + 4].copy_from_slice(&1u32.to_le_bytes());
        svc2_page[SR_SERVICE_TYPE..SR_SERVICE_TYPE + 4].copy_from_slice(&0x20u32.to_le_bytes());
        svc2_page[SR_START_TYPE..SR_START_TYPE + 4].copy_from_slice(&3u32.to_le_bytes());

        let img2_ustr = str2_vaddr + 0x400;
        svc2_page[SR_IMAGE_PATH..SR_IMAGE_PATH + 8]
            .copy_from_slice(&img2_ustr.to_le_bytes());
        write_unicode_string(
            &mut str2_page,
            0x400,
            str2_vaddr + 0x500,
            0x500,
            "C:\\Windows\\system32\\svchost.exe -k netsvcs",
        );

        let obj2_ustr = str2_vaddr + 0x700;
        svc2_page[SR_OBJECT_NAME..SR_OBJECT_NAME + 8]
            .copy_from_slice(&obj2_ustr.to_le_bytes());
        write_unicode_string(
            &mut str2_page,
            0x700,
            str2_vaddr + 0x800,
            0x800,
            "LocalSystem",
        );

        svc2_page[SR_PROCESS_ID..SR_PROCESS_ID + 4].copy_from_slice(&0u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(svc1_vaddr, svc1_paddr, flags::WRITABLE)
            .map_4k(svc2_vaddr, svc2_paddr, flags::WRITABLE)
            .map_4k(str1_vaddr, str1_paddr, flags::WRITABLE)
            .map_4k(str2_vaddr, str2_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_page)
            .write_phys(svc1_paddr, &svc1_page)
            .write_phys(svc2_paddr, &svc2_page)
            .write_phys(str1_paddr, &str1_page)
            .write_phys(str2_paddr, &str2_page);

        let reader = make_svc_reader(ptb);
        let services = walk_services(&reader, head_vaddr).unwrap();

        assert_eq!(services.len(), 2);

        // First service: Spooler
        assert_eq!(services[0].name, "Spooler");
        assert_eq!(services[0].display_name, "Print Spooler");
        assert_eq!(services[0].state, ServiceState::Running);
        assert_eq!(services[0].start_type, ServiceStartType::AutoStart);
        assert_eq!(services[0].service_type, 0x10);
        assert!(services[0].image_path.contains("spoolsv.exe"));
        assert_eq!(services[0].object_name, "LocalSystem");
        assert_eq!(services[0].pid, 2048);

        // Second service: BITS
        assert_eq!(services[1].name, "BITS");
        assert_eq!(
            services[1].display_name,
            "Background Intelligent Transfer Service"
        );
        assert_eq!(services[1].state, ServiceState::Stopped);
        assert_eq!(services[1].start_type, ServiceStartType::DemandStart);
        assert_eq!(services[1].service_type, 0x20);
        assert!(services[1].image_path.contains("svchost.exe"));
        assert_eq!(services[1].pid, 0);
    }
}
