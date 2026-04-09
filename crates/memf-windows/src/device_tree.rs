//! Windows device tree enumeration.
//!
//! Enumerates the Windows device tree by walking DriverObject -> DeviceObject
//! chains. Each kernel driver maintains a linked list of device objects it has
//! created. Rootkits create device objects to intercept I/O requests (filter
//! drivers, device attachment). Hidden or rogue device objects that do not
//! appear in the official device tree are strong indicators of compromise.
//!
//! Equivalent to Volatility's `devicetree` plugin. MITRE ATT&CK T1014.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::unicode::read_unicode_string;
use crate::Result;

/// Maximum number of drivers to iterate before bailing out (cycle protection).
const MAX_DRIVERS: usize = 4096;

/// Maximum number of device objects per driver (cycle protection).
const MAX_DEVICES_PER_DRIVER: usize = 1024;

/// A single entry in the device tree: one device object owned by a driver.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceTreeEntry {
    /// Name of the owning driver (from `_DRIVER_OBJECT.DriverName`).
    pub driver_name: String,
    /// Virtual address of the `_DRIVER_OBJECT`.
    pub driver_addr: u64,
    /// Name of this device object (best-effort, may be empty).
    pub device_name: String,
    /// Virtual address of the `_DEVICE_OBJECT`.
    pub device_addr: u64,
    /// Device type code from `_DEVICE_OBJECT.DeviceType`.
    pub device_type: u32,
    /// Virtual address of the attached (layered) device, or 0 if none.
    pub attached_device: u64,
    /// Whether this device/driver combination looks suspicious.
    pub is_suspicious: bool,
}

/// Map a `_DEVICE_OBJECT.DeviceType` value to a human-readable name.
///
/// Common values from the Windows DDK `FILE_DEVICE_*` constants.
pub fn device_type_name(device_type: u32) -> &'static str {
    match device_type {
        0x01 => "Beep",
        0x02 => "CDRom",
        0x03 => "CDRomFileSystem",
        0x04 => "Controller",
        0x05 => "Datalink",
        0x06 => "Dfs",
        0x07 => "Disk",
        0x08 => "DiskFileSystem",
        0x09 => "FileSystem",
        0x0A => "InPortPort",
        0x0B => "Keyboard",
        0x0C => "Mailslot",
        0x0D => "MidiIn",
        0x0E => "MidiOut",
        0x0F => "Mouse",
        0x10 => "MultiUncProvider",
        0x11 => "NamedPipe",
        0x12 => "Network",
        0x13 => "NetworkBrowser",
        0x14 => "NetworkFileSystem",
        0x15 => "Null",
        0x16 => "ParallelPort",
        0x17 => "PhysicalNetcard",
        0x18 => "Printer",
        0x19 => "Scanner",
        0x1A => "SerialMousePort",
        0x1B => "SerialPort",
        0x1C => "Screen",
        0x1D => "Sound",
        0x1E => "Streams",
        0x1F => "Tape",
        0x20 => "TapeFileSystem",
        0x21 => "Transport",
        0x22 => "Unknown",
        0x23 => "Video",
        0x24 => "VirtualDisk",
        0x25 => "WaveIn",
        0x26 => "WaveOut",
        0x27 => "Port8042",
        0x28 => "NetworkRedirector",
        0x29 => "Battery",
        0x2A => "BusExtender",
        0x2B => "Modem",
        0x2C => "Vdm",
        0x2D => "MassStorage",
        0x2E => "Smb",
        0x2F => "Ks",
        0x30 => "Changer",
        0x31 => "Smartcard",
        0x32 => "Acpi",
        0x33 => "Dvd",
        0x34 => "FullscreenVideo",
        0x35 => "DfsFileSystem",
        0x36 => "DfsVolume",
        0x37 => "Serenum",
        0x38 => "TerminalServer",
        0x39 => "Ksec",
        0x3A => "Fips",
        0x3B => "Infiniband",
        0x3E => "Vmbus",
        0x3F => "CryptProvider",
        0x40 => "Wpd",
        0x41 => "Bluetooth",
        0x42 => "MtComposite",
        0x43 => "MtTransport",
        0x44 => "Biometric",
        0x45 => "Pmi",
        _ => "Other",
    }
}

/// Classify whether a device/driver combination is suspicious.
///
/// Heuristics:
/// - Empty driver name: rootkits often create unnamed driver objects.
/// - Device type 0: invalid/uninitialized, suggests hand-crafted object.
/// - Device type > 0x40: outside the standard range of known device types.
pub fn classify_device(driver_name: &str, device_type: u32) -> bool {
    if driver_name.is_empty() {
        return true;
    }
    if device_type == 0 {
        return true;
    }
    if device_type > 0x40 {
        return true;
    }
    false
}

/// Walk the Windows device tree starting from a driver object list.
///
/// `driver_list_head` is the virtual address of the list head that links
/// `_DRIVER_OBJECT` structures (via their `DriverSection` `_LIST_ENTRY`).
/// For each driver, follows the `DeviceObject` pointer and walks the
/// `NextDevice` chain to enumerate all device objects.
pub fn walk_device_tree<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
    driver_list_head: u64,
) -> Result<Vec<DeviceTreeEntry>> {
    // Offsets within _DRIVER_OBJECT
    let driver_section_off = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "DriverSection")
        .unwrap_or(0x28);
    let driver_name_off = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "DriverName")
        .unwrap_or(0x38);
    let device_object_off = reader
        .symbols()
        .field_offset("_DRIVER_OBJECT", "DeviceObject")
        .unwrap_or(0x08);

    // Offsets within _DEVICE_OBJECT
    let next_device_off = reader
        .symbols()
        .field_offset("_DEVICE_OBJECT", "NextDevice")
        .unwrap_or(0x10);
    let attached_device_off = reader
        .symbols()
        .field_offset("_DEVICE_OBJECT", "AttachedDevice")
        .unwrap_or(0x18);
    let device_type_off = reader
        .symbols()
        .field_offset("_DEVICE_OBJECT", "DeviceType")
        .unwrap_or(0x34);

    let mut results = Vec::new();
    let mut visited_drivers = std::collections::HashSet::new();
    let mut current = driver_list_head;
    let mut count = 0;

    loop {
        // Read Flink from the list head / current entry
        let flink_bytes = match reader.read_bytes(current, 8) {
            Ok(b) => b,
            Err(_) => break,
        };
        let flink = u64::from_le_bytes(flink_bytes[..8].try_into().unwrap());

        // Empty list: Flink points back to head
        if flink == driver_list_head {
            break;
        }

        if !visited_drivers.insert(flink) {
            break; // cycle detected
        }

        count += 1;
        if count > MAX_DRIVERS {
            break;
        }

        // flink points to the DriverSection field inside _DRIVER_OBJECT.
        // The _DRIVER_OBJECT base is flink - driver_section_off.
        let driver_addr = flink.wrapping_sub(driver_section_off as u64);

        // Read DriverName (_UNICODE_STRING)
        let driver_name = read_unicode_string(reader, driver_addr.wrapping_add(driver_name_off as u64))
            .unwrap_or_default();

        // Read DeviceObject pointer
        let dev_ptr_bytes = match reader.read_bytes(driver_addr.wrapping_add(device_object_off as u64), 8) {
            Ok(b) => b,
            Err(_) => {
                current = flink;
                continue;
            }
        };
        let mut device_addr = u64::from_le_bytes(dev_ptr_bytes[..8].try_into().unwrap());

        // Walk the device chain
        let mut device_count = 0;
        let mut visited_devices = std::collections::HashSet::new();
        while device_addr != 0 {
            if !visited_devices.insert(device_addr) {
                break;
            }
            device_count += 1;
            if device_count > MAX_DEVICES_PER_DRIVER {
                break;
            }

            // Read DeviceType (u32)
            let device_type = reader
                .read_bytes(device_addr.wrapping_add(device_type_off as u64), 4)
                .ok()
                .and_then(|b| b[..4].try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(0);

            // Read AttachedDevice pointer
            let attached_device = reader
                .read_bytes(device_addr.wrapping_add(attached_device_off as u64), 8)
                .ok()
                .and_then(|b| b[..8].try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);

            let is_suspicious = classify_device(&driver_name, device_type);

            results.push(DeviceTreeEntry {
                driver_name: driver_name.clone(),
                driver_addr,
                device_name: String::new(),
                device_addr,
                device_type,
                attached_device,
                is_suspicious,
            });

            // Read NextDevice pointer
            device_addr = reader
                .read_bytes(device_addr.wrapping_add(next_device_off as u64), 8)
                .ok()
                .and_then(|b| b[..8].try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
        }

        current = flink;
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    // ---------------------------------------------------------------
    // device_type_name tests
    // ---------------------------------------------------------------

    #[test]
    fn device_type_disk() {
        assert_eq!(device_type_name(0x07), "Disk");
    }

    #[test]
    fn device_type_disk_file_system() {
        assert_eq!(device_type_name(0x08), "DiskFileSystem");
    }

    #[test]
    fn device_type_network_file_system() {
        assert_eq!(device_type_name(0x14), "NetworkFileSystem");
    }

    #[test]
    fn device_type_serial_port() {
        assert_eq!(device_type_name(0x1B), "SerialPort");
    }

    #[test]
    fn device_type_unknown() {
        assert_eq!(device_type_name(0x22), "Unknown");
    }

    #[test]
    fn device_type_unmapped_returns_other() {
        assert_eq!(device_type_name(0xFF), "Other");
        assert_eq!(device_type_name(0x100), "Other");
    }

    // ---------------------------------------------------------------
    // classify_device tests
    // ---------------------------------------------------------------

    #[test]
    fn classify_empty_driver_suspicious() {
        assert!(classify_device("", 0x07));
    }

    #[test]
    fn classify_normal_benign() {
        assert!(!classify_device("\\Driver\\Disk", 0x07));
    }

    #[test]
    fn classify_unusual_type_suspicious() {
        // Device type > 0x40 is outside the known range
        assert!(classify_device("\\Driver\\SomeDriver", 0x80));
    }

    #[test]
    fn classify_zero_type_suspicious() {
        // Device type 0 is invalid/uninitialized
        assert!(classify_device("\\Driver\\SomeDriver", 0));
    }

    #[test]
    fn classify_boundary_type_benign() {
        // 0x40 is the upper boundary of standard types (Wpd)
        assert!(!classify_device("\\Driver\\Wpd", 0x40));
    }

    // ---------------------------------------------------------------
    // walk_device_tree tests
    // ---------------------------------------------------------------

    /// Encode a Rust &str as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Build a _UNICODE_STRING struct in memory (16 bytes):
    /// [0..2]: Length (u16 LE)
    /// [2..4]: MaximumLength (u16 LE)
    /// [8..16]: Buffer (u64 LE pointer)
    fn build_unicode_string_at(buf: &mut [u8], offset: usize, length: u16, buffer_ptr: u64) {
        buf[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&length.to_le_bytes());
        buf[offset + 8..offset + 16].copy_from_slice(&buffer_ptr.to_le_bytes());
    }

    /// Place UTF-16LE string data at a physical offset and return the byte length.
    fn place_utf16_string(buf: &mut [u8], phys_offset: usize, s: &str) -> u16 {
        let utf16 = utf16le_bytes(s);
        let len = utf16.len();
        buf[phys_offset..phys_offset + len].copy_from_slice(&utf16);
        len as u16
    }

    /// Build an ISF preset with the device tree structures.
    fn device_tree_isf() -> IsfBuilder {
        IsfBuilder::windows_kernel_preset()
    }

    /// Build a reader from ISF and page table builder.
    fn make_reader(isf: &serde_json::Value, ptb: PageTableBuilder) -> ObjectReader<SyntheticPhysMem> {
        let resolver = IsfResolver::from_value(isf).unwrap();
        let (cr3, mem) = ptb.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn walk_no_drivers_returns_empty() {
        // Empty driver list: head points back to itself.
        let isf = device_tree_isf().build_json();

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let head_paddr: u64 = 0x0080_0000;

        let mut head_data = vec![0u8; 4096];
        // Flink -> head (circular, empty list)
        head_data[0..8].copy_from_slice(&head_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&head_vaddr.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data);

        let reader = make_reader(&isf, ptb);
        let result = walk_device_tree(&reader, head_vaddr).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn walk_single_driver_with_one_device() {
        // One driver object with one device object.
        //
        // Memory layout (4 pages):
        //   Page 0 (head_paddr):    DriverSection list head
        //   Page 1 (driver_paddr):  _DRIVER_OBJECT
        //   Page 2 (device_paddr):  _DEVICE_OBJECT
        //   Page 3 (strings_paddr): UTF-16LE string data

        let isf = device_tree_isf().build_json();

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let driver_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let device_vaddr: u64 = 0xFFFF_8000_0030_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0040_0000;

        let head_paddr: u64 = 0x0080_0000;
        let driver_paddr: u64 = 0x0090_0000;
        let device_paddr: u64 = 0x00A0_0000;
        let strings_paddr: u64 = 0x00B0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut driver_data = vec![0u8; 4096];
        let mut device_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        // _DRIVER_OBJECT layout:
        //   DriverSection (_LIST_ENTRY) at offset 0x28
        //   DriverName (_UNICODE_STRING) at offset 0x38
        //   DeviceObject (pointer) at offset 0x08

        let driver_section_off: u64 = 0x28;
        let driver_section_vaddr = driver_vaddr + driver_section_off;

        // Head list: Flink -> driver.DriverSection, Blink -> driver.DriverSection
        head_data[0..8].copy_from_slice(&driver_section_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&driver_section_vaddr.to_le_bytes());

        // Driver DriverSection: Flink -> head, Blink -> head (single entry)
        driver_data[0x28..0x30].copy_from_slice(&head_vaddr.to_le_bytes());
        driver_data[0x30..0x38].copy_from_slice(&head_vaddr.to_le_bytes());

        // DriverName at offset 0x38 (_UNICODE_STRING)
        let driver_name_str = "\\Driver\\Disk";
        let name_len = place_utf16_string(&mut string_data, 0, driver_name_str);
        build_unicode_string_at(&mut driver_data, 0x38, name_len, strings_vaddr);

        // DeviceObject at offset 0x08 -> points to device
        driver_data[0x08..0x10].copy_from_slice(&device_vaddr.to_le_bytes());

        // _DEVICE_OBJECT layout:
        //   DriverObject at offset 0x08
        //   NextDevice at offset 0x10
        //   AttachedDevice at offset 0x18
        //   DeviceType at offset 0x34

        // DriverObject -> driver
        device_data[0x08..0x10].copy_from_slice(&driver_vaddr.to_le_bytes());
        // NextDevice -> 0 (no more devices)
        device_data[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        // AttachedDevice -> 0 (no attached device)
        device_data[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());
        // DeviceType -> 0x07 (Disk)
        device_data[0x34..0x38].copy_from_slice(&0x07u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(driver_vaddr, driver_paddr, flags::WRITABLE)
            .map_4k(device_vaddr, device_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(driver_paddr, &driver_data)
            .write_phys(device_paddr, &device_data)
            .write_phys(strings_paddr, &string_data);

        let reader = make_reader(&isf, ptb);
        let entries = walk_device_tree(&reader, head_vaddr).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].driver_name, "\\Driver\\Disk");
        assert_eq!(entries[0].driver_addr, driver_vaddr);
        assert_eq!(entries[0].device_addr, device_vaddr);
        assert_eq!(entries[0].device_type, 0x07);
        assert_eq!(entries[0].attached_device, 0);
        assert!(!entries[0].is_suspicious);
    }

    #[test]
    fn walk_driver_with_no_devices() {
        // A driver object with DeviceObject == NULL (no devices).
        let isf = device_tree_isf().build_json();

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let driver_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let strings_vaddr: u64 = 0xFFFF_8000_0040_0000;

        let head_paddr: u64 = 0x0080_0000;
        let driver_paddr: u64 = 0x0090_0000;
        let strings_paddr: u64 = 0x00B0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut driver_data = vec![0u8; 4096];
        let mut string_data = vec![0u8; 4096];

        let driver_section_off: u64 = 0x28;
        let driver_section_vaddr = driver_vaddr + driver_section_off;

        head_data[0..8].copy_from_slice(&driver_section_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&driver_section_vaddr.to_le_bytes());

        driver_data[0x28..0x30].copy_from_slice(&head_vaddr.to_le_bytes());
        driver_data[0x30..0x38].copy_from_slice(&head_vaddr.to_le_bytes());

        // DriverName
        let name_len = place_utf16_string(&mut string_data, 0, "\\Driver\\Beep");
        build_unicode_string_at(&mut driver_data, 0x38, name_len, strings_vaddr);

        // DeviceObject -> NULL
        driver_data[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(driver_vaddr, driver_paddr, flags::WRITABLE)
            .map_4k(strings_vaddr, strings_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(driver_paddr, &driver_data)
            .write_phys(strings_paddr, &string_data);

        let reader = make_reader(&isf, ptb);
        let entries = walk_device_tree(&reader, head_vaddr).unwrap();

        // Driver with no devices should produce zero entries.
        assert!(entries.is_empty());
    }

    #[test]
    fn walk_driver_with_suspicious_device() {
        // A driver with an empty name and device_type=0 => suspicious.
        let isf = device_tree_isf().build_json();

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let driver_vaddr: u64 = 0xFFFF_8000_0020_0000;
        let device_vaddr: u64 = 0xFFFF_8000_0030_0000;

        let head_paddr: u64 = 0x0080_0000;
        let driver_paddr: u64 = 0x0090_0000;
        let device_paddr: u64 = 0x00A0_0000;

        let mut head_data = vec![0u8; 4096];
        let mut driver_data = vec![0u8; 4096];
        let mut device_data = vec![0u8; 4096];

        let driver_section_off: u64 = 0x28;
        let driver_section_vaddr = driver_vaddr + driver_section_off;

        head_data[0..8].copy_from_slice(&driver_section_vaddr.to_le_bytes());
        head_data[8..16].copy_from_slice(&driver_section_vaddr.to_le_bytes());

        driver_data[0x28..0x30].copy_from_slice(&head_vaddr.to_le_bytes());
        driver_data[0x30..0x38].copy_from_slice(&head_vaddr.to_le_bytes());

        // DriverName: empty (Length=0, Buffer=0)
        // Already zero-initialized in driver_data at offset 0x38

        // DeviceObject -> device
        driver_data[0x08..0x10].copy_from_slice(&device_vaddr.to_le_bytes());

        // Device: type=0, NextDevice=0, AttachedDevice=0
        device_data[0x08..0x10].copy_from_slice(&driver_vaddr.to_le_bytes());
        device_data[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        device_data[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());
        device_data[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(driver_vaddr, driver_paddr, flags::WRITABLE)
            .map_4k(device_vaddr, device_paddr, flags::WRITABLE)
            .write_phys(head_paddr, &head_data)
            .write_phys(driver_paddr, &driver_data)
            .write_phys(device_paddr, &device_data);

        let reader = make_reader(&isf, ptb);
        let entries = walk_device_tree(&reader, head_vaddr).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].driver_name.is_empty());
        assert_eq!(entries[0].device_type, 0);
        assert!(entries[0].is_suspicious);
    }
}
