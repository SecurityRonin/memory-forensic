//! Linux TTY operations hook detector.
//!
//! Walks the `tty_drivers` list and checks each driver's
//! `tty_operations` function pointers against the kernel text
//! region (`_stext`..`_etext`). Handlers pointing outside this
//! range indicate potential rootkit hooks on TTY devices.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, Result, TtyCheckInfo};

/// Check TTY driver operations for hooks.
///
/// Walks the `tty_drivers` linked list, reads each driver's
/// `tty_operations` struct, and checks function pointers against
/// the kernel text region.
pub fn check_tty_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<TtyCheckInfo>> {
    let tty_drivers_addr = reader
        .symbols()
        .symbol_address("tty_drivers")
        .ok_or_else(|| Error::Walker("symbol 'tty_drivers' not found".into()))?;

    let stext = reader
        .symbols()
        .symbol_address("_stext")
        .ok_or_else(|| Error::Walker("symbol '_stext' not found".into()))?;

    let etext = reader
        .symbols()
        .symbol_address("_etext")
        .ok_or_else(|| Error::Walker("symbol '_etext' not found".into()))?;

    let _tty_drivers_offset = reader
        .symbols()
        .field_offset("tty_driver", "tty_drivers")
        .ok_or_else(|| Error::Walker("tty_driver.tty_drivers field not found".into()))?;

    // Walk the tty_drivers linked list
    let driver_addrs = reader.walk_list(tty_drivers_addr, "tty_driver", "tty_drivers")?;

    let mut results = Vec::new();

    for &driver_addr in &driver_addrs {
        let name = reader
            .read_field_string(driver_addr, "tty_driver", "name", 64)
            .unwrap_or_else(|_| "<unknown>".to_string());

        let ops_ptr: u64 = match reader.read_field(driver_addr, "tty_driver", "ops") {
            Ok(v) if v != 0 => v,
            _ => continue,
        };

        // Check each operation function pointer
        let ops_fields = ["open", "close", "write", "ioctl"];
        for &op_name in &ops_fields {
            let handler: u64 = match reader.read_field(ops_ptr, "tty_operations", op_name) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if handler == 0 {
                continue;
            }

            let hooked = handler < stext || handler > etext;

            results.push(TtyCheckInfo {
                name: name.clone(),
                operation: op_name.to_string(),
                handler,
                hooked,
            });
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags as ptflags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_test_reader(
        data: &[u8],
        vaddr: u64,
        paddr: u64,
        stext: u64,
        etext: u64,
    ) -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 128)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_field("tty_driver", "ops", 16, "pointer")
            .add_field("tty_driver", "tty_drivers", 24, "list_head")
            .add_struct("tty_operations", 128)
            .add_field("tty_operations", "open", 0, "pointer")
            .add_field("tty_operations", "close", 8, "pointer")
            .add_field("tty_operations", "write", 16, "pointer")
            .add_field("tty_operations", "ioctl", 48, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("tty_drivers", vaddr + 0x800)
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(vaddr, paddr, ptflags::WRITABLE)
            .write_phys(paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn clean_tty_ops_not_hooked() {
        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;
        let mut data = vec![0u8; 4096];

        let handler: u64 = 0xFFFF_8000_0001_0000; // in text region

        // tty_drivers list_head at +0x800 (points to self = empty list → just test setup)
        let drivers_head = vaddr + 0x800;
        data[0x800..0x808].copy_from_slice(&drivers_head.to_le_bytes()); // next = self
        data[0x808..0x810].copy_from_slice(&drivers_head.to_le_bytes()); // prev = self

        let reader = make_test_reader(&data, vaddr, paddr, stext, etext);
        let results = check_tty_hooks(&reader).unwrap();

        // Empty list → no results (but no error either)
        assert!(results.is_empty());
    }

    #[test]
    fn missing_tty_drivers_symbol() {
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 64)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_tty_hooks(&reader);
        assert!(result.is_err());
    }

    #[test]
    fn missing_stext_symbol_returns_error() {
        // tty_drivers present but _stext absent → Error
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 64)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_field("tty_driver", "tty_drivers", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("tty_drivers", 0xFFFF_8000_0010_0000)
            // _stext intentionally omitted
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_tty_hooks(&reader);
        assert!(result.is_err(), "missing _stext should return an error");
    }

    #[test]
    fn missing_etext_symbol_returns_error() {
        // tty_drivers + _stext present but _etext absent → Error
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 64)
            .add_field("tty_driver", "name", 0, "pointer")
            .add_field("tty_driver", "tty_drivers", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("tty_drivers", 0xFFFF_8000_0010_0000)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            // _etext intentionally omitted
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_tty_hooks(&reader);
        assert!(result.is_err(), "missing _etext should return an error");
    }

    #[test]
    fn missing_tty_drivers_field_offset_returns_error() {
        // tty_drivers symbol present but tty_driver.tty_drivers field absent → Error
        let isf = IsfBuilder::new()
            .add_struct("tty_driver", 64)
            .add_field("tty_driver", "name", 0, "pointer")
            // tty_drivers field intentionally omitted from tty_driver struct
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer")
            .add_symbol("tty_drivers", 0xFFFF_8000_0010_0000)
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let result = check_tty_hooks(&reader);
        assert!(result.is_err(), "missing tty_driver.tty_drivers field should error");
    }

    // --- check_tty_hooks: list with a real driver entry, ops non-zero, handler in text range ---
    // Exercises the driver-loop body (lines 46-77): ops_ptr != 0, read handler, hooked=false.
    #[test]
    fn check_tty_hooks_driver_with_clean_ops() {
        // Layout:
        //   page at vaddr (paddr):
        //     +0x000: tty_driver struct
        //       +0x000: name ptr (points to name string at +0xE00)
        //       +0x010: ops ptr  (points to tty_operations at +0xC00)
        //       +0x018: tty_drivers list_head
        //     +0x800: tty_drivers global list_head (next=driver_entry, prev=driver_entry)
        //     +0xC00: tty_operations struct
        //       +0x000: open handler
        //       +0x008: close handler
        //       +0x010: write handler
        //       +0x030: ioctl handler
        //     +0xE00: name string "ttyS\0"
        //
        //   stext = 0xFFFF_8000_0000_0000, etext = 0xFFFF_8000_00FF_FFFF
        //   All handlers inside [stext, etext] → hooked = false.

        let vaddr: u64 = 0xFFFF_8000_0020_0000;
        let paddr: u64 = 0x0020_0000;

        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        // A handler value inside the text region.
        let clean_handler: u64 = 0xFFFF_8000_0001_0000;

        // tty_drivers list head sits at vaddr + 0x800 (as per make_test_reader).
        let drivers_head: u64 = vaddr + 0x800;
        // Driver entry's tty_drivers list_head is at driver_base + 0x018.
        let driver_list_entry: u64 = vaddr + 0x018;
        // ops pointer stored at driver_base + 0x010.
        let ops_ptr: u64 = vaddr + 0xC00;
        // Name pointer stored at driver_base + 0x000 (name field at offset 0).
        let name_ptr: u64 = vaddr + 0xE00;

        let mut data = vec![0u8; 4096];

        // --- tty_driver at base 0x000 ---
        // name ptr (field offset=0): points to name string
        data[0x000..0x008].copy_from_slice(&name_ptr.to_le_bytes());
        // ops ptr (field offset=16=0x010)
        data[0x010..0x018].copy_from_slice(&ops_ptr.to_le_bytes());
        // tty_drivers list_head (field offset=24=0x018):
        //   next = drivers_head  (so walk_list returns this one driver)
        //   prev = drivers_head
        data[0x018..0x020].copy_from_slice(&drivers_head.to_le_bytes()); // next
        data[0x020..0x028].copy_from_slice(&drivers_head.to_le_bytes()); // prev

        // --- tty_drivers global list_head at 0x800 ---
        // next = driver_list_entry (the driver's embedded list_head)
        // prev = driver_list_entry
        data[0x800..0x808].copy_from_slice(&driver_list_entry.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&driver_list_entry.to_le_bytes());

        // --- tty_operations at 0xC00 ---
        data[0xC00..0xC08].copy_from_slice(&clean_handler.to_le_bytes()); // open
        data[0xC08..0xC10].copy_from_slice(&clean_handler.to_le_bytes()); // close
        data[0xC10..0xC18].copy_from_slice(&clean_handler.to_le_bytes()); // write
        data[0xC30..0xC38].copy_from_slice(&clean_handler.to_le_bytes()); // ioctl

        // --- name string at 0xE00 ---
        data[0xE00..0xE05].copy_from_slice(b"ttyS\0");

        let reader = make_test_reader(&data, vaddr, paddr, stext, etext);
        let results = check_tty_hooks(&reader).expect("should not error");

        // 4 ops checked, all within text region → hooked=false for all.
        assert!(!results.is_empty(), "expected at least one ops entry from the driver");
        for r in &results {
            assert!(!r.hooked, "clean handler inside text region must not be flagged");
        }
    }

    // --- check_tty_hooks: driver with ops outside text region → hooked = true ---
    #[test]
    fn check_tty_hooks_driver_with_hooked_ops() {
        let vaddr: u64 = 0xFFFF_8000_0021_0000;
        let paddr: u64 = 0x0021_0000;

        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        // A handler value OUTSIDE the text region (suspicious).
        let hooked_handler: u64 = 0xFFFF_CAFE_DEAD_0001;

        let drivers_head: u64   = vaddr + 0x800;
        let driver_list_entry: u64 = vaddr + 0x018;
        let ops_ptr: u64        = vaddr + 0xC00;
        let name_ptr: u64       = vaddr + 0xE00;

        let mut data = vec![0u8; 4096];

        data[0x000..0x008].copy_from_slice(&name_ptr.to_le_bytes());
        data[0x010..0x018].copy_from_slice(&ops_ptr.to_le_bytes());
        data[0x018..0x020].copy_from_slice(&drivers_head.to_le_bytes());
        data[0x020..0x028].copy_from_slice(&drivers_head.to_le_bytes());

        data[0x800..0x808].copy_from_slice(&driver_list_entry.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&driver_list_entry.to_le_bytes());

        // All ops point outside text region.
        data[0xC00..0xC08].copy_from_slice(&hooked_handler.to_le_bytes());
        data[0xC08..0xC10].copy_from_slice(&hooked_handler.to_le_bytes());
        data[0xC10..0xC18].copy_from_slice(&hooked_handler.to_le_bytes());
        data[0xC30..0xC38].copy_from_slice(&hooked_handler.to_le_bytes());

        data[0xE00..0xE09].copy_from_slice(b"rootkit0\0");

        let reader = make_test_reader(&data, vaddr, paddr, stext, etext);
        let results = check_tty_hooks(&reader).expect("should not error");

        assert!(!results.is_empty(), "hooked ops must produce entries");
        for r in &results {
            assert!(r.hooked, "handler outside text region must be flagged as hooked");
        }
    }

    // --- check_tty_hooks: driver with ops == 0 → skipped (continue branch) ---
    #[test]
    fn check_tty_hooks_driver_ops_null_skipped() {
        let vaddr: u64 = 0xFFFF_8000_0022_0000;
        let paddr: u64 = 0x0022_0000;

        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let drivers_head: u64      = vaddr + 0x800;
        let driver_list_entry: u64 = vaddr + 0x018;
        let name_ptr: u64          = vaddr + 0xE00;

        let mut data = vec![0u8; 4096];

        data[0x000..0x008].copy_from_slice(&name_ptr.to_le_bytes());
        // ops at 0x010 = 0 (null) → ops branch: `Ok(v) if v != 0` fails → continue
        data[0x010..0x018].copy_from_slice(&0u64.to_le_bytes());
        data[0x018..0x020].copy_from_slice(&drivers_head.to_le_bytes());
        data[0x020..0x028].copy_from_slice(&drivers_head.to_le_bytes());

        data[0x800..0x808].copy_from_slice(&driver_list_entry.to_le_bytes());
        data[0x808..0x810].copy_from_slice(&driver_list_entry.to_le_bytes());

        data[0xE00..0xE09].copy_from_slice(b"nullops\0\0");

        let reader = make_test_reader(&data, vaddr, paddr, stext, etext);
        let results = check_tty_hooks(&reader).expect("should not error");

        assert!(results.is_empty(), "null ops_ptr → driver skipped → no results");
    }
}
