//! Keyboard notifier chain forensics — keylogger detection.
//!
//! Walks the `keyboard_notifier_list` (`raw_notifier_head`) linked list of
//! `notifier_block` structures.  Each entry records a `notifier_call`
//! function pointer.  A pointer outside the kernel text range indicates a
//! potential keylogger injected by a rootkit.

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::Result;

/// Information about a single `notifier_block` on the keyboard notifier chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyboardNotifierInfo {
    /// Virtual address of the `notifier_block`.
    pub address: u64,
    /// `notifier_block.notifier_call` — function pointer.
    pub notifier_call: u64,
    /// `notifier_block.priority`.
    pub priority: i32,
    /// True when `notifier_call` lies outside `_stext`..`_etext`.
    pub is_suspicious: bool,
}

/// Walk `keyboard_notifier_list` and return all registered notifier blocks.
///
/// Returns `Ok(Vec::new())` when the `keyboard_notifier_list` symbol is absent.
///
/// `raw_notifier_head` layout:
///   +0: head (pointer to first `notifier_block`, or NULL)
///
/// `notifier_block` layout:
///   +0:  notifier_call (pointer)
///   +8:  next (pointer to next notifier_block, or NULL)
///   +16: priority (i32)
pub fn walk_keyboard_notifiers<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KeyboardNotifierInfo>> {
    let Some(head_addr) = reader.symbols().symbol_address("keyboard_notifier_list") else {
        return Ok(Vec::new());
    };

    let stext = reader.symbols().symbol_address("_stext").unwrap_or(0);
    let etext = reader
        .symbols()
        .symbol_address("_etext")
        .unwrap_or(u64::MAX);

    // Read raw_notifier_head.head pointer (offset 0).
    let first_nb = match reader.read_bytes(head_addr, 8) {
        Ok(b) if b.len() == 8 => u64::from_le_bytes(b.try_into().unwrap()),
        _ => return Ok(Vec::new()),
    };

    const MAX_NOTIFIERS: usize = 1_000;
    let mut notifiers = Vec::new();
    let mut current = first_nb;

    for _ in 0..MAX_NOTIFIERS {
        if current == 0 {
            break;
        }

        // notifier_call at offset 0
        let notifier_call = match reader.read_bytes(current, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b.try_into().unwrap()),
            _ => break,
        };

        // next at offset 8
        let next = match reader.read_bytes(current + 8, 8) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b.try_into().unwrap()),
            _ => 0,
        };

        // priority at offset 16 (i32)
        let priority = match reader.read_bytes(current + 16, 4) {
            Ok(b) if b.len() == 4 => i32::from_le_bytes(b.try_into().unwrap()),
            _ => 0,
        };

        let is_suspicious = classify_notifier(notifier_call, stext, etext);

        notifiers.push(KeyboardNotifierInfo {
            address: current,
            notifier_call,
            priority,
            is_suspicious,
        });

        current = next;
    }

    Ok(notifiers)
}

/// Classify a notifier_call pointer as suspicious if outside kernel text.
pub fn classify_notifier(notifier_call: u64, stext: u64, etext: u64) -> bool {
    notifier_call < stext || notifier_call >= etext
}

#[cfg(test)]
mod tests {
    use super::*;
    use memf_core::test_builders::{flags, PageTableBuilder, SyntheticPhysMem};
    use memf_core::vas::{TranslationMode, VirtualAddressSpace};
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_no_symbol_reader() -> ObjectReader<SyntheticPhysMem> {
        let isf = IsfBuilder::new().build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn no_symbol_returns_empty() {
        let reader = make_no_symbol_reader();
        let result = walk_keyboard_notifiers(&reader).unwrap();
        assert!(
            result.is_empty(),
            "no keyboard_notifier_list symbol → empty vec"
        );
    }

    #[test]
    fn classify_in_kernel_benign() {
        let stext = 0xFFFF_FFFF_8100_0000_u64;
        let etext = 0xFFFF_FFFF_8200_0000_u64;
        let call = 0xFFFF_FFFF_8150_0000_u64;
        assert!(
            !classify_notifier(call, stext, etext),
            "in-kernel notifier_call should be benign"
        );
    }

    #[test]
    fn classify_out_of_kernel_suspicious() {
        let stext = 0xFFFF_FFFF_8100_0000_u64;
        let etext = 0xFFFF_FFFF_8200_0000_u64;
        let call = 0x0000_7FFF_1234_5678_u64; // userspace range → suspicious
        assert!(
            classify_notifier(call, stext, etext),
            "out-of-kernel notifier_call should be suspicious"
        );
    }

    // RED test: walk with a symbol and one notifier_block in memory returns an entry.
    #[test]
    fn walk_keyboard_notifiers_with_symbol_returns_entry() {
        // notifier_block layout:
        //   offset 0:  notifier_call (pointer, 8 bytes)
        //   offset 8:  next (pointer, 8 bytes) — NULL = end of chain
        //   offset 16: priority (i32, 4 bytes)
        //
        // raw_notifier_head:
        //   offset 0: head (pointer to first notifier_block, or NULL)

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000; // raw_notifier_head.head
        let head_paddr: u64 = 0x0080_0000;
        let nb_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let nb_paddr: u64 = 0x0081_0000;

        let notifier_call: u64 = 0xFFFF_FFFF_8155_0000; // in-kernel
        let priority: i32 = 10;

        // raw_notifier_head page: head ptr at offset 0 → nb_vaddr
        let mut head_data = [0u8; 0x1000];
        head_data[0..8].copy_from_slice(&nb_vaddr.to_le_bytes());

        // notifier_block page:
        //   +0: notifier_call
        //   +8: next = 0 (end of chain)
        //   +16: priority
        let mut nb_data = [0u8; 0x1000];
        nb_data[0..8].copy_from_slice(&notifier_call.to_le_bytes());
        nb_data[8..16].copy_from_slice(&0u64.to_le_bytes()); // next = NULL
        nb_data[16..20].copy_from_slice(&priority.to_le_bytes());

        let stext: u64 = 0xFFFF_FFFF_8100_0000;
        let etext: u64 = 0xFFFF_FFFF_8200_0000;

        let isf = IsfBuilder::new()
            .add_symbol("keyboard_notifier_list", head_vaddr)
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mut mem) = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::PRESENT | flags::WRITABLE)
            .map_4k(nb_vaddr, nb_paddr, flags::PRESENT | flags::WRITABLE)
            .build();
        mem.write_bytes(head_paddr, &head_data);
        mem.write_bytes(nb_paddr, &nb_data);

        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let notifiers = walk_keyboard_notifiers(&reader).unwrap();
        assert_eq!(notifiers.len(), 1, "should find one notifier_block");
        assert_eq!(notifiers[0].notifier_call, notifier_call);
        assert_eq!(notifiers[0].priority, priority);
        assert!(
            !notifiers[0].is_suspicious,
            "in-kernel call should be benign"
        );
    }
}
