//! Linux kernel inline hook detector.
//!
//! Checks the first bytes of key kernel functions for JMP/CALL
//! trampolines that indicate inline hooking. Reads the function
//! prologue and checks for x86_64 patterns like:
//!   - `0xE9` (relative JMP)
//!   - `0xFF 0x25` (absolute indirect JMP)
//!   - `0x48 0xB8 ... 0xFF 0xE0` (MOV RAX, imm64; JMP RAX)

use memf_core::object_reader::ObjectReader;
use memf_format::PhysicalMemoryProvider;

use crate::{Error, KernelHookInfo, Result};

/// Number of prologue bytes to read from each function.
const PROLOGUE_SIZE: usize = 16;

/// Well-known kernel functions to check for inline hooks.
const FUNCTIONS_TO_CHECK: &[&str] = &[
    "sys_read",
    "sys_write",
    "sys_open",
    "sys_close",
    "vfs_read",
    "vfs_write",
    "tcp4_seq_show",
    "filldir",
    "filldir64",
];

/// Check key kernel functions for inline hooks.
///
/// Reads the first [`PROLOGUE_SIZE`] bytes of each function in
/// [`FUNCTIONS_TO_CHECK`] and looks for JMP/CALL trampoline patterns.
pub fn check_inline_hooks<P: PhysicalMemoryProvider>(
    reader: &ObjectReader<P>,
) -> Result<Vec<KernelHookInfo>> {
    let stext = reader
        .symbols()
        .symbol_address("_stext")
        .ok_or_else(|| Error::Walker("symbol '_stext' not found".into()))?;
    let etext = reader
        .symbols()
        .symbol_address("_etext")
        .ok_or_else(|| Error::Walker("symbol '_etext' not found".into()))?;

    let mut results = Vec::new();

    for &func_name in FUNCTIONS_TO_CHECK {
        let Some(func_addr) = reader.symbols().symbol_address(func_name) else {
            continue; // Symbol not present, skip
        };

        let Ok(prologue) = reader.read_bytes(func_addr, PROLOGUE_SIZE) else {
            continue;
        };

        let (hook_type, target) = analyze_prologue(&prologue, func_addr);
        // Suspicious only when a hook IS present AND the target is outside kernel text.
        // A jmp into a legitimate kernel function is not suspicious.
        let suspicious = hook_type != "none" && target.map_or(true, |t| t < stext || t > etext);

        results.push(KernelHookInfo {
            symbol: func_name.to_string(),
            address: func_addr,
            hook_type,
            target,
            suspicious,
        });
    }

    Ok(results)
}

/// Analyze a function prologue for hook patterns.
///
/// Returns `(hook_type, target)` if a hook is detected, or `("none", None)`.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn analyze_prologue(bytes: &[u8], func_addr: u64) -> (String, Option<u64>) {
    if bytes.len() < PROLOGUE_SIZE {
        return ("none".to_string(), None);
    }

    // Pattern 1: E9 xx xx xx xx — relative JMP (5 bytes)
    if bytes[0] == 0xE9 {
        let offset = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
        let target = (func_addr as i64 + 5 + i64::from(offset)) as u64;
        return ("jmp_rel32".to_string(), Some(target));
    }

    // Pattern 2: FF 25 xx xx xx xx — absolute indirect JMP [rip+disp32]
    if bytes[0] == 0xFF && bytes[1] == 0x25 {
        let offset = i32::from_le_bytes(bytes[2..6].try_into().unwrap());
        let target = (func_addr as i64 + 6 + i64::from(offset)) as u64;
        return ("jmp_indirect".to_string(), Some(target));
    }

    // Pattern 3: 48 B8 <imm64> FF E0 — MOV RAX, imm64; JMP RAX (12 bytes)
    if bytes.len() >= 12
        && bytes[0] == 0x48
        && bytes[1] == 0xB8
        && bytes[10] == 0xFF
        && bytes[11] == 0xE0
    {
        let target = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        return ("mov_rax_jmp".to_string(), Some(target));
    }

    ("none".to_string(), None)
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
        func_vaddr: u64,
        func_paddr: u64,
        stext: u64,
        etext: u64,
        func_symbols: &[(&str, u64)],
    ) -> ObjectReader<SyntheticPhysMem> {
        let mut builder = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", stext)
            .add_symbol("_etext", etext);

        for &(name, addr) in func_symbols {
            builder = builder.add_symbol(name, addr);
        }

        let isf = builder.build_json();
        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new()
            .map_4k(func_vaddr, func_paddr, ptflags::WRITABLE)
            .write_phys(func_paddr, data)
            .build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn clean_function_no_hook() {
        // Normal function prologue: push rbp; mov rbp, rsp; sub rsp, 0x20
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0x55; // push rbp
        prologue[1] = 0x48; // REX.W
        prologue[2] = 0x89; // mov
        prologue[3] = 0xE5; // rbp, rsp

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].suspicious);
        assert_eq!(results[0].symbol, "sys_read");
        assert_eq!(results[0].hook_type, "none");
    }

    #[test]
    fn detects_relative_jmp_hook() {
        // Hooked: E9 xx xx xx xx (relative JMP)
        // Target lands inside kernel text → hook detected but NOT suspicious
        // (jmp to a legitimate kernel function should not be flagged).
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0xE9; // JMP rel32
        prologue[1..5].copy_from_slice(&0x1000i32.to_le_bytes());

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        // target = func_vaddr + 5 + 0x1000 = 0xFFFF_8000_0002_1005, inside [stext, etext)
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hook_type, "jmp_rel32");
        assert!(results[0].target.is_some());
        // Hook detected but target inside kernel text → not suspicious
        assert!(!results[0].suspicious, "jmp into kernel text should not be suspicious");
    }

    #[test]
    fn detects_movabs_jmp_rax_hook() {
        // Hooked: 48 B8 <8 bytes> FF E0 (MOV RAX, imm64; JMP RAX)
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0x48; // REX.W
        prologue[1] = 0xB8; // MOV RAX, imm64
        let target: u64 = 0xFFFF_C900_DEAD_BEEF;
        prologue[2..10].copy_from_slice(&target.to_le_bytes());
        prologue[10] = 0xFF; // JMP
        prologue[11] = 0xE0; // RAX

        let func_vaddr: u64 = 0xFFFF_8000_0001_0000;
        let func_paddr: u64 = 0x0080_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert!(results[0].suspicious);
        assert_eq!(results[0].hook_type, "mov_rax_jmp");
        assert_eq!(results[0].target, Some(target));
    }

    #[test]
    fn analyze_prologue_normal() {
        let bytes = [
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let (hook_type, target) = analyze_prologue(&bytes, 0xFFFF_8000_0001_0000);
        assert_eq!(hook_type, "none");
        assert_eq!(target, None);
    }

    #[test]
    fn detects_indirect_jmp_hook() {
        // Covers lines 91-93: FF 25 xx xx xx xx (absolute indirect JMP [rip+disp32])
        // Target = func_addr + 6 (inside kernel text) → hook detected, not suspicious.
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0xFF;
        prologue[1] = 0x25;
        // offset = 0 → target = func_addr + 6 + 0 = func_addr + 6
        prologue[2..6].copy_from_slice(&0i32.to_le_bytes());

        let func_vaddr: u64 = 0xFFFF_8000_0002_0000;
        let func_paddr: u64 = 0x0081_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_00FF_FFFF;

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("sys_write", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hook_type, "jmp_indirect");
        // target = func_addr + 6 + 0 (offset) = 0xFFFF_8000_0002_0006 (inside kernel text)
        assert_eq!(results[0].target, Some(func_vaddr + 6));
        // Hook detected but target is inside kernel text → not suspicious
        assert!(!results[0].suspicious, "jmp_indirect targeting kernel text must not be suspicious");
    }

    #[test]
    fn skips_symbol_with_unreadable_prologue() {
        // Covers line 55: symbol present but read_bytes fails → skip
        // We add a function symbol that points to an unmapped address.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            // sys_read points to unmapped memory → read_bytes fails
            .add_symbol("sys_read", 0xFFFF_DEAD_0000_0000)
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_inline_hooks(&reader).unwrap();
        // Symbol is present but page is not mapped → read_bytes fails → entry skipped
        assert!(results.is_empty(), "unreadable prologue should be skipped");
    }

    #[test]
    fn detects_rel_jmp_hook_outside_text_region() {
        // Cover: hook_type == "none" but target outside text range = suspicious
        // Use a JMP that lands outside [stext, etext]
        let mut prologue = vec![0u8; 4096];
        prologue[0] = 0xE9;
        // A large positive offset that lands outside etext
        prologue[1..5].copy_from_slice(&0x0FFF_0000i32.to_le_bytes());

        let func_vaddr: u64 = 0xFFFF_8000_0003_0000;
        let func_paddr: u64 = 0x0082_0000;
        let stext: u64 = 0xFFFF_8000_0000_0000;
        let etext: u64 = 0xFFFF_8000_0005_0000; // small range

        let reader = make_test_reader(
            &prologue,
            func_vaddr,
            func_paddr,
            stext,
            etext,
            &[("vfs_read", func_vaddr)],
        );
        let results = check_inline_hooks(&reader).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hook_type, "jmp_rel32");
        assert!(results[0].suspicious, "JMP to outside text region must be suspicious");
    }

    #[test]
    fn analyze_prologue_short_bytes_returns_none() {
        // Covers line 79: bytes.len() < PROLOGUE_SIZE → ("none", None)
        let short = [0x55u8; 4]; // only 4 bytes, need 16
        let (hook_type, target) = analyze_prologue(&short, 0xFFFF_8000_0001_0000);
        assert_eq!(hook_type, "none");
        assert_eq!(target, None);
    }

    #[test]
    fn skips_missing_symbols() {
        // If sys_read symbol is missing, just skip it (no error)
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 64)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("_stext", 0xFFFF_8000_0000_0000)
            .add_symbol("_etext", 0xFFFF_8000_00FF_FFFF)
            // No function symbols
            .build_json();

        let resolver = IsfResolver::from_value(&isf).unwrap();
        let (cr3, mem) = PageTableBuilder::new().build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        let reader = ObjectReader::new(vas, Box::new(resolver));

        let results = check_inline_hooks(&reader).unwrap();
        assert!(results.is_empty());
    }
}
