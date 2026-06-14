//! Empirical probe: does find_low_stub + symbol RVA reconstruct the kernel VAs
//! on a raw Windows .mem dump? Compares against vol3's known CR3.
//!
//! Usage: cargo run --release -p memf-symbols --example probe_lowstub -- <dump> <isf.json>

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use memf_symbols::{find_low_stub, isf::IsfResolver, SymbolResolver};

fn main() {
    let mut args = std::env::args().skip(1);
    let dump = args.next().expect("usage: probe_lowstub <dump> <isf.json>");
    let isf = args.next().expect("usage: probe_lowstub <dump> <isf.json>");

    let mem = memf_format::open_dump_with_raw_fallback(Path::new(&dump)).expect("open dump");
    let stub = find_low_stub(&mem);
    println!("find_low_stub => {stub:?}");
    let base = memf_symbols::resolve_kernel_base_va(&mem);
    println!("resolve_kernel_base_va => {base:#x?}  (vol3 truth: 0xfffff80162a14000)");

    let resolver = IsfResolver::from_path(Path::new(&isf)).expect("load isf");
    for sym in ["PsActiveProcessHead", "PsLoadedModuleList"] {
        let rva = resolver.symbol_address(sym);
        println!("  symbol {sym} rva = {rva:#x?}");
        if let (Some(s), Some(rva)) = (stub, rva) {
            println!("    => VA = {:#x}", s.kernel_base_va.wrapping_add(rva));
        }
    }
}
