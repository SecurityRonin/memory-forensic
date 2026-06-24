//! Dual-backend equivalence: parse one synthetic hive both through winreg-core's
//! flat-file `Hive<Cursor<Vec<u8>>>` backend and through memf's HMAP-backed
//! [`MemfHiveReader`], and assert the walked keys/values are identical.
//!
//! The flat backend reads bins bytes at `4096 + cell_offset`. The memf backend
//! resolves the *same* `CellOffset` (a cell index) through a real
//! `_HHIVE.Storage[].Map` directory/table/`_HMAP_ENTRY` chain to a virtual
//! address — so agreement proves the HMAP translation, independent of any
//! oracle: the ground truth is the *construction* of the hive itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use memf_core::object_reader::ObjectReader;
use memf_core::test_builders::{flags, PageTableBuilder};
use memf_core::vas::{TranslationMode, VirtualAddressSpace};
use memf_symbols::isf::IsfResolver;
use memf_symbols::test_builders::IsfBuilder;
use memf_windows::hive_reader::MemfHiveReader;
use winreg_core::cell_reader::CellReader;
use winreg_core::hive::Hive;
use winreg_core::key::Key;
use winreg_format::cells::CellOffset;
use winreg_format::header::BaseBlock;

const HBIN_SIZE: u32 = 4096;

// Bins-relative cell offsets (== memf cell indices) for each cell.
const ROOT_OFF: u32 = 0x20;
const LH_OFF: u32 = 0x80;
const CHILD_OFF: u32 = 0xB0;
const VLIST_OFF: u32 = 0x110;
const VK_OFF: u32 = 0x130;

const KEY_NODE_FLAGS_HIVE_ENTRY: u16 = 0x0004;
const KEY_NODE_FLAGS_COMP_NAME: u16 = 0x0020;
const VALUE_FLAG_COMP_NAME: u16 = 0x0001;
const VK_RESIDENT_FLAG: u32 = 0x8000_0000;

/// Write an allocated `_HCELL` size header (negative size) at a bins-relative
/// cell offset, returning the file-relative position just past the 4-byte header
/// (where the cell body — including the 2-byte signature — begins).
fn write_cell_header(buf: &mut [u8], cell_off: u32, body_len: usize) -> usize {
    let total = 4 + body_len;
    // Cells are 8-byte aligned; size includes the header.
    let aligned = total.div_ceil(8) * 8;
    let pos = BaseBlock::SIZE + cell_off as usize;
    let size = -(aligned as i32);
    buf[pos..pos + 4].copy_from_slice(&size.to_le_bytes());
    pos + 4
}

/// Build a minimal but realistic hive: base block + one hbin holding a root nk
/// with one subkey (via an `lh` index) and one resident value.
fn build_hive() -> Vec<u8> {
    let total = BaseBlock::SIZE + HBIN_SIZE as usize;
    let mut buf = vec![0u8; total];

    // ── Base block (regf) ──
    buf[0..4].copy_from_slice(b"regf");
    buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // primary seq
    buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes()); // secondary seq
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version
    buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // format
    buf[0x24..0x28].copy_from_slice(&ROOT_OFF.to_le_bytes()); // root cell offset
    buf[0x28..0x2C].copy_from_slice(&HBIN_SIZE.to_le_bytes()); // hive bins data size
    buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor

    // ── hbin header ──
    let hbin = BaseBlock::SIZE;
    buf[hbin..hbin + 4].copy_from_slice(b"hbin");
    buf[hbin + 4..hbin + 8].copy_from_slice(&0u32.to_le_bytes()); // offset within bins
    buf[hbin + 8..hbin + 12].copy_from_slice(&HBIN_SIZE.to_le_bytes());

    // ── root nk ──
    {
        let mut body = vec![0u8; 2 + 78]; // sig + 74-byte header + "ROOT"
        body[0..2].copy_from_slice(b"nk");
        let nk = &mut body[2..]; // after-sig view, matching RawKeyNode::parse
        nk[0..2]
            .copy_from_slice(&(KEY_NODE_FLAGS_HIVE_ENTRY | KEY_NODE_FLAGS_COMP_NAME).to_le_bytes());
        nk[2..10].copy_from_slice(&130_000_000_000_000_000u64.to_le_bytes()); // last_written
        nk[18..22].copy_from_slice(&1u32.to_le_bytes()); // subkey_count (stable)
        nk[26..30].copy_from_slice(&LH_OFF.to_le_bytes()); // subkeys_list_offset
        nk[34..38].copy_from_slice(&1u32.to_le_bytes()); // value_count
        nk[38..42].copy_from_slice(&VLIST_OFF.to_le_bytes()); // values_list_offset
        nk[70..72].copy_from_slice(&4u16.to_le_bytes()); // key_name_len
        nk[74..78].copy_from_slice(b"ROOT"); // name @ after-sig offset 74
        let p = write_cell_header(&mut buf, ROOT_OFF, body.len());
        buf[p..p + body.len()].copy_from_slice(&body);
    }

    // ── lh subkey index (1 element → child) ──
    {
        let mut body = vec![0u8; 2 + 2 + 8];
        body[0..2].copy_from_slice(b"lh");
        body[2..4].copy_from_slice(&1u16.to_le_bytes()); // count
        body[4..8].copy_from_slice(&CHILD_OFF.to_le_bytes()); // key_offset
        body[8..12].copy_from_slice(&0u32.to_le_bytes()); // name_hash
        let p = write_cell_header(&mut buf, LH_OFF, body.len());
        buf[p..p + body.len()].copy_from_slice(&body);
    }

    // ── child nk ("Child"), no subkeys, no values ──
    {
        let mut body = vec![0u8; 2 + 79]; // sig + 74 header + "Child"(5)
        body[0..2].copy_from_slice(b"nk");
        let nk = &mut body[2..];
        nk[0..2].copy_from_slice(&KEY_NODE_FLAGS_COMP_NAME.to_le_bytes());
        nk[2..10].copy_from_slice(&130_000_000_000_000_001u64.to_le_bytes());
        nk[18..22].copy_from_slice(&0u32.to_le_bytes()); // subkey_count
        nk[34..38].copy_from_slice(&0u32.to_le_bytes()); // value_count
        nk[70..72].copy_from_slice(&5u16.to_le_bytes()); // key_name_len
        nk[74..79].copy_from_slice(b"Child"); // name @ after-sig offset 74
        let p = write_cell_header(&mut buf, CHILD_OFF, body.len());
        buf[p..p + body.len()].copy_from_slice(&body);
    }

    // ── value list (1 entry → vk) ──
    {
        let mut body = vec![0u8; 4];
        body[0..4].copy_from_slice(&VK_OFF.to_le_bytes());
        let p = write_cell_header(&mut buf, VLIST_OFF, body.len());
        buf[p..p + body.len()].copy_from_slice(&body);
    }

    // ── vk ("Val"), resident 2-byte data "AB" ──
    {
        let mut body = vec![0u8; 2 + 18 + 3]; // sig + 18-byte header + "Val"
        body[0..2].copy_from_slice(b"vk");
        let vk = &mut body[2..]; // after-sig view, matching RawKeyValue::parse
        vk[0..2].copy_from_slice(&3u16.to_le_bytes()); // name_len
        vk[2..6].copy_from_slice(&(2u32 | VK_RESIDENT_FLAG).to_le_bytes()); // data_size + resident
        vk[6..10].copy_from_slice(&u32::from_le_bytes([b'A', b'B', 0, 0]).to_le_bytes()); // inline data
        vk[10..14].copy_from_slice(&1u32.to_le_bytes()); // type = REG_SZ
        vk[14..16].copy_from_slice(&VALUE_FLAG_COMP_NAME.to_le_bytes());
        vk[18..21].copy_from_slice(b"Val"); // name @ after-sig offset 18
        let p = write_cell_header(&mut buf, VK_OFF, body.len());
        buf[p..p + body.len()].copy_from_slice(&body);
    }

    // Fill the rest of the hbin with one free cell so the bin is well-formed.
    let used_end = BaseBlock::SIZE + VK_OFF as usize + 0x30;
    let free_size = total - used_end;
    if free_size >= 4 {
        buf[used_end..used_end + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
    }

    let checksum = BaseBlock::compute_checksum(&buf);
    buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());
    buf
}

/// Snapshot of a walked key: name plus its (value-name, raw-data) pairs.
#[derive(Debug, PartialEq, Eq)]
struct KeySnapshot {
    name: String,
    is_root: bool,
    last_written: u64,
    values: Vec<(String, Vec<u8>)>,
    subkeys: Vec<String>,
}

fn snapshot<R: CellReader>(key: &Key<'_, R>) -> KeySnapshot {
    let values = key
        .values()
        .unwrap()
        .iter()
        .map(|v| (v.name(), v.raw_data().unwrap()))
        .collect();
    let subkeys = key.subkeys().unwrap().iter().map(Key::name).collect();
    KeySnapshot {
        name: key.name(),
        is_root: key.is_root(),
        last_written: key.last_written_raw(),
        values,
        subkeys,
    }
}

/// Build an `ObjectReader` whose memory backs the hive's bins data via a real
/// HMAP directory/table/entry chain, so cell index `N` → `bins_base_va + N`.
///
/// Returns the reader and the `_HHIVE` VA to hand to [`MemfHiveReader::new`].
/// The reader must outlive its borrows, so the caller owns it; we return the
/// page-table-built reader by value.
fn build_memory_backed_reader(
    hive: &[u8],
) -> (
    ObjectReader<memf_core::test_builders::SyntheticPhysMem>,
    u64,
) {
    // Minimal ISF: the structs/fields cell_index_to_va reads.
    let isf = IsfBuilder::new()
        .add_struct("_HHIVE", 0x800)
        .add_field("_HHIVE", "Storage", 0xb8, "char")
        .add_struct("_DUAL", 0x278)
        .add_field("_DUAL", "Map", 0x18, "pointer")
        .add_struct("_HMAP_ENTRY", 0x20)
        .add_field("_HMAP_ENTRY", "PermanentBinAddress", 0x0, "pointer")
        .add_field("_HMAP_ENTRY", "BlockOffset", 0x8, "unsigned long")
        .build_json();
    let resolver = IsfResolver::from_value(&isf).unwrap();

    let hhive_vaddr = 0xFFFF_8000_0010_0000u64;
    let dir_vaddr = 0xFFFF_8000_0010_2000u64;
    let table_vaddr = 0xFFFF_8000_0010_3000u64;
    let bins_vaddr = 0xFFFF_8000_0010_5000u64; // block 0 base
    let (hhive_p, dir_p, table_p, bins_p) =
        (0x20_0000u64, 0x20_2000u64, 0x20_3000u64, 0x20_5000u64);

    // _HHIVE page: Storage[0].Map @ 0xb8 + 0x18 = 0xd0 → directory VA.
    let mut hhive_page = vec![0u8; 4096];
    hhive_page[0xd0..0xd8].copy_from_slice(&dir_vaddr.to_le_bytes());

    // Directory[0] @ 0 → table VA.
    let mut dir_page = vec![0u8; 4096];
    dir_page[0..8].copy_from_slice(&table_vaddr.to_le_bytes());

    // Table[0] @ 0: PermanentBinAddress = bins base (clean, no flags),
    // BlockOffset = 0. cell_index N → (bins & !0xF) + 0 + N = bins + N.
    let mut table_page = vec![0u8; 4096];
    table_page[0..8].copy_from_slice(&bins_vaddr.to_le_bytes());
    table_page[8..12].copy_from_slice(&0u32.to_le_bytes());

    // Bins-data page: everything after the 4096-byte base block.
    let bins = &hive[BaseBlock::SIZE..];
    let mut bins_page = vec![0u8; 4096];
    bins_page[..bins.len()].copy_from_slice(bins);

    let (cr3, mem) = PageTableBuilder::new()
        .map_4k(hhive_vaddr, hhive_p, flags::WRITABLE)
        .map_4k(dir_vaddr, dir_p, flags::WRITABLE)
        .map_4k(table_vaddr, table_p, flags::WRITABLE)
        .map_4k(bins_vaddr, bins_p, flags::WRITABLE)
        .write_phys(hhive_p, &hhive_page)
        .write_phys(dir_p, &dir_page)
        .write_phys(table_p, &table_page)
        .write_phys(bins_p, &bins_page)
        .build();
    let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
    (ObjectReader::new(vas, Box::new(resolver)), hhive_vaddr)
}

#[test]
fn both_backends_agree_on_walked_keys_and_values() {
    let hive_bytes = build_hive();

    // Flat-file backend (the reference).
    let flat = Hive::from_bytes(hive_bytes.clone()).expect("flat hive opens");
    let flat_root = flat.root_key().expect("flat root");

    // memf HMAP-backed backend over the same bytes.
    let (reader, hhive_addr) = build_memory_backed_reader(&hive_bytes);
    let memf = MemfHiveReader::new(&reader, hhive_addr);
    let memf_root =
        Key::from_cell_offset(&memf, CellOffset(ROOT_OFF)).expect("memf root from cell offset");

    // The `root_key()` convenience (which resolves the root cell index the way
    // every memf walker does, defaulting to 0x20 when the base block is absent)
    // must reach the same root as the explicit `from_cell_offset` seam.
    let memf_root_via_helper = memf.root_key().expect("memf root via root_key()");
    assert_eq!(snapshot(&memf_root), snapshot(&memf_root_via_helper));

    // Root agrees.
    let flat_snap = snapshot(&flat_root);
    let memf_snap = snapshot(&memf_root);
    assert_eq!(flat_snap, memf_snap, "root key snapshots must match");
    assert_eq!(flat_snap.name, "ROOT");
    assert!(flat_snap.is_root);
    assert_eq!(flat_snap.subkeys, vec!["Child".to_string()]);
    assert_eq!(
        flat_snap.values,
        vec![("Val".to_string(), b"AB".to_vec())],
        "resident value must decode to AB"
    );

    // Child subkey agrees, walked through each backend independently.
    let flat_child = flat_root.subkey("Child").unwrap().expect("flat child");
    let memf_child = memf_root.subkey("Child").unwrap().expect("memf child");
    assert_eq!(snapshot(&flat_child), snapshot(&memf_child));
}
