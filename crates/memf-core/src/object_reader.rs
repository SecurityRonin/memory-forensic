//! High-level kernel object reading using symbol resolution.

use bytemuck::Pod;
use memf_format::PhysicalMemoryProvider;
use memf_symbols::SymbolResolver;

use crate::vas::VirtualAddressSpace;
use crate::{Error, Result};

/// Maximum number of iterations when walking a linked list (cycle protection).
const MAX_LIST_ITERATIONS: usize = 100_000;

/// Reads kernel objects from a physical memory dump using symbol information.
///
/// Combines a [`VirtualAddressSpace`] with a [`SymbolResolver`] to provide
/// high-level access to kernel data structures like task_struct, modules, etc.
pub struct ObjectReader<P: PhysicalMemoryProvider> {
    vas: VirtualAddressSpace<P>,
    symbols: Box<dyn SymbolResolver>,
    /// Kernel image base virtual address (KVO). Windows ISF symbols are RVAs
    /// relative to this; it is added in [`Self::required_symbol`] so no caller
    /// can obtain an un-rebased address. Zero for resolvers whose symbols are
    /// already absolute VAs (e.g. Linux kallsyms), leaving them unchanged.
    kernel_base: u64,
}

impl<P: PhysicalMemoryProvider> ObjectReader<P> {
    /// Create a new object reader (kernel base unset → symbols used verbatim).
    pub fn new(vas: VirtualAddressSpace<P>, symbols: Box<dyn SymbolResolver>) -> Self {
        Self {
            vas,
            symbols,
            kernel_base: 0,
        }
    }

    /// Set the kernel image base VA (KVO) so RVA-based symbols are rebased to
    /// real virtual addresses. Builder form; the default (0) is a no-op.
    #[must_use]
    pub fn with_kernel_base(mut self, kernel_base: u64) -> Self {
        self.kernel_base = kernel_base;
        self
    }

    /// Access the underlying symbol resolver.
    pub fn symbols(&self) -> &dyn SymbolResolver {
        self.symbols.as_ref()
    }

    /// Access the underlying virtual address space.
    pub fn vas(&self) -> &VirtualAddressSpace<P> {
        &self.vas
    }

    /// Create a new reader sharing the same physical memory and symbols but
    /// using a different page table root (CR3). Useful for switching to a
    /// process's user-mode address space.
    pub fn with_cr3(&self, cr3: u64) -> Self
    where
        P: Clone,
    {
        let vas = VirtualAddressSpace::new(self.vas.physical().clone(), cr3, self.vas.mode());
        Self {
            vas,
            symbols: self.symbols.clone_boxed(),
            kernel_base: self.kernel_base,
        }
    }

    /// Read a field from a struct at `base_vaddr` and interpret it as type `T`.
    ///
    /// Looks up the field offset from the symbol resolver, reads `size_of::<T>()`
    /// bytes from virtual memory, and casts via `bytemuck::from_bytes`.
    pub fn read_field<T: Pod + Default>(
        &self,
        base_vaddr: u64,
        struct_name: &str,
        field_name: &str,
    ) -> Result<T> {
        let offset = self
            .symbols
            .field_offset(struct_name, field_name)
            .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{field_name}")))?;

        let size = std::mem::size_of::<T>();
        let mut buf = vec![0u8; size];
        self.vas
            .read_virt(base_vaddr.wrapping_add(offset), &mut buf)?;

        if buf.len() != size {
            return Err(Error::SizeMismatch {
                expected: size,
                got: buf.len(),
            });
        }

        Ok(*bytemuck::from_bytes::<T>(&buf))
    }

    /// Read a pointer (u64) from a struct field.
    pub fn read_pointer(
        &self,
        base_vaddr: u64,
        struct_name: &str,
        field_name: &str,
    ) -> Result<u64> {
        self.read_field::<u64>(base_vaddr, struct_name, field_name)
    }

    /// Read a null-terminated string from virtual memory, up to `max_len` bytes.
    pub fn read_string(&self, vaddr: u64, max_len: usize) -> Result<String> {
        let mut buf = vec![0u8; max_len];
        self.vas.read_virt(vaddr, &mut buf)?;

        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
    }

    /// Read a string from a struct field (the field contains inline char data, not a pointer).
    pub fn read_field_string(
        &self,
        base_vaddr: u64,
        struct_name: &str,
        field_name: &str,
        max_len: usize,
    ) -> Result<String> {
        let offset = self
            .symbols
            .field_offset(struct_name, field_name)
            .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{field_name}")))?;

        self.read_string(base_vaddr.wrapping_add(offset), max_len)
    }

    /// Walk a Linux `list_head` doubly-linked list.
    ///
    /// Starting from `head_vaddr` (the address of the list_head embedded in the
    /// head/sentinel node), follows `next` pointers and returns the virtual address
    /// of each containing struct (using container_of logic with `list_field` offset).
    ///
    /// Stops when the walk loops back to `head_vaddr` or hits `MAX_LIST_ITERATIONS`.
    pub fn walk_list(
        &self,
        head_vaddr: u64,
        struct_name: &str,
        list_field: &str,
    ) -> Result<Vec<u64>> {
        self.walk_list_with(head_vaddr, "list_head", "next", struct_name, list_field)
    }

    /// Walk a doubly-linked list with configurable list struct and field names.
    ///
    /// This is a generalized version of [`walk_list`](Self::walk_list) that works
    /// with any linked-list structure, not just Linux `list_head`.
    ///
    /// For example, Windows uses `_LIST_ENTRY` with `Flink`/`Blink` fields
    /// instead of `list_head` with `next`/`prev`.
    ///
    /// # Arguments
    /// * `head_vaddr` — virtual address of the list head (sentinel node)
    /// * `list_struct` — name of the list-link struct (e.g., `"list_head"`, `"_LIST_ENTRY"`)
    /// * `next_field` — name of the forward pointer field (e.g., `"next"`, `"Flink"`)
    /// * `container_struct` — name of the containing struct (e.g., `"_EPROCESS"`)
    /// * `list_field` — name of the list-link field in the container struct (e.g., `"ActiveProcessLinks"`)
    pub fn walk_list_with(
        &self,
        head_vaddr: u64,
        list_struct: &str,
        next_field: &str,
        container_struct: &str,
        list_field: &str,
    ) -> Result<Vec<u64>> {
        let list_offset = self
            .symbols
            .field_offset(container_struct, list_field)
            .ok_or_else(|| Error::MissingSymbol(format!("{container_struct}.{list_field}")))?;

        let next_offset = self
            .symbols
            .field_offset(list_struct, next_field)
            .ok_or_else(|| Error::MissingSymbol(format!("{list_struct}.{next_field}")))?;

        // Read the first forward pointer from head
        let mut current = self.read_u64_at(head_vaddr.wrapping_add(next_offset))?;

        let mut result = Vec::new();

        for _ in 0..MAX_LIST_ITERATIONS {
            // If we've looped back to head, the walk is complete
            if current == head_vaddr {
                return Ok(result);
            }

            // Smear tolerance: a live-acquired dump can contain a torn-down node
            // whose link reads 0 (a null terminus). Stop rather than dereference
            // null or fabricate a container from `0 - offset`.
            if current == 0 {
                return Ok(result);
            }

            // Peek-before-record: read this node's forward pointer FIRST. If its
            // LIST_ENTRY page is not mapped, `current` is not a real node — a
            // torn-down node's link can hold garbage (e.g. the user-half value
            // 0x5a289000 seen on DESKTOP-SDN1RPT.mem, which is canonical but
            // unmapped). Terminate without fabricating a container that a later
            // field read would fault on. This works for BOTH kernel object lists
            // and user-space lists (PEB/LDR modules), so it must NOT assume a
            // kernel-half address.
            let next = match self.read_u64_at(current.wrapping_add(next_offset)) {
                Ok(next) => next,
                Err(_) => return Ok(result),
            };

            // container_of: subtract list_offset to get the containing struct base
            result.push(current.wrapping_sub(list_offset));
            current = next;
        }

        Err(Error::ListCycle(MAX_LIST_ITERATIONS))
    }

    /// Walk a doubly-linked list in BOTH directions and return the union of
    /// containers, deduplicated (forward order first, then backward-only nodes).
    ///
    /// On a live-acquired dump a single torn-down node can break the forward
    /// (`next_field`/Flink) chain, orphaning every node beyond it from a
    /// forward-only walk — yet those nodes remain reachable from the head via the
    /// backward (`prev_field`/Blink) chain. Walking both directions recovers them
    /// without resorting to pool-tag scanning. (A node unlinked from *both*
    /// directions — full DKOM hiding — still requires a pool scan.)
    pub fn walk_list_bidirectional(
        &self,
        head_vaddr: u64,
        list_struct: &str,
        next_field: &str,
        prev_field: &str,
        container_struct: &str,
        list_field: &str,
    ) -> Result<Vec<u64>> {
        let mut forward =
            self.walk_list_with(head_vaddr, list_struct, next_field, container_struct, list_field)?;
        let backward =
            self.walk_list_with(head_vaddr, list_struct, prev_field, container_struct, list_field)?;
        let mut seen: std::collections::HashSet<u64> = forward.iter().copied().collect();
        for container in backward {
            if seen.insert(container) {
                forward.push(container);
            }
        }
        Ok(forward)
    }

    /// Read `len` raw bytes from virtual memory at `vaddr`.
    pub fn read_bytes(&self, vaddr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.vas.read_virt(vaddr, &mut buf)?;
        Ok(buf)
    }

    /// Resolve a global kernel symbol to a real virtual address, returning an
    /// error if absent. The resolver yields an RVA (Windows ISF); the kernel
    /// base (KVO) is added here so callers cannot obtain an un-rebased address.
    pub fn required_symbol(&self, name: &str) -> Result<u64> {
        self.symbols()
            .symbol_address(name)
            .map(|rva| self.kernel_base.wrapping_add(rva))
            .ok_or_else(|| Error::MissingSymbol(name.to_owned()))
    }

    /// Resolve a struct field offset, returning an error if absent.
    pub fn required_field_offset(&self, struct_name: &str, field_name: &str) -> Result<usize> {
        self.symbols()
            .field_offset(struct_name, field_name)
            .map(|v| v as usize)
            .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{field_name}")))
    }

    fn read_u64_at(&self, vaddr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.vas.read_virt(vaddr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Returns a lazy iterator over a kernel linked list (Linux `list_head`).
    ///
    /// Yields the virtual address of each containing struct (container_of adjusted),
    /// same as [`walk_list`](Self::walk_list). Unlike `walk_list`, this does not
    /// allocate a `Vec` — entries are yielded one at a time. Use `.take(n)` for
    /// early termination or filter with `.filter_map`.
    ///
    /// # Errors
    ///
    /// Each yielded item is `Result<u64>`. The iterator stops (returning `None`) on
    /// cycle or when the list loops back to `head_vaddr`. If a pointer read fails,
    /// the failing `Err` is yielded as the last item.
    pub fn iter_list<'a>(
        &'a self,
        head_vaddr: u64,
        container_struct: &'a str,
        list_field: &'a str,
    ) -> ListIter<'a, P> {
        let list_offset = self
            .symbols
            .field_offset(container_struct, list_field)
            .unwrap_or(0);
        let next_offset = self
            .symbols
            .field_offset("list_head", "next")
            .unwrap_or(0);

        let current = match self.read_u64_at(head_vaddr.wrapping_add(next_offset)) {
            Ok(v) => v,
            Err(_) => head_vaddr, // will immediately return None (current == head)
        };

        ListIter {
            reader: self,
            head_vaddr,
            current,
            list_offset,
            next_offset,
            seen: std::collections::HashSet::new(),
            done: false,
        }
    }
}

/// Streaming iterator over a kernel doubly-linked list.
///
/// Returned by [`ObjectReader::iter_list`]. Yields the virtual address of each
/// container struct (using container_of logic, same as [`ObjectReader::walk_list`]).
pub struct ListIter<'a, P: PhysicalMemoryProvider> {
    reader: &'a ObjectReader<P>,
    head_vaddr: u64,
    current: u64,
    list_offset: u64,
    next_offset: u64,
    seen: std::collections::HashSet<u64>,
    done: bool,
}

impl<P: PhysicalMemoryProvider> Iterator for ListIter<'_, P> {
    type Item = crate::Result<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        // Termination: looped back to head
        if self.current == self.head_vaddr {
            return None;
        }
        // Cycle detection
        if !self.seen.insert(self.current) {
            self.done = true;
            return None; // silently stop on detected cycle without valid entry
        }
        if self.seen.len() > MAX_LIST_ITERATIONS {
            self.done = true;
            return Some(Err(crate::Error::ListCycle(MAX_LIST_ITERATIONS)));
        }

        // container_of: subtract list_offset to get containing struct base
        let container = self.current.wrapping_sub(self.list_offset);

        // Advance: follow next pointer
        match self
            .reader
            .read_u64_at(self.current.wrapping_add(self.next_offset))
        {
            Ok(next) => self.current = next,
            Err(e) => {
                self.done = true;
                return Some(Err(e));
            }
        }

        Some(Ok(container))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_builders::{flags, PageTableBuilder};
    use crate::vas::TranslationMode;
    use memf_symbols::isf::IsfResolver;
    use memf_symbols::test_builders::IsfBuilder;

    fn make_reader(
        isf: &IsfBuilder,
        builder: PageTableBuilder,
    ) -> ObjectReader<crate::test_builders::SyntheticPhysMem> {
        let json = isf.build_json();
        let resolver = IsfResolver::from_value(&json).unwrap();
        let (cr3, mem) = builder.build();
        let vas = VirtualAddressSpace::new(mem, cr3, TranslationMode::X86_64FourLevel);
        ObjectReader::new(vas, Box::new(resolver))
    }

    #[test]
    fn read_field_u32() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "pid",
            0,
            "int",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys_u64(paddr, u64::from(42u32)); // pid = 42 at offset 0

        let reader = make_reader(&isf, ptb);
        let pid: u32 = reader.read_field(vaddr, "task_struct", "pid").unwrap();
        assert_eq!(pid, 42);
    }

    #[test]
    fn read_field_u64() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "mm",
            8,
            "pointer",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mm_value: u64 = 0xFFFF_8000_DEAD_BEEF;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys_u64(paddr + 8, mm_value);

        let reader = make_reader(&isf, ptb);
        let mm: u64 = reader.read_field(vaddr, "task_struct", "mm").unwrap();
        assert_eq!(mm, mm_value);
    }

    #[test]
    fn read_field_missing_symbol() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        let result = reader.read_field::<u32>(vaddr, "task_struct", "nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::MissingSymbol(s) => assert_eq!(s, "task_struct.nonexistent"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn read_field_string_test() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "comm",
            16,
            "char",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr + 16, b"systemd\0");

        let reader = make_reader(&isf, ptb);
        let comm = reader
            .read_field_string(vaddr, "task_struct", "comm", 16)
            .unwrap();
        assert_eq!(comm, "systemd");
    }

    #[test]
    fn read_string_with_null() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "comm",
            16,
            "char",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr + 16, b"init\0\0\0\0\0\0\0\0\0\0\0\0");

        let reader = make_reader(&isf, ptb);
        let s = reader.read_string(vaddr + 16, 16).unwrap();
        assert_eq!(s, "init");
    }

    #[test]
    fn walk_list_simple() {
        // Create a simplified task_struct layout:
        //   offset 0: pid (u32)
        //   offset 8: tasks.next (u64)  -- list_head embedded at offset 8
        //   offset 16: comm (16 bytes)
        //   struct size: 128
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_field("task_struct", "comm", 16, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer");

        // Physical layout:
        //   paddr 0x0080_0000: head task_struct (init_task)
        //   paddr 0x0080_1000: task A
        //   paddr 0x0080_2000: task B
        //
        // Circular list:
        //   head.tasks.next -> A.tasks -> B.tasks -> head.tasks
        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;

        let list_offset: u64 = 8; // tasks field offset

        // head.tasks.next = &A.tasks
        // A.tasks.next = &B.tasks
        // B.tasks.next = &head.tasks
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            // head: pid=0, tasks.next = a_vaddr + list_offset
            .write_phys_u64(head_paddr, 0) // pid
            .write_phys_u64(head_paddr + list_offset, a_vaddr + list_offset) // tasks.next
            // A: pid=100, tasks.next = b_vaddr + list_offset
            .write_phys_u64(a_paddr, 100) // pid
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset) // tasks.next
            // B: pid=200, tasks.next = head_vaddr + list_offset (loops back)
            .write_phys_u64(b_paddr, 200) // pid
            .write_phys_u64(b_paddr + list_offset, head_vaddr + list_offset); // tasks.next

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list(head_vaddr + list_offset, "task_struct", "tasks")
            .unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0], a_vaddr);
        assert_eq!(containers[1], b_vaddr);
    }

    #[test]
    fn read_pointer_test() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "mm",
            8,
            "pointer",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let mm_value: u64 = 0xFFFF_8000_CAFE_BABE;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys_u64(paddr + 8, mm_value);

        let reader = make_reader(&isf, ptb);
        let ptr = reader.read_pointer(vaddr, "task_struct", "mm").unwrap();
        assert_eq!(ptr, mm_value);
    }

    #[test]
    fn read_field_invalid_struct_name() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128).add_field(
            "task_struct",
            "pid",
            0,
            "int",
        );

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        let result = reader.read_field::<u32>(vaddr, "nonexistent_struct", "pid");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::MissingSymbol(s) => assert_eq!(s, "nonexistent_struct.pid"),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn walk_list_empty_list() {
        // A list where head.next points back to head (empty list)
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let list_offset: u64 = 8;

        // head.tasks.next = head.tasks (points back to itself -> empty list)
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr + list_offset, head_vaddr + list_offset);

        let reader = make_reader(&isf, ptb);
        let containers = reader
            .walk_list(head_vaddr + list_offset, "task_struct", "tasks")
            .unwrap();
        assert!(containers.is_empty());
    }

    #[test]
    fn walk_list_with_windows_list_entry() {
        // Test walk_list_with using Windows _LIST_ENTRY / Flink naming.
        // Layout: _EPROCESS with ActiveProcessLinks at offset 0x10.
        // _LIST_ENTRY with Flink at offset 0, Blink at offset 8.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "UniqueProcessId", 0, "pointer")
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        // Physical layout:
        //   head (sentinel list head at some vaddr)
        //   proc_a at paddr 0x0080_1000
        //   proc_b at paddr 0x0080_2000
        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000; // sentinel list head
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;

        let list_offset: u64 = 0x10; // ActiveProcessLinks offset in _EPROCESS

        // Circular: head.Flink -> A.ActiveProcessLinks -> B.ActiveProcessLinks -> head
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            // head sentinel: Flink -> A.ActiveProcessLinks
            .write_phys_u64(head_paddr, a_vaddr + list_offset) // Flink
            // A: pid=4, ActiveProcessLinks.Flink -> B.ActiveProcessLinks
            .write_phys_u64(a_paddr, 4) // UniqueProcessId
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset) // Flink
            // B: pid=100, ActiveProcessLinks.Flink -> head (loop back)
            .write_phys_u64(b_paddr, 100) // UniqueProcessId
            .write_phys_u64(b_paddr + list_offset, head_vaddr); // Flink -> head

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list_with(
                head_vaddr,
                "_LIST_ENTRY",
                "Flink",
                "_EPROCESS",
                "ActiveProcessLinks",
            )
            .unwrap();

        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0], a_vaddr);
        assert_eq!(containers[1], b_vaddr);
    }

    #[test]
    fn walk_list_with_tolerates_smeared_null_link() {
        // Real raw dumps captured live contain "smear": a torn-down EPROCESS
        // whose ActiveProcessLinks.Flink reads as 0 (validated on
        // DESKTOP-SDN1RPT.mem at process #83, a duplicate pid-4096 empty-name
        // rundown entry). The walk must return the processes collected so far —
        // NOT hard-error and lose all of them, and NOT push a bogus container
        // derived from the null pointer.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let list_offset: u64 = 0x10;

        // head -> A -> B -> NULL (smear: B.Flink == 0, never loops back to head).
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, a_vaddr + list_offset)
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset)
            .write_phys_u64(b_paddr + list_offset, 0); // smeared null Flink

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list_with(
                head_vaddr,
                "_LIST_ENTRY",
                "Flink",
                "_EPROCESS",
                "ActiveProcessLinks",
            )
            .expect("a smeared null link must terminate the walk gracefully, not error");

        // A and B were reached before the smear; the null link is the terminus.
        assert_eq!(containers, vec![a_vaddr, b_vaddr]);
    }

    #[test]
    fn walk_list_with_stops_on_non_canonical_kernel_pointer() {
        // A torn-down node's link can hold a non-canonical / user-half garbage
        // value (DESKTOP-SDN1RPT.mem: a smeared Blink of 0x5a289000). The walk
        // must treat it as a terminus — NOT fabricate a container from it (which
        // a later field read would fault on), NOT error.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let lo: u64 = 0x10;
        let head_p = 0x0080_0000u64;
        let a_p = 0x0080_1000u64;
        let head_v = 0xFFFF_8000_0010_0000u64;
        let a_v = 0xFFFF_8000_0010_1000u64;

        // head -> A -> (garbage, non-canonical user-half pointer)
        let ptb = PageTableBuilder::new()
            .map_4k(head_v, head_p, flags::WRITABLE)
            .map_4k(a_v, a_p, flags::WRITABLE)
            .write_phys_u64(head_p, a_v + lo)
            .write_phys_u64(a_p + lo, 0x0000_0000_5A28_9000); // non-canonical garbage

        let reader = make_reader(&isf, ptb);
        let containers = reader
            .walk_list_with(head_v, "_LIST_ENTRY", "Flink", "_EPROCESS", "ActiveProcessLinks")
            .expect("non-canonical link terminates the walk, not errors");

        assert_eq!(containers, vec![a_v], "only the real node A; no bogus container");
    }

    #[test]
    fn walk_list_bidirectional_recovers_forward_orphans() {
        // A doubly-linked list whose FORWARD chain is smeared (B.Flink = 0) but
        // whose BACKWARD chain (Blink) is intact. The forward walk reaches only
        // A and B; the node C, orphaned forward, is still reachable via Blink
        // from the head. A bidirectional walk must return all three. This is the
        // DESKTOP-SDN1RPT.mem case: 11 processes after the smear are recovered
        // from the Blink side.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let lo: u64 = 0x10;
        let head_p = 0x0080_0000u64;
        let a_p = 0x0080_1000u64;
        let b_p = 0x0080_2000u64;
        let c_p = 0x0080_3000u64;
        let head_v = 0xFFFF_8000_0010_0000u64;
        let a_v = 0xFFFF_8000_0010_1000u64;
        let b_v = 0xFFFF_8000_0010_2000u64;
        let c_v = 0xFFFF_8000_0010_3000u64;

        let ptb = PageTableBuilder::new()
            .map_4k(head_v, head_p, flags::WRITABLE)
            .map_4k(a_v, a_p, flags::WRITABLE)
            .map_4k(b_v, b_p, flags::WRITABLE)
            .map_4k(c_v, c_p, flags::WRITABLE)
            // head: Flink -> A, Blink -> C
            .write_phys_u64(head_p, a_v + lo)
            .write_phys_u64(head_p + 8, c_v + lo)
            // A: Flink -> B, Blink -> head
            .write_phys_u64(a_p + lo, b_v + lo)
            .write_phys_u64(a_p + lo + 8, head_v)
            // B: Flink -> 0 (forward smear), Blink -> A
            .write_phys_u64(b_p + lo, 0)
            .write_phys_u64(b_p + lo + 8, a_v + lo)
            // C: Flink -> head, Blink -> B
            .write_phys_u64(c_p + lo, head_v)
            .write_phys_u64(c_p + lo + 8, b_v + lo);

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list_bidirectional(
                head_v,
                "_LIST_ENTRY",
                "Flink",
                "Blink",
                "_EPROCESS",
                "ActiveProcessLinks",
            )
            .unwrap();

        // Forward gives [A, B]; backward adds [C]. Order: forward first, then
        // backward-only, deduplicated.
        assert_eq!(containers.len(), 3, "all three nodes recovered: {containers:x?}");
        assert!(containers.contains(&a_v));
        assert!(containers.contains(&b_v));
        assert!(containers.contains(&c_v), "forward-orphaned C recovered via Blink");
    }

    #[test]
    fn walk_list_with_empty() {
        // Empty list: head.Flink points back to head.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;

        // head.Flink = head (empty circular list)
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, head_vaddr); // Flink -> self

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list_with(
                head_vaddr,
                "_LIST_ENTRY",
                "Flink",
                "_EPROCESS",
                "ActiveProcessLinks",
            )
            .unwrap();

        assert!(containers.is_empty());
    }

    #[test]
    fn walk_list_still_works_after_refactor() {
        // Ensure the existing walk_list (Linux list_head/next) still works
        // after the refactor to call walk_list_with internally.
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;

        let list_offset: u64 = 8;

        // Single-element list: head.next -> A.tasks -> head.tasks
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr + list_offset, a_vaddr + list_offset)
            .write_phys_u64(a_paddr, 42) // pid
            .write_phys_u64(a_paddr + list_offset, head_vaddr + list_offset);

        let reader = make_reader(&isf, ptb);

        let containers = reader
            .walk_list(head_vaddr + list_offset, "task_struct", "tasks")
            .unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0], a_vaddr);
    }

    #[test]
    fn symbols_accessor() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_symbol("init_task", 0xFFFF_0000);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        assert_eq!(reader.symbols().backend_name(), "ISF JSON");
        assert_eq!(reader.symbols().field_offset("task_struct", "pid"), Some(0));
    }

    #[test]
    fn required_symbol_ok() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_symbol("init_task", 0xFFFF_8000_CAFE_0000);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        assert_eq!(
            reader.required_symbol("init_task").unwrap(),
            0xFFFF_8000_CAFE_0000
        );
    }

    #[test]
    fn required_symbol_rebases_by_kernel_base() {
        let isf = IsfBuilder::new()
            .add_struct("x", 1)
            .add_symbol("PsActiveProcessHead", 0x002b_00a0);
        let reader = make_reader(&isf, PageTableBuilder::new())
            .with_kernel_base(0xFFFF_F800_CBE0_0000);
        assert_eq!(
            reader.required_symbol("PsActiveProcessHead").unwrap(),
            0xFFFF_F800_CC0B_00A0
        );
    }

    #[test]
    fn required_symbol_missing_returns_error() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        assert!(reader.required_symbol("nonexistent").is_err());
    }

    #[test]
    fn required_field_offset_ok() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 4, "int");

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        assert_eq!(
            reader.required_field_offset("task_struct", "pid").unwrap(),
            4
        );
    }

    #[test]
    fn required_field_offset_missing_returns_error() {
        let isf = IsfBuilder::new().add_struct("task_struct", 128);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;
        let ptb = PageTableBuilder::new().map_4k(vaddr, paddr, flags::WRITABLE);

        let reader = make_reader(&isf, ptb);
        assert!(reader
            .required_field_offset("task_struct", "nonexistent")
            .is_err());
    }

    #[test]
    fn walk_list_cycle_detection() {
        // ISF: _EPROCESS with ActiveProcessLinks at offset 0x10;
        // _LIST_ENTRY with Flink at offset 0.
        let isf = IsfBuilder::new()
            .add_struct("_EPROCESS", 256)
            .add_field("_EPROCESS", "ActiveProcessLinks", 0x10, "_LIST_ENTRY")
            .add_struct("_LIST_ENTRY", 16)
            .add_field("_LIST_ENTRY", "Flink", 0, "pointer")
            .add_field("_LIST_ENTRY", "Blink", 8, "pointer");

        // head: never referenced by the cycle, so the walk never terminates
        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;

        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;

        let list_offset: u64 = 0x10; // ActiveProcessLinks offset

        // head.Flink → a.ActiveProcessLinks (kick off the walk)
        // A.Flink → B.ActiveProcessLinks
        // B.Flink → A.ActiveProcessLinks  (cycle — never reaches head)
        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            // head.Flink → a's list field
            .write_phys_u64(head_paddr, a_vaddr + list_offset)
            // A.ActiveProcessLinks.Flink → B.ActiveProcessLinks
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset)
            // B.ActiveProcessLinks.Flink → A.ActiveProcessLinks (cycle)
            .write_phys_u64(b_paddr + list_offset, a_vaddr + list_offset);

        let reader = make_reader(&isf, ptb);
        let result = reader.walk_list_with(
            head_vaddr,
            "_LIST_ENTRY",
            "Flink",
            "_EPROCESS",
            "ActiveProcessLinks",
        );

        assert!(
            matches!(result, Err(Error::ListCycle(_))),
            "expected ListCycle error, got: {result:?}"
        );
    }

    #[test]
    fn iter_list_yields_same_as_walk_list() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_field("task_struct", "comm", 16, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let list_offset: u64 = 8;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, 0)
            .write_phys_u64(head_paddr + list_offset, a_vaddr + list_offset)
            .write_phys_u64(a_paddr, 100)
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset)
            .write_phys_u64(b_paddr, 200)
            .write_phys_u64(b_paddr + list_offset, head_vaddr + list_offset);

        let reader = make_reader(&isf, ptb);
        let head = head_vaddr + list_offset;

        let walk_result = reader.walk_list(head, "task_struct", "tasks").unwrap();
        let iter_result: Vec<u64> = reader
            .iter_list(head, "task_struct", "tasks")
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(iter_result, walk_result);
    }

    #[test]
    fn iter_list_take_stops_early() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int")
            .add_field("task_struct", "tasks", 8, "list_head")
            .add_field("task_struct", "comm", 16, "char")
            .add_struct("list_head", 16)
            .add_field("list_head", "next", 0, "pointer")
            .add_field("list_head", "prev", 8, "pointer");

        let head_paddr: u64 = 0x0080_0000;
        let a_paddr: u64 = 0x0080_1000;
        let b_paddr: u64 = 0x0080_2000;
        let head_vaddr: u64 = 0xFFFF_8000_0010_0000;
        let a_vaddr: u64 = 0xFFFF_8000_0010_1000;
        let b_vaddr: u64 = 0xFFFF_8000_0010_2000;
        let list_offset: u64 = 8;

        let ptb = PageTableBuilder::new()
            .map_4k(head_vaddr, head_paddr, flags::WRITABLE)
            .map_4k(a_vaddr, a_paddr, flags::WRITABLE)
            .map_4k(b_vaddr, b_paddr, flags::WRITABLE)
            .write_phys_u64(head_paddr, 0)
            .write_phys_u64(head_paddr + list_offset, a_vaddr + list_offset)
            .write_phys_u64(a_paddr, 100)
            .write_phys_u64(a_paddr + list_offset, b_vaddr + list_offset)
            .write_phys_u64(b_paddr, 200)
            .write_phys_u64(b_paddr + list_offset, head_vaddr + list_offset);

        let reader = make_reader(&isf, ptb);
        let head = head_vaddr + list_offset;

        let first_two: Vec<u64> = reader
            .iter_list(head, "task_struct", "tasks")
            .take(2)
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(first_two.len(), 2);
    }
}
