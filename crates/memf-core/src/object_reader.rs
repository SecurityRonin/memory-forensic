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
}

impl<P: PhysicalMemoryProvider> ObjectReader<P> {
    /// Create a new object reader.
    pub fn new(vas: VirtualAddressSpace<P>, symbols: Box<dyn SymbolResolver>) -> Self {
        Self { vas, symbols }
    }

    /// Read a field from a struct at `base_vaddr` and interpret it as type `T`.
    ///
    /// Looks up the field offset from the symbol resolver, reads `size_of::<T>()`
    /// bytes from virtual memory, and casts via `bytemuck::from_bytes`.
    pub fn read_field<T: Pod + Default>(&self, base_vaddr: u64, struct_name: &str, field_name: &str) -> Result<T> {
        let offset = self.symbols.field_offset(struct_name, field_name)
            .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{field_name}")))?;

        let size = std::mem::size_of::<T>();
        let mut buf = vec![0u8; size];
        self.vas.read_virt(base_vaddr.wrapping_add(offset), &mut buf)?;

        if buf.len() != size {
            return Err(Error::SizeMismatch { expected: size, got: buf.len() });
        }

        Ok(*bytemuck::from_bytes::<T>(&buf))
    }

    /// Read a pointer (u64) from a struct field.
    pub fn read_pointer(&self, base_vaddr: u64, struct_name: &str, field_name: &str) -> Result<u64> {
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
    pub fn read_field_string(&self, base_vaddr: u64, struct_name: &str, field_name: &str, max_len: usize) -> Result<String> {
        let offset = self.symbols.field_offset(struct_name, field_name)
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
    pub fn walk_list(&self, head_vaddr: u64, struct_name: &str, list_field: &str) -> Result<Vec<u64>> {
        let list_offset = self.symbols.field_offset(struct_name, list_field)
            .ok_or_else(|| Error::MissingSymbol(format!("{struct_name}.{list_field}")))?;

        let next_offset = self.symbols.field_offset("list_head", "next")
            .ok_or_else(|| Error::MissingSymbol("list_head.next".into()))?;

        // Read the first `next` pointer from head
        let mut current = self.read_u64_at(head_vaddr.wrapping_add(next_offset))?;

        let mut result = Vec::new();

        for _ in 0..MAX_LIST_ITERATIONS {
            // If we've looped back to head, we're done
            if current == head_vaddr {
                return Ok(result);
            }

            // container_of: subtract list_offset to get struct base
            let container = current.wrapping_sub(list_offset);
            result.push(container);

            // Follow next pointer
            current = self.read_u64_at(current.wrapping_add(next_offset))?;
        }

        Err(Error::ListCycle(MAX_LIST_ITERATIONS))
    }

    fn read_u64_at(&self, vaddr: u64) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.vas.read_virt(vaddr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
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
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "pid", 0, "int");

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys_u64(paddr, 42u32 as u64); // pid = 42 at offset 0

        let reader = make_reader(&isf, ptb);
        let pid: u32 = reader.read_field(vaddr, "task_struct", "pid").unwrap();
        assert_eq!(pid, 42);
    }

    #[test]
    fn read_field_u64() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "mm", 8, "pointer");

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
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128);

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE);

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
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "comm", 16, "char");

        let vaddr: u64 = 0xFFFF_8000_0010_0000;
        let paddr: u64 = 0x0080_0000;

        let ptb = PageTableBuilder::new()
            .map_4k(vaddr, paddr, flags::WRITABLE)
            .write_phys(paddr + 16, b"systemd\0");

        let reader = make_reader(&isf, ptb);
        let comm = reader.read_field_string(vaddr, "task_struct", "comm", 16).unwrap();
        assert_eq!(comm, "systemd");
    }

    #[test]
    fn read_string_with_null() {
        let isf = IsfBuilder::new()
            .add_struct("task_struct", 128)
            .add_field("task_struct", "comm", 16, "char");

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

        let containers = reader.walk_list(head_vaddr + list_offset, "task_struct", "tasks").unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0], a_vaddr);
        assert_eq!(containers[1], b_vaddr);
    }
}
