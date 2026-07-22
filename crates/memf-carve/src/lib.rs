//! `memf-carve` — Plane-V memory artifact carving (the `[M]`-medium application of
//! the fleet `forensic-carve` sweep).
//!
//! This crate does **not** reimplement carving. The [`forensic_carve`] sweep engine
//! already owns detection (chunked aho-corasick scanning through
//! [`forensic_carve::RegionSource`]) and materialize-around-hit (it reads the
//! carver-declared window through the same `read_at`). `memf-carve` supplies the
//! *memory* pieces the engine needs:
//!
//! - [`VaRegionSource`] — a [`forensic_carve::RegionSource`] over a process's
//!   **virtual** address space, delegating to `memf-core`'s
//!   [`memf_core::vas::VirtualAddressSpace::read_virt`] so the engine reads
//!   virtually-contiguous bytes with page-crossing resolved for it. A non-resident
//!   / paged-out page yields a **short read** (never fabricated or zero-filled
//!   bytes), which the engine treats as a region gap.
//! - [`MemAttribution`] + [`process_regions`] — one [`forensic_carve::Region`] per
//!   VAD, tagged with **coarse** attribution (pid / process / VA start / protection /
//!   private flag). There is no rich Heap/Stack/MappedFile classification because the
//!   VAD walker does not expose one.
//! - [`carve_process`] — the driver: builds a [`VaRegionSource`], enumerates the
//!   process's VAD regions, and runs [`forensic_carve::sweep`] forcing
//!   [`forensic_carve::RecoveryMethod::MemoryCarve`]. Carvers arrive via injection or
//!   [`forensic_carve::registered_carvers`]; `memf-carve` never depends on a parser
//!   crate.
//! - [`carve_dump`] / [`carve_dump_from_processes`] — the multi-process Plane-V
//!   driver: [`carve_dump`] carves every [`ProcessView`] in a resolved set;
//!   [`carve_dump_from_processes`] is the thin resolver that walks each Windows
//!   process's `_EPROCESS.VadRoot` and builds its user VAS from `cr3` before
//!   carving. Attribution rides each item back out on its owning pid / name.
//!
//! # Scope: Plane-V ONLY (fleet ADR 0001 §5)
//!
//! This crate carves **resident / VAS-reachable** process memory only. The following
//! are deliberately deferred (ADR 0001 §6) and are **not** implemented here:
//!
//! - **Plane-P** — physical-frame carving of unallocated / process-unowned pages
//!   (a `PfnRegionSource` over the raw physical stream driven by the PFN database).
//! - **PFN bitmap** — using the PFN database to find and attribute free/standby frames.
//! - **Pagefile gap-fill** — reassembling a paged-out region from `pagefile.sys`
//!   during a carve (a short read here simply ends the window).
//! - **Confidence floor** — the driver keeps every carved item
//!   ([`forensic_carve::ConfidencePolicy::KeepAll`]); a memory-specific floor is future work.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod attribution;
mod driver;
mod dump;
mod region_source;

pub use attribution::{process_regions, MemAttribution};
pub use driver::carve_process;
pub use dump::{carve_dump, carve_dump_from_processes, ProcessView};
pub use region_source::VaRegionSource;
