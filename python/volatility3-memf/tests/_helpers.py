"""Shared helpers and path constants for the volatility3-memf test suite."""
from __future__ import annotations

from pathlib import Path

MEMF = Path("/Users/4n6h4x0r/src/memory-forensic/target/release/memf")
DUMP_PRIMARY = Path("/tmp/vol3_test/DESKTOP-SDN1RPT.mem")
DUMP_PRIMARY_DTB = 0x1AD000
DUMP_BANKING = Path("/tmp/vol3_test/banking-malware.vmem")
ISSEN_DATA = Path.home() / "src/issen/tests/data"
DUMP_BANKING_ZIP = ISSEN_DATA / "CyberDefenders/78-DeepDive.zip"


def build_memf_context(dump_path: Path, dtb: int = 0x1000):
    """Return (ctx, phys_layer, intel_layer) backed by MemfDataLayer."""
    from volatility3.framework import contexts
    from volatility3.framework.layers.intel import WindowsIntel32e

    from volatility3_memf.data_layer import MemfDataLayer

    ctx = contexts.Context()
    phys = MemfDataLayer(
        ctx,
        "layers.MemfPhys",
        "MemfPhys",
        dump_path=str(dump_path),
        memf_binary=str(MEMF),
        timeout=10,
    )
    ctx.add_layer(phys)
    ctx.config["layers.IntelMemf.memory_layer"] = "MemfPhys"
    ctx.config["layers.IntelMemf.page_map_offset"] = dtb
    intel = WindowsIntel32e(ctx, "layers.IntelMemf", "IntelMemf")
    ctx.add_layer(intel)
    return ctx, phys, intel


def no_rust_panic(stderr: bytes, label: str = "") -> None:
    """Assert memf did not emit a Rust panic traceback."""
    assert b"panicked" not in stderr, (
        f"Rust panic{' in ' + label if label else ''}:\n"
        + stderr.decode(errors="replace")[:500]
    )
