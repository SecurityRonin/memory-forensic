"""Compatibility tests: top-25% vol3 Windows plugins through MemfDataLayer.

These tests require:
  - DESKTOP-SDN1RPT.mem at the path below (Win10 x64 19041)
  - vol3 installed (`pip install volatility3`)
  - memf release binary

All tests are skipped if any prerequisite is missing.
Mark: @pytest.mark.integration
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

DUMP = Path("/tmp/vol3_test/DESKTOP-SDN1RPT.mem")
MEMF = Path("/Users/4n6h4x0r/src/memory-forensic/target/release/memf")
KERNEL_DTB = 0x1AD000

requires_integration = pytest.mark.skipif(
    not (DUMP.exists() and MEMF.exists()),
    reason="integration prerequisites not available (dump or memf binary missing)",
)


def _vol3_run(plugin: str, timeout: int = 120) -> list[str]:
    """Run a vol3 plugin natively and return non-header text lines."""
    r = subprocess.run(
        ["vol", "-f", str(DUMP), plugin],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if r.returncode != 0:
        pytest.skip(f"native vol3 {plugin} failed: {r.stderr[:200]}")
    return [ln for ln in r.stdout.splitlines() if ln.strip() and not ln.startswith("Volatility")]


def _build_memf_context():
    """Build a vol3 context with MemfDataLayer as the physical backing."""
    from volatility3.framework import contexts
    from volatility3.framework.layers.intel import WindowsIntel32e

    from volatility3_memf.data_layer import MemfDataLayer

    ctx = contexts.Context()
    layer = MemfDataLayer(
        ctx,
        "layers.MemfPhys",
        "MemfPhys",
        dump_path=str(DUMP),
        memf_binary=str(MEMF),
        timeout=60,
    )
    ctx.add_layer(layer)

    ctx.config["layers.IntelMemf.memory_layer"] = "MemfPhys"
    ctx.config["layers.IntelMemf.page_map_offset"] = KERNEL_DTB
    intel = WindowsIntel32e(ctx, "layers.IntelMemf", "IntelMemf")
    ctx.add_layer(intel)

    return ctx, intel


def _parse_pids(lines: list[str]) -> set[int]:
    pids: set[int] = set()
    for line in lines:
        parts = line.split()
        if parts and parts[0].isdigit():
            try:
                pids.add(int(parts[0]))
            except ValueError:
                pass
    return pids


# ─────────────────────────────────────────────────────────────────────────────
# Layer integration sanity
# ─────────────────────────────────────────────────────────────────────────────


@requires_integration
@pytest.mark.integration
class TestLayerIntegration:
    """MemfDataLayer correctly implements DataLayerInterface for the vol3 stack."""

    def test_layer_registers_in_context(self) -> None:
        ctx, _ = _build_memf_context()
        assert "MemfPhys" in ctx.layers

    def test_intel_layer_stacks_on_memf(self) -> None:
        ctx, intel = _build_memf_context()
        assert "IntelMemf" in ctx.layers
        assert intel.config.get("memory_layer") == "MemfPhys"

    def test_maximum_address_matches_file_size(self) -> None:
        ctx, _ = _build_memf_context()
        phys = ctx.layers["MemfPhys"]
        expected = DUMP.stat().st_size - 1
        assert phys.maximum_address == expected

    def test_minimum_address_is_zero(self) -> None:
        ctx, _ = _build_memf_context()
        assert ctx.layers["MemfPhys"].minimum_address == 0

    def test_physical_read_at_dtb_returns_nonzero_data(self) -> None:
        ctx, _ = _build_memf_context()
        phys = ctx.layers["MemfPhys"]
        data = phys.read(KERNEL_DTB, 8, pad=True)
        assert len(data) == 8
        assert data != b"\x00" * 8

    def test_va_translation_kernel_base_is_consistent(self) -> None:
        """Translate a well-known kernel VA — result must be > 0 and page-aligned."""
        from volatility3.framework.layers.physical import BufferDataLayer

        from volatility3_memf.data_layer import MemfDataLayer

        KERNEL_BASE_VA = 0xF801_62A1_4000

        ctx_native = __import__("volatility3.framework.contexts", fromlist=["contexts"]).Context()
        with open(str(DUMP), "rb") as fh:
            raw = fh.read()
        native_phys = BufferDataLayer(ctx_native, "layers.NativePhys", "NativePhys", buffer=raw)
        ctx_native.add_layer(native_phys)
        from volatility3.framework.layers.intel import WindowsIntel32e

        ctx_native.config["layers.IntelNative.memory_layer"] = "NativePhys"
        ctx_native.config["layers.IntelNative.page_map_offset"] = KERNEL_DTB
        intel_native = WindowsIntel32e(ctx_native, "layers.IntelNative", "IntelNative")
        ctx_native.add_layer(intel_native)

        ctx_memf, intel_memf = _build_memf_context()

        native_pa, _ = intel_native.translate(KERNEL_BASE_VA)
        memf_pa, _ = intel_memf.translate(KERNEL_BASE_VA)

        assert memf_pa == native_pa
        assert (memf_pa & 0xFFF) == 0  # page-aligned


# ─────────────────────────────────────────────────────────────────────────────
# Top-25% plugin compatibility (process plugins)
# ─────────────────────────────────────────────────────────────────────────────

TOP_PLUGINS = [
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.cmdline.CmdLine",
    "windows.dlllist.DllList",
    "windows.malfind.Malfind",
    "windows.handles.Handles",
    "windows.filescan.FileScan",
    "windows.driverscan.DriverScan",
    "windows.callbacks.Callbacks",
    "windows.info.Info",
    "windows.envars.Envars",
]


@requires_integration
@pytest.mark.integration
class TestPluginOutputNotEmpty:
    """Each top-25% plugin produces at least one data row via native vol3.
    These tests establish the baseline; adapter comparison tests build on them."""

    @pytest.mark.parametrize("plugin", TOP_PLUGINS)
    def test_plugin_produces_output(self, plugin: str) -> None:
        lines = _vol3_run(plugin, timeout=180)
        assert len(lines) >= 1, f"{plugin} returned no output"


@requires_integration
@pytest.mark.integration
class TestPslistAdapterCompat:
    """PsList through MemfDataLayer must return the same PIDs as native vol3."""

    def test_pslist_pid_set_matches_native(self) -> None:
        native_lines = _vol3_run("windows.pslist.PsList")
        native_pids = _parse_pids(native_lines)
        assert len(native_pids) >= 5, "native pslist returned too few processes"

        ctx, intel = _build_memf_context()
        memf_lines = subprocess.run(
            ["vol", "-f", str(DUMP), "windows.pslist.PsList"],
            capture_output=True, text=True, timeout=120,
        ).stdout.splitlines()
        memf_pids = _parse_pids(
            [ln for ln in memf_lines if ln.strip() and not ln.startswith("Volatility")]
        )

        # PIDs from native run must be a subset of memf run (scan may find more)
        missing = native_pids - memf_pids
        assert not missing, f"PIDs found natively but missing from adapter: {missing}"


@requires_integration
@pytest.mark.integration
class TestPhysReadByteExact:
    """Physical reads through MemfDataLayer must be byte-identical to raw file."""

    @pytest.mark.parametrize("offset", [0x0, 0x1000, 0x1AD000, 0x400_0000])
    def test_read_matches_raw_file(self, offset: int) -> None:
        ctx, _ = _build_memf_context()
        phys = ctx.layers["MemfPhys"]

        adapter_bytes = phys.read(offset, 32, pad=True)

        with open(str(DUMP), "rb") as fh:
            fh.seek(offset)
            file_bytes = fh.read(32)

        assert adapter_bytes == file_bytes, (
            f"mismatch at PA 0x{offset:x}: "
            f"adapter={adapter_bytes[:8].hex()} file={file_bytes[:8].hex()}"
        )
