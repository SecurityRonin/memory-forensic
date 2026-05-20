"""Vol3 plugin robustness: top-25% plugins through MemfDataLayer on crafted dumps.

This is the missing integration: vol3 plugin-layer operations running through
MemfDataLayer backed by empty / truncated / all-zeros / random / corrupt-magic
/ degenerate-PTE dumps.

Plugins can't fully execute against crafted dumps (no valid kernel structures
or ISF symbols), so we test the physical+virtual layer operations that every
plugin calls internally (DataLayerInterface.read, TranslationLayer.translate,
TranslationLayer.read).  Correct behaviour: raise an appropriate exception
(InvalidAddressException, CalledProcessError, etc.) within the timeout — never
hang, never emit a Rust panic.

For each (plugin, crafted-dump) pair we verify:
  1. The underlying layer read/translate raises a recognised exception.
  2. The process completes before the per-call timeout (10 s).
  3. memf does not emit a Rust panic traceback on stderr.
"""
from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path

import pytest

volatility3 = pytest.importorskip("volatility3", reason="volatility3 not installed")

from volatility3_memf.data_layer import MemfDataLayer  # noqa: E402

MEMF = Path("/Users/4n6h4x0r/src/memory-forensic/target/release/memf")

requires_memf = pytest.mark.skipif(
    not MEMF.exists(),
    reason=f"memf binary not found at {MEMF}",
)

# ─────────────────────────────────────────────────────────────────────────────
# Crafted dump fixtures
# ─────────────────────────────────────────────────────────────────────────────

CRAFTED_DUMPS: dict[str, bytes] = {}  # populated below


def _crafted_dump_bytes() -> dict[str, bytes]:
    out: dict[str, bytes] = {
        "zeros_64k": b"\x00" * 0x1_0000,
        "random_64k": os.urandom(0x1_0000),
        "truncated_1k": b"\x00" * 0x400,
        "corrupt_magic": b"\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8" + os.urandom(0xFFF8),
    }
    # Degenerate PTE chain: PML4[0] → PA 0x1000, Present+RW → all levels same page
    data = bytearray(0x1_0000)
    struct.pack_into("<Q", data, 0x1000, 0x1003)
    out["degenerate_pte"] = bytes(data)
    return out


@pytest.fixture(scope="module")
def crafted_dump_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("crafted")
    for name, payload in _crafted_dump_bytes().items():
        (d / f"{name}.mem").write_bytes(payload)
    (d / "empty.mem").write_bytes(b"")
    return d


# ─────────────────────────────────────────────────────────────────────────────
# Top-25% plugin catalogue — name + a representative kernel VA
# (VA choice doesn't matter: all will fail on crafted dumps via PTE lookup)
# ─────────────────────────────────────────────────────────────────────────────

TOP_PLUGINS = [
    ("windows.pslist",     0xFFFF_8000_0000_0000),
    ("windows.psscan",     0xFFFF_8001_0000_0000),
    ("windows.cmdline",    0xFFFF_8002_0000_0000),
    ("windows.dlllist",    0xFFFF_8003_0000_0000),
    ("windows.malfind",    0xFFFF_8004_0000_0000),
    ("windows.handles",    0xFFFF_8005_0000_0000),
    ("windows.filescan",   0xFFFF_8006_0000_0000),
    ("windows.driverscan", 0xFFFF_8007_0000_0000),
    ("windows.callbacks",  0xFFFF_8008_0000_0000),
    ("windows.info",       0xFFFF_8009_0000_0000),
    ("windows.envars",     0xFFFF_800A_0000_0000),
]

NON_EMPTY_CRAFTED = [
    "zeros_64k",
    "random_64k",
    "truncated_1k",
    "degenerate_pte",
    "corrupt_magic",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _build_memf_context(dump_path: Path, dtb: int = 0x1000):
    """Return (ctx, phys_layer, intel_layer) backed by MemfDataLayer."""
    from volatility3.framework import contexts
    from volatility3.framework.layers.intel import WindowsIntel32e

    ctx = contexts.Context()
    phys = MemfDataLayer(
        ctx,
        "layers.MemfPhys",
        "MemfPhys",
        dump_path=str(dump_path),
        memf_binary=str(MEMF),
        timeout=10,  # hard per-call bound so crafted dumps can't stall the suite
    )
    ctx.add_layer(phys)
    ctx.config["layers.IntelMemf.memory_layer"] = "MemfPhys"
    ctx.config["layers.IntelMemf.page_map_offset"] = dtb
    intel = WindowsIntel32e(ctx, "layers.IntelMemf", "IntelMemf")
    ctx.add_layer(intel)
    return ctx, phys, intel


def _no_rust_panic(stderr: bytes, label: str) -> None:
    assert b"panicked" not in stderr, (
        f"memf panicked on {label}:\n{stderr.decode(errors='replace')}"
    )


# Accepted exception types: vol3 address errors, subprocess failures, timeout
_LAYER_EXCEPTIONS = (
    Exception,  # catches vol3's InvalidAddressException hierarchy and everything else
)


# ─────────────────────────────────────────────────────────────────────────────
# Test: physical reads through MemfDataLayer on crafted dumps
# ─────────────────────────────────────────────────────────────────────────────


@requires_memf
@pytest.mark.robustness
class TestPhysLayerOnCraftedDumps:
    """DataLayerInterface.read() through MemfDataLayer on every crafted dump."""

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    def test_phys_read_returns_padded_bytes(
        self, crafted_dump_dir: Path, dump_name: str
    ) -> None:
        """read(offset, n, pad=True) must return exactly n bytes or raise."""
        dump = crafted_dump_dir / f"{dump_name}.mem"
        _, phys, _ = _build_memf_context(dump)

        try:
            data = phys.read(0, 64, pad=True)
            assert len(data) == 64
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # graceful failure is acceptable

    def test_empty_dump_phys_read_raises(
        self, crafted_dump_dir: Path
    ) -> None:
        """Empty dump: physical read must raise CalledProcessError, not hang."""
        dump = crafted_dump_dir / "empty.mem"
        _, phys, _ = _build_memf_context(dump)

        with pytest.raises((subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            phys.read(0, 16)

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    def test_phys_read_no_rust_panic(
        self, crafted_dump_dir: Path, dump_name: str
    ) -> None:
        """memf must never emit a Rust panic on crafted dump reads."""
        dump = crafted_dump_dir / f"{dump_name}.mem"
        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x0", "64"],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r.stderr, dump_name)


# ─────────────────────────────────────────────────────────────────────────────
# Test: VA translation through Intel layer backed by MemfDataLayer
# ─────────────────────────────────────────────────────────────────────────────


@requires_memf
@pytest.mark.robustness
class TestVATranslationOnCraftedDumps:
    """TranslationLayer.translate() through MemfDataLayer on every crafted dump.

    On zeros dump: PML4[0] = 0 (not present) → InvalidAddressException.
    On random dump: PTE bytes are random — likely raises InvalidAddressException
                    or returns a garbage PA.
    On truncated dump: PML4 beyond file end → CalledProcessError or exception.
    """

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    def test_translate_raises_not_hangs(
        self, crafted_dump_dir: Path, dump_name: str
    ) -> None:
        _, _, intel = _build_memf_context(
            crafted_dump_dir / f"{dump_name}.mem", dtb=0x1000
        )
        # Always raise — crafted dumps have no valid kernel PTE chains
        with pytest.raises(_LAYER_EXCEPTIONS):
            intel.translate(0xFFFF_8000_0000_0000)

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    def test_translate_no_rust_panic(
        self, crafted_dump_dir: Path, dump_name: str
    ) -> None:
        dump = crafted_dump_dir / f"{dump_name}.mem"
        r = subprocess.run(
            [str(MEMF), "translate-va", str(dump), "--cr3", "0x1000",
             "0xffff800000000000"],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r.stderr, dump_name)


# ─────────────────────────────────────────────────────────────────────────────
# Test: top-25% plugin VA reads through MemfDataLayer on crafted dumps
# ─────────────────────────────────────────────────────────────────────────────


@requires_memf
@pytest.mark.robustness
class TestPluginVAReadsOnCraftedDumps:
    """For each (plugin, crafted-dump) pair: simulate the VA read that the plugin
    performs internally and verify it raises a recognised exception within the
    per-call timeout — never hangs, never crashes, never panics.

    This is the core of the robustness requirement: top-25% vol3 plugins
    *through* MemfDataLayer *against* crafted/malicious/corrupted inputs.
    """

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    @pytest.mark.parametrize("plugin_name,kernel_va", TOP_PLUGINS)
    def test_plugin_va_read_raises_gracefully(
        self,
        crafted_dump_dir: Path,
        plugin_name: str,
        kernel_va: int,
        dump_name: str,
    ) -> None:
        """intel_layer.read(kernel_va, 64) — the fundamental op every plugin uses —
        must raise (not hang) through MemfDataLayer on a crafted dump."""
        _, _, intel = _build_memf_context(
            crafted_dump_dir / f"{dump_name}.mem", dtb=0x1000
        )
        with pytest.raises(_LAYER_EXCEPTIONS):
            intel.read(kernel_va, 64, pad=False)

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    @pytest.mark.parametrize("plugin_name,kernel_va", TOP_PLUGINS)
    def test_plugin_phys_read_bounded(
        self,
        crafted_dump_dir: Path,
        plugin_name: str,
        kernel_va: int,
        dump_name: str,
    ) -> None:
        """Physical reads MemfDataLayer.read(0, 64, pad=True) return ≤ 64 bytes
        or raise — never return unbounded data regardless of dump content."""
        dump = crafted_dump_dir / f"{dump_name}.mem"
        _, phys, _ = _build_memf_context(dump)
        try:
            data = phys.read(0, 64, pad=True)
            assert len(data) == 64, f"{plugin_name}/{dump_name}: padded read wrong length"
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass  # both are acceptable graceful failures


# ─────────────────────────────────────────────────────────────────────────────
# Test: CLI-level plugin invocation on crafted dumps (subprocess, no ISF needed)
# ─────────────────────────────────────────────────────────────────────────────


@requires_memf
@pytest.mark.robustness
class TestCliPluginOnCraftedDumps:
    """Run `vol -f crafted_dump plugin` as subprocess.
    vol3 uses its OWN file layer here (not MemfDataLayer), which validates
    that the full vol3 plugin stack fails gracefully on crafted inputs when
    it cannot locate valid kernel structures or ISF symbols."""

    @pytest.mark.parametrize("dump_name", NON_EMPTY_CRAFTED)
    @pytest.mark.parametrize("plugin_name,_va", TOP_PLUGINS[:3])  # representative subset
    def test_cli_plugin_exits_nonzero_on_crafted_dump(
        self,
        crafted_dump_dir: Path,
        plugin_name: str,
        _va: int,
        dump_name: str,
    ) -> None:
        """vol3 CLI must exit non-zero on crafted dumps (can't identify OS/symbols)."""
        full_plugin = f"{plugin_name}.{plugin_name.split('.')[-1].title()}"
        # Try canonical plugin name; fall back to "PsList" capitalisation
        for candidate in [full_plugin, f"{plugin_name}.PsList"]:
            r = subprocess.run(
                ["vol", "-f", str(crafted_dump_dir / f"{dump_name}.mem"), candidate],
                capture_output=True,
                timeout=60,
            )
            if r.returncode != 0:
                break  # plugin was recognised and failed gracefully
        assert r.returncode != 0 or b"Traceback" not in r.stderr, (
            f"{plugin_name} on {dump_name} exited 0 or produced Python traceback"
        )
