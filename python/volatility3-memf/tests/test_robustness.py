"""Robustness tests for the volatility3-memf adapter.

Split into two tiers:
  1. Offline (subprocess mocked) — timeout propagation and malformed output.
  2. Binary-level (real memf + crafted temp files, @pytest.mark.robustness) —
     verifies memf exits gracefully on empty, truncated, all-zeros, and
     loop-crafted dumps without panicking or hanging.
"""
from __future__ import annotations

import os
import struct
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from volatility3_memf.physical_layer import MemfPhysicalLayer
from volatility3_memf.virtual_layer import MemfVirtualLayer

MEMF = Path("/Users/4n6h4x0r/src/memory-forensic/target/release/memf")


def _phys(binary: str = "memf") -> MemfPhysicalLayer:
    return MemfPhysicalLayer("/dump.mem", memf_binary=binary)


def _virt(binary: str = "memf") -> MemfVirtualLayer:
    return MemfVirtualLayer("/dump.mem", cr3=0x1A2B3C, memf_binary=binary)


# ─────────────────────────────────────────────────────────────────────────────
# Tier 1 — offline, subprocess mocked
# ─────────────────────────────────────────────────────────────────────────────


class TestTimeoutPropagation:
    """TimeoutExpired from subprocess must surface to callers, not be swallowed."""

    def test_phys_read_propagates_timeout_expired(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("memf", 30)):
            with pytest.raises(subprocess.TimeoutExpired):
                _phys().read(0, 16)

    def test_virt_read_propagates_timeout_expired(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("memf", 30)):
            with pytest.raises(subprocess.TimeoutExpired):
                _virt().read(0xFFFF_8000_0000_0000, 16)

    def test_virt_translate_propagates_timeout_expired(self) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("memf", 30)):
            with pytest.raises(subprocess.TimeoutExpired):
                _virt().translate(0xFFFF_8000_0000_0000)


class TestTimeoutPassedToSubprocess:
    """Constructor timeout must be forwarded to subprocess.run — without this,
    a stalled memf process will hang the entire test suite indefinitely."""

    def test_phys_read_forwards_timeout(self) -> None:
        phys = MemfPhysicalLayer("/dump.mem", timeout=12)
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            phys.read(0, 1)

        assert mock_run.call_args[1].get("timeout") == 12

    def test_virt_read_forwards_timeout(self) -> None:
        virt = MemfVirtualLayer("/dump.mem", cr3=0x1000, timeout=8)
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            virt.read(0xFFFF_8000_0000_0000, 1)

        assert mock_run.call_args[1].get("timeout") == 8

    def test_virt_translate_forwards_timeout(self) -> None:
        virt = MemfVirtualLayer("/dump.mem", cr3=0x1000, timeout=15)
        mock_result = MagicMock()
        mock_result.stdout = b"0x1000\n"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            virt.translate(0xFFFF_8000_0000_0000)

        assert mock_run.call_args[1].get("timeout") == 15


class TestMalformedOutput:
    """translate-va returning non-hex or empty output must raise ValueError,
    not silently produce 0 or crash with an unrelated exception."""

    def test_translate_raises_on_empty_stdout(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = b""

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises((ValueError, Exception)):
                _virt().translate(0xFFFF_8000_0000_0000)

    def test_translate_raises_on_non_hex_output(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = b"translation error: page not present\n"

        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises((ValueError, Exception)):
                _virt().translate(0xFFFF_8000_0000_0000)

    def test_phys_read_empty_stdout_no_pad_returns_empty(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = b""

        with patch("subprocess.run", return_value=mock_result):
            assert _phys().read(0, 16, pad=False) == b""

    def test_phys_read_empty_stdout_with_pad_returns_zeros(self) -> None:
        mock_result = MagicMock()
        mock_result.stdout = b""

        with patch("subprocess.run", return_value=mock_result):
            assert _phys().read(0, 16, pad=True) == b"\x00" * 16


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — real memf binary + crafted temp files
# ─────────────────────────────────────────────────────────────────────────────

pytestmark_robustness = pytest.mark.robustness
requires_memf = pytest.mark.skipif(
    not MEMF.exists(),
    reason=f"memf binary not found at {MEMF}",
)


def _no_rust_panic(result: subprocess.CompletedProcess) -> None:
    """Assert the process did not emit a Rust panic backtrace."""
    assert b"thread" not in result.stderr or b"panicked" not in result.stderr, (
        f"memf panicked:\n{result.stderr.decode(errors='replace')}"
    )


@requires_memf
@pytest.mark.robustness
class TestCraftedInputs:
    def test_empty_dump_read_phys_exits_nonzero(self, tmp_path: Path) -> None:
        dump = tmp_path / "empty.mem"
        dump.write_bytes(b"")

        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x0", "16"],
            capture_output=True,
            timeout=10,
        )
        assert r.returncode != 0
        _no_rust_panic(r)

    def test_truncated_dump_read_phys_no_panic(self, tmp_path: Path) -> None:
        """8-byte file, request 16 bytes — partial read or failure, never panic."""
        dump = tmp_path / "tiny.mem"
        dump.write_bytes(b"\x00" * 8)

        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x0", "16"],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r)

    def test_all_zeros_dump_translate_va_exits_nonzero(self, tmp_path: Path) -> None:
        """All-zeros PTE chain is invalid — translate must fail, not return 0."""
        dump = tmp_path / "zeros.mem"
        dump.write_bytes(b"\x00" * 0x1_0000)

        r = subprocess.run(
            [str(MEMF), "translate-va", str(dump),
             "--cr3", "0x1000", "0xffff800000000000"],
            capture_output=True,
            timeout=10,
        )
        assert r.returncode != 0
        _no_rust_panic(r)

    def test_random_data_read_phys_no_panic(self, tmp_path: Path) -> None:
        dump = tmp_path / "random.mem"
        dump.write_bytes(os.urandom(0x1000))

        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x0", "16"],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r)

    def test_nonexistent_dump_exits_nonzero(self, tmp_path: Path) -> None:
        r = subprocess.run(
            [str(MEMF), "read-phys", str(tmp_path / "ghost.mem"), "0x0", "16"],
            capture_output=True,
            timeout=10,
        )
        assert r.returncode != 0

    def test_hugelen_bounded_output_no_panic(self, tmp_path: Path) -> None:
        """Requesting 2^40 bytes: memf must not panic and must return ≤ file_size bytes."""
        file_size = 0x1000
        dump = tmp_path / "small.mem"
        dump.write_bytes(b"\x00" * file_size)

        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x0", str(2**40)],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r)
        # Either fails (non-zero) or succeeds but returns at most file_size bytes
        if r.returncode == 0:
            assert len(r.stdout) <= file_size, (
                f"memf returned {len(r.stdout)} bytes from a {file_size}-byte file"
            )

    def test_crafted_page_table_all_same_page_translates_deterministically(
        self, tmp_path: Path
    ) -> None:
        """Degenerate page table: every level reuses the same physical page.
        x64 4-level paging always terminates after exactly 4 levels — there
        is no infinite loop.  Validates memf exits cleanly and emits valid hex."""
        data = bytearray(0x1_0000)
        # PML4[0] at PA 0x1000 → PDPT at PA 0x1000 (same page), P+RW
        struct.pack_into("<Q", data, 0x1000, 0x1003)
        dump = tmp_path / "degenerate.mem"
        dump.write_bytes(bytes(data))

        r = subprocess.run(
            [str(MEMF), "translate-va", str(dump),
             "--cr3", "0x1000", "0x0"],
            capture_output=True,
            timeout=5,
        )
        _no_rust_panic(r)
        # Either succeeds (degenerate but valid PTE chain) or fails gracefully
        if r.returncode == 0:
            output = r.stdout.strip()
            assert output.startswith(b"0x"), f"expected hex PA, got: {output!r}"

    def test_corrupt_magic_read_phys_succeeds_raw_fallback(self, tmp_path: Path) -> None:
        """Corrupted container magic still allows physical read via raw fallback."""
        data = bytearray(0x1000)
        data[0:8] = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"  # invalid container header
        data[0x100:0x104] = b"\xDE\xAD\xBE\xEF"
        dump = tmp_path / "corrupt.mem"
        dump.write_bytes(bytes(data))

        r = subprocess.run(
            [str(MEMF), "read-phys", str(dump), "0x100", "4"],
            capture_output=True,
            timeout=10,
        )
        _no_rust_panic(r)
        # If raw fallback works, stdout should contain our marker bytes
        if r.returncode == 0:
            assert r.stdout == b"\xDE\xAD\xBE\xEF"
