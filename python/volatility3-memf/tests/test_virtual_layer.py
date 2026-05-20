"""Tests for MemfVirtualLayer — fully offline via subprocess.run mocking."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from volatility3_memf.virtual_layer import MemfVirtualLayer


def _layer(
    dump: str = "/dump.lime",
    cr3: int = 0x1A2B3C,
    binary: str = "memf",
) -> MemfVirtualLayer:
    return MemfVirtualLayer(dump, cr3=cr3, memf_binary=binary)


class TestTranslate:
    def test_translate_calls_translate_va_subcommand(self) -> None:
        layer = _layer(cr3=0x1A2B3C)
        mock_result = MagicMock()
        mock_result.stdout = b"0xdeadbeef\n"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            pa, layer_name = layer.translate(0xFFFF_8000_0040_1000)

        mock_run.assert_called_once_with(
            [
                "memf", "translate-va", "/dump.lime",
                "--cr3", "0x1a2b3c",
                "0xffff800000401000",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )
        assert pa == 0xDEAD_BEEF
        assert layer_name == "MemfPhysical"

    def test_translate_strips_whitespace_from_output(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"  0xcafe1234  \n"

        with patch("subprocess.run", return_value=mock_result):
            pa, _ = layer.translate(0x1000)

        assert pa == 0xCAFE_1234

    def test_translate_propagates_subprocess_error(self) -> None:
        layer = _layer()

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "memf")):
            with pytest.raises(subprocess.CalledProcessError):
                layer.translate(0xFFFF_8000_0000_0000)


class TestReadVirt:
    def test_read_calls_read_virt_subcommand(self) -> None:
        layer = _layer(cr3=0xDEAD_BEEF)
        mock_result = MagicMock()
        mock_result.stdout = b"\x90\x90\x90\x90"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            data = layer.read(0xFFFF_8000_0040_1000, 4)

        mock_run.assert_called_once_with(
            [
                "memf", "read-virt", "/dump.lime",
                "--cr3", "0xdeadbeef",
                "0xffff800000401000", "4",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )
        assert data == b"\x90\x90\x90\x90"

    def test_read_pads_short_result(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xCC"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0x1000, 4, pad=True)

        assert data == b"\xCC\x00\x00\x00"

    def test_read_no_pad_returns_exact_bytes(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xCC"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0x1000, 4, pad=False)

        assert data == b"\xCC"

    def test_read_propagates_subprocess_error(self) -> None:
        layer = _layer()

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "memf")):
            with pytest.raises(subprocess.CalledProcessError):
                layer.read(0xFFFF_8000_0000_0000, 8)

    def test_pathlib_path_accepted(self) -> None:
        layer = MemfVirtualLayer(Path("/some/dump.lime"), cr3=0x1000)
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0, 1)

        args = mock_run.call_args[0][0]
        assert "/some/dump.lime" in args
