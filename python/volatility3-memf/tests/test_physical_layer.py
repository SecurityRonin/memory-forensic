"""Tests for MemfPhysicalLayer — fully offline via subprocess.run mocking."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from volatility3_memf.physical_layer import MemfPhysicalLayer


def _layer(dump: str = "/dump.lime", binary: str = "memf") -> MemfPhysicalLayer:
    return MemfPhysicalLayer(dump, memf_binary=binary)


class TestRead:
    def test_read_calls_read_phys_subcommand(self) -> None:
        layer = _layer("/path/to/dump.lime")
        mock_result = MagicMock()
        mock_result.stdout = b"\xDE\xAD\xBE\xEF"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            data = layer.read(0x1000, 4)

        mock_run.assert_called_once_with(
            ["memf", "read-phys", "/path/to/dump.lime", "0x1000", "4"],
            capture_output=True,
            check=True,
        )
        assert data == b"\xDE\xAD\xBE\xEF"

    def test_read_pads_short_result(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xAA\xBB"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0x1000, 4, pad=True)

        assert data == b"\xAA\xBB\x00\x00"

    def test_read_no_pad_returns_exact_bytes(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xAA\xBB"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0x1000, 4, pad=False)

        assert data == b"\xAA\xBB"

    def test_read_uses_custom_binary(self) -> None:
        layer = _layer(binary="/usr/local/bin/memf")
        mock_result = MagicMock()
        mock_result.stdout = b"\xFF"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0x2000, 1)

        args = mock_run.call_args[0][0]
        assert args[0] == "/usr/local/bin/memf"

    def test_read_formats_addr_as_hex(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0xDEAD_BEEF, 1)

        args = mock_run.call_args[0][0]
        assert "0xdeadbeef" in args

    def test_read_propagates_subprocess_error(self) -> None:
        layer = _layer()

        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "memf")):
            with pytest.raises(subprocess.CalledProcessError):
                layer.read(0x1000, 8)

    def test_pathlib_path_accepted(self) -> None:
        layer = MemfPhysicalLayer(Path("/some/dump.lime"))
        mock_result = MagicMock()
        mock_result.stdout = b"\x42"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0, 1)

        args = mock_run.call_args[0][0]
        assert "/some/dump.lime" in args
