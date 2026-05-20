"""Tests for MemfDataLayer — vol3 DataLayerInterface backed by memf.

All tests are offline (subprocess.run is mocked) and require vol3 to
be installed in the environment.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

volatility3 = pytest.importorskip("volatility3", reason="volatility3 not installed")

from volatility3_memf.data_layer import MemfDataLayer  # noqa: E402


def _ctx():
    from volatility3.framework import contexts

    return contexts.Context()


def _layer(
    size: int = 4096,
    binary: str = "memf",
    timeout: int = 30,
) -> MemfDataLayer:
    ctx = _ctx()
    with patch("os.path.getsize", return_value=size):
        return MemfDataLayer(
            ctx,
            "layers.MemfPhys",
            "MemfPhys",
            dump_path="/fake/dump.mem",
            memf_binary=binary,
            timeout=timeout,
        )


class TestImport:
    def test_importable_from_package(self) -> None:
        from volatility3_memf import MemfDataLayer as _M  # noqa: F401

    def test_is_data_layer_interface_subclass(self) -> None:
        from volatility3.framework.interfaces import layers

        assert issubclass(MemfDataLayer, layers.DataLayerInterface)


class TestAddressProperties:
    def test_minimum_address_is_zero(self) -> None:
        assert _layer(size=1024).minimum_address == 0

    def test_maximum_address_is_size_minus_one(self) -> None:
        assert _layer(size=4096).maximum_address == 4095

    def test_maximum_address_one_byte_file(self) -> None:
        assert _layer(size=1).maximum_address == 0


class TestIsValid:
    def test_offset_zero_valid(self) -> None:
        assert _layer(size=512).is_valid(0, 1) is True

    def test_offset_at_last_byte_valid(self) -> None:
        assert _layer(size=512).is_valid(511, 1) is True

    def test_offset_equal_to_size_invalid(self) -> None:
        assert _layer(size=512).is_valid(512, 1) is False

    def test_negative_offset_invalid(self) -> None:
        assert _layer(size=512).is_valid(-1, 1) is False


class TestWrite:
    def test_write_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError):
            _layer().write(0, b"\x00")


class TestRead:
    def test_read_calls_read_phys_subcommand(self) -> None:
        layer = _layer(binary="memf")
        mock_result = MagicMock()
        mock_result.stdout = b"\xDE\xAD\xBE\xEF"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            data = layer.read(0x1000, 4)

        args = mock_run.call_args[0][0]
        assert args[0] == "memf"
        assert "read-phys" in args
        assert "/fake/dump.mem" in args
        assert "0x1000" in args
        assert "4" in args
        assert data == b"\xDE\xAD\xBE\xEF"

    def test_read_pads_short_result(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xAA"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0, 4, pad=True)

        assert data == b"\xAA\x00\x00\x00"

    def test_read_no_pad_returns_exact_bytes(self) -> None:
        layer = _layer()
        mock_result = MagicMock()
        mock_result.stdout = b"\xAA"

        with patch("subprocess.run", return_value=mock_result):
            data = layer.read(0, 4, pad=False)

        assert data == b"\xAA"

    def test_read_propagates_called_process_error(self) -> None:
        layer = _layer()
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "memf")):
            with pytest.raises(subprocess.CalledProcessError):
                layer.read(0x1000, 4)

    def test_read_uses_constructor_timeout(self) -> None:
        layer = _layer(timeout=7)
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0, 1)

        kwargs = mock_run.call_args[1]
        assert kwargs.get("timeout") == 7

    def test_read_propagates_timeout_expired(self) -> None:
        layer = _layer()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("memf", 30)):
            with pytest.raises(subprocess.TimeoutExpired):
                layer.read(0x1000, 4)

    def test_custom_binary_path_used(self) -> None:
        layer = _layer(binary="/opt/memf/bin/memf")
        mock_result = MagicMock()
        mock_result.stdout = b"\x00"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            layer.read(0, 1)

        args = mock_run.call_args[0][0]
        assert args[0] == "/opt/memf/bin/memf"
