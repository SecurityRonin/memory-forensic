"""Volatility 3 DataLayerInterface backed by `memf read-phys`.

MemfDataLayer plugs into the vol3 layer stack as a physical layer so that
any vol3 plugin can use memf as its backing without modification.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from volatility3.framework import interfaces


class MemfDataLayer(interfaces.layers.DataLayerInterface):
    """Physical layer that delegates all reads to `memf read-phys`.

    Satisfies vol3's DataLayerInterface contract so it can be stacked under
    WindowsIntel32e (or any other translation layer) just like BufferDataLayer.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        dump_path: str | Path,
        memf_binary: str = "memf",
        timeout: int = 30,
        **kwargs,
    ) -> None:
        super().__init__(context=context, config_path=config_path, name=name, **kwargs)
        self._dump = str(dump_path)
        self._binary = memf_binary
        self._timeout = timeout
        self._size = os.path.getsize(dump_path)

    @property
    def maximum_address(self) -> int:
        return self._size - 1

    @property
    def minimum_address(self) -> int:
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        return 0 <= offset < self._size

    def write(self, offset: int, data: bytes) -> None:
        raise NotImplementedError("MemfDataLayer is read-only")

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = subprocess.run(
            [self._binary, "read-phys", self._dump, f"0x{offset:x}", str(length)],
            capture_output=True,
            check=True,
            timeout=self._timeout,
        )
        out = result.stdout
        if pad and len(out) < length:
            out += b"\x00" * (length - len(out))
        return out
