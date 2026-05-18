"""Volatility 3 physical memory layer backed by `memf read-phys`."""
from __future__ import annotations

import subprocess
from pathlib import Path


class MemfPhysicalLayer:
    """DataLayerInterface implementation that delegates reads to `memf read-phys`."""

    name: str = "MemfPhysical"

    def __init__(self, dump_path: str | Path, memf_binary: str = "memf") -> None:
        self._dump = str(dump_path)
        self._binary = memf_binary

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = subprocess.run(
            [self._binary, "read-phys", self._dump, f"0x{offset:x}", str(length)],
            capture_output=True,
            check=True,
        )
        data = result.stdout
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data
