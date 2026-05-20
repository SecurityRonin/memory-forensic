"""Volatility 3 virtual memory layer backed by `memf translate-va` and `memf read-virt`."""
from __future__ import annotations

import subprocess
from pathlib import Path


class MemfVirtualLayer:
    """TranslationLayerInterface implementation backed by memf subprocesses."""

    name: str = "MemfVirtual"

    def __init__(
        self,
        dump_path: str | Path,
        cr3: int,
        memf_binary: str = "memf",
        timeout: int = 30,
    ) -> None:
        self._dump = str(dump_path)
        self._cr3 = cr3
        self._binary = memf_binary
        self._timeout = timeout

    def translate(self, offset: int) -> tuple[int, str]:
        result = subprocess.run(
            [
                self._binary, "translate-va", self._dump,
                "--cr3", f"0x{self._cr3:x}",
                f"0x{offset:x}",
            ],
            capture_output=True,
            check=True,
            timeout=self._timeout,
        )
        pa = int(result.stdout.strip(), 16)
        return pa, "MemfPhysical"

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        result = subprocess.run(
            [
                self._binary, "read-virt", self._dump,
                "--cr3", f"0x{self._cr3:x}",
                f"0x{offset:x}",
                str(length),
            ],
            capture_output=True,
            check=True,
            timeout=self._timeout,
        )
        data = result.stdout
        if pad and len(data) < length:
            data = data + b"\x00" * (length - len(data))
        return data
