"""Shared pytest fixtures for the volatility3-memf test suite."""
from __future__ import annotations

import os
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from _helpers import (
    DUMP_BANKING,
    DUMP_BANKING_ZIP,
    MEMF,
    build_memf_context,
    no_rust_panic,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def banking_dump() -> Path | None:
    """Return path to banking-malware.vmem, extracting from password-protected
    CyberDefenders zip if needed (password: 'cyberdefenders.org')."""
    if DUMP_BANKING.exists():
        return DUMP_BANKING

    if not DUMP_BANKING_ZIP.exists():
        return None

    DUMP_BANKING.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["unzip", "-P", "cyberdefenders.org", "-o",
         str(DUMP_BANKING_ZIP), "-d", str(DUMP_BANKING.parent)],
        capture_output=True,
        timeout=600,
    )
    if r.returncode != 0:
        return None

    candidate = DUMP_BANKING.parent / "temp_extract_dir" / "banking-malware.vmem"
    if candidate.exists():
        candidate.rename(DUMP_BANKING)

    return DUMP_BANKING if DUMP_BANKING.exists() else None


@pytest.fixture(scope="module")
def crafted_dumps(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Suite of crafted / corrupted dumps for robustness testing."""
    d = tmp_path_factory.mktemp("crafted")

    (d / "empty.mem").write_bytes(b"")
    (d / "zeros_64k.mem").write_bytes(b"\x00" * 0x1_0000)
    (d / "random_64k.mem").write_bytes(os.urandom(0x1_0000))
    (d / "truncated_1k.mem").write_bytes(b"\x00" * 0x400)

    data = bytearray(0x1_0000)
    struct.pack_into("<Q", data, 0x1000, 0x1003)
    (d / "degenerate_pte.mem").write_bytes(bytes(data))

    body = bytearray(os.urandom(0x1_0000))
    body[0:8] = b"\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8"
    (d / "corrupt_magic.mem").write_bytes(bytes(body))

    return {p.stem: p for p in d.iterdir()}
