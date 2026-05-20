"""Volatility 3 memory layer adapter backed by the memf CLI."""
from .physical_layer import MemfPhysicalLayer
from .virtual_layer import MemfVirtualLayer

try:
    from .data_layer import MemfDataLayer

    __all__ = ["MemfPhysicalLayer", "MemfVirtualLayer", "MemfDataLayer"]
except ImportError:
    # volatility3 not installed — MemfDataLayer unavailable but rest of package works
    __all__ = ["MemfPhysicalLayer", "MemfVirtualLayer"]
