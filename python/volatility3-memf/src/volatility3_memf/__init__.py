"""Volatility 3 memory layer adapter backed by the memf CLI."""
from .physical_layer import MemfPhysicalLayer
from .virtual_layer import MemfVirtualLayer

__all__ = ["MemfPhysicalLayer", "MemfVirtualLayer"]
