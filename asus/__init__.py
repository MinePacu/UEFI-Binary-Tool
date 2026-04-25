"""
ASUS BIOS Section Binary analysis module

Analyzes and repacks ASUS motherboard BIOS/UEFI Section binary files.
Supports ASUS OROM-style payloads.
"""

__version__ = "1.0.0"
__author__ = "UEFI-Binary-Tool"

# Import the primary modules.
from .analyzer import AsusFileAnalyzer
from .repacker import AsusImageRepacker

__all__ = ['AsusFileAnalyzer', 'AsusImageRepacker']
