"""MSI BIOS Section Binary package.

Analyzes and repacks MSI motherboard BIOS/UEFI Section binary files.
Supports MSI Packer format with the $MsI$ signature.
"""

__version__ = "1.0.0"
__author__ = "UEFI-Binary-Tool"

from .analyzer.msi_analyzer import MSIFileAnalyzer
from .repacker.msi_repacker import MSIImageRepacker

__all__ = ['MSIFileAnalyzer', 'MSIImageRepacker']
