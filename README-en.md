> [!IMPORTANT]
> The developer of this program is not responsible for any consequences, losses, or damages that result from using this program. Use it carefully.

# BIOS Section Binary Analysis/Embedded Image Repacking Integrated Tool

A Python-based tool for analyzing and repacking Section binary files from motherboard BIOS/UEFI.

## 📋 Overview

This tool provides a solution to analyze the Section within motherboard BIOS/UEFI to understand the internal structure and repackage embedded images.

> [!Note]
> Usage instructions will be added to the Wiki in the future.

**Supported Manufacturers:**
- **ASUS**: Supports ASUS Packer format
- **MSI**: Supports MSI Packer format (`$MsI$` signature)

> [!CAUTION]
> For `MSI`, only `CLICK BIOS X` is supported.<br>For `CLICK BIOS 5`, support for icon changing functionality is under consideration.

## 🚀 Key Features

- **Section Binary File Analysis**: Magic byte pattern detection and structure analysis
- **Format validation before file loading**: Checks ASUS/MSI Packer signatures and basic entry structure
- **Image Repacking**: Packaging modified images in each manufacturer's Packer format

## 🛠️ Installation and Requirements

### System Requirements
- Python 3.6 or higher
- Windows/Linux/macOS

### Dependencies
- Uses only standard libraries (no additional installation required)
  - `os`, `sys`, `struct`, `re`, `binascii`
  - `collections`, `datetime`

## 🎯 Usage

### 1. Running Batch Files on Windows

**ASUS Tools:**
```bash
batch\asus_tools.bat
```

**MSI Tools:**
```bash
batch\msi_tools.bat
```

Batch files also choose Korean or English from the Windows language setting.
- Korean Windows: Korean batch menus
- Other languages: English batch menus

You can force the batch language with the same environment variable.

```bat
set UEFI_BINARY_TOOL_LANG=ko
batch\asus_tools.bat

set UEFI_BINARY_TOOL_LANG=en
batch\msi_tools.bat
```

### 2. Direct Python Execution

#### ASUS Interactive Mode
```bash
python asus_main.py
```

#### MSI Interactive Mode
```bash
python msi_main.py
```

#### Command Line Mode

**ASUS:**
```bash
# File analysis
python asus_main.py analyze [file_path]

# Image repacking
python asus_main.py repack [file_path]
```

**MSI:**
```bash
# File analysis
python msi_main.py analyze [file_path]

# Image repacking (requires extracted folder)
python msi_main.py repack [directory_path]
```

#### Drag and Drop
**ASUS**: You can drag BIOS files directly to `batch\asus_tools.bat` to execute.

**MSI**: Dragging MSI BIOS files (.bin) to `batch\msi_tools.bat` will automatically process as follows:
1. 🔍 **File Analysis**: MSI Packer structure analysis
2. 📁 **Extract Folder Check**: Search for existing `msi_extracted/MSI_pack_folder/`
3. 📦 **Structure-Preserving Repacking**: Regenerate with identical structure as original
4. 📋 **Report Generation**: Document analysis and repacking results
5. ⚠️ **Note**: Image extraction functionality requires separate tools

## 🔧 Supported Formats

### Input Formats
- Section packages (.bin)
- UEFI Firmware Volume
- PE/DOS executable files
- Other binary images

### Output Formats
- Repackaged Section Binary files
- Analysis reports (text)

## 📝 Usage Examples

### 1. BIOS File Analysis
```
[ANALYZE] ASUS BIOS File Analysis Mode
==================================================
File to analyze: bios_sector_ABCDEFGH-IJKL-MNOP-QRST-UVWXYZABCDEF.bin
File size: 16,777,216 bytes (16.00 MB)

=== Magic Byte Analysis ===
Offset 0x00000000: MZ (PE/DOS Executable)
Offset 0x00000800: _FVH (UEFI Firmware Volume)
```

### 2. Image Repacking
```
[REPACK] ASUS Image Repacking Mode
==================================================
Original file: original_bios.bin
Extract directory: asus_extracted/
Output file: original_bios_asus_repacked.bin

[SUCCESS] Repacking completed.
```

## ⚠️ Precautions

1. **Backup Required**: Always backup the original BIOS file
2. **Compatibility**: This is a tool specifically for ASUS motherboards. We are working to support other manufacturer BIOS in the future.
3. **Verification**: Thoroughly verify the repacked file before flashing.

## 🐛 Troubleshooting

### Common Errors
- **Module import error**: Check Python path settings
- **File access error**: Check file permissions and paths
- **Invalid file error**: Check that the selected file matches the target vendor's Packer format

### Debugging
The program outputs detailed error messages and progress information. Check the output messages when issues occur.

## 📁 Project Structure

```
UEFI-Binary-Tool/
├── asus_main.py           # ASUS main program (entry point)
├── msi_main.py            # MSI main program (entry point)
├── batch/                 # Windows batch execution scripts
│   ├── _lang.bat          # Korean/English language resources for batch files
│   ├── asus_tools.bat     # ASUS tool batch launcher
│   ├── msi_tools.bat      # MSI tool batch launcher
│   └── msi_tools_new.bat  # MSI compatibility launcher
├── asus/                  # ASUS related modules
│   ├── analyzer/
│   │   └── asus_analyzer.py    # ASUS BIOS file analyzer
│   └── repacker/
│       └── asus_repacker.py    # ASUS image repacker
├── msi/                   # MSI related modules
│   ├── analyzer/
│   │   └── msi_analyzer.py     # MSI BIOS file analyzer
│   └── repacker/
│       └── msi_repacker.py     # MSI image repacker
└── common/                # Common utilities
    ├── binary_validation.py # ASUS/MSI binary format validation
    └── file_utils.py        # File processing utilities
```

## 🤝 Contributing

Please register bug reports or feature suggestions as issues.

---

**⚡ Quick Start**: 
- **ASUS**: Run `batch\asus_tools.bat` or drag BIOS files to `batch\asus_tools.bat`!
- **MSI**: Run `batch\msi_tools.bat` or drag BIOS files to `batch\msi_tools.bat`!
