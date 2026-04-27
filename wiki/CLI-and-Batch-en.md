# CLI and Windows Batch Files

## GUI Launch Commands

```bash
python3 gui_main.py
```

Or:

```bash
python3 -m uefi_binary_tool
```

## ASUS CLI

Interactive mode:

```bash
python3 asus_main.py
```

Analysis:

```bash
python3 asus_main.py analyze /path/to/asus_section.bin
```

Repacking:

```bash
python3 asus_main.py repack /path/to/original_asus_section.bin
```

The ASUS repack CLI asks for the extracted directory and output file name during execution.

[scene showing the ASUS menu after running `python3 asus_main.py` in a terminal]

## MSI CLI

Interactive mode:

```bash
python3 msi_main.py
```

Analysis:

```bash
python3 msi_main.py analyze /path/to/msi_section.bin
```

Repacking:

```bash
python3 msi_main.py repack /path/to/msi_extracted
```

The MSI repack CLI tries to find the original `.bin` file near the input directory. If found, it uses original analysis data for change detection and structure preservation.

[scene showing MSI Entry output after running `python3 msi_main.py analyze bios.bin` in a terminal]

## Windows Batch Files

On Windows, use the batch files in the `batch` directory.

ASUS:

```bat
batch\asus_tools.bat
```

MSI:

```bat
batch\msi_tools.bat
```

The batch files first check:

- Whether Python is available
- Whether required Python files exist
- Whether a menu-selected or drag-and-dropped file exists

[scene showing the ASUS batch menu in Windows Command Prompt]

## Batch File Drag and Drop

ASUS:

- Drag a BIOS/Section file onto `batch\asus_tools.bat`.
- Choose analysis or repacking from the menu.
- For repacking, enter the extracted directory path.

MSI:

- Drag an MSI `.bin` file onto `batch\msi_tools.bat`.
- The analysis menu uses the passed file.
- The repack menu uses `msi_extracted` under the project root by default.

[scene showing a BIOS file being dragged onto a Windows batch file]

## Force UI Language

Batch files also support the `UEFI_BINARY_TOOL_LANG` environment variable.

Korean:

```bat
set UEFI_BINARY_TOOL_LANG=ko
batch\asus_tools.bat
```

English:

```bat
set UEFI_BINARY_TOOL_LANG=en
batch\msi_tools.bat
```
