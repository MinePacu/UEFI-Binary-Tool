# UEFI Binary Tool Wiki

> This wiki was written against the current state of the program.
> Screenshot placeholders are left in `[scene to capture]` format so screenshots can be added later.

## Overview

UEFI Binary Tool analyzes ASUS Packer or MSI Packer structures in BIOS/UEFI Section binaries and repacks externally edited image files back into the vendor-specific package format.

Current support:

| Vendor | Supported features | Notes |
|---|---|---|
| ASUS | Section Binary analysis, ASUS Packer structure-based image repacking | Repacking requires the original BIOS/Section file and an extracted folder such as `asus_extracted/asus_pack_*`. |
| MSI | MSI Click BIOS X Section Binary analysis, image repacking | MSI image extraction is not included. Prepare the extracted folder with a separate tool. |

## Quick Start

Run the GUI:

```bash
python3 gui_main.py
```

Or run the package module:

```bash
python3 -m uefi_binary_tool
```

If Python includes Tkinter, the desktop GUI opens. If Tkinter is unavailable, the local web UI starts automatically and opens in your browser.

[scene showing the first launch with vendor selection, Analyze tab, Repack tab, and operation log]

## Recommended Reading Order

1. [GUI Usage](GUI-Usage-en)
2. [ASUS Analysis and Repacking](ASUS-Workflow-en)
3. [MSI Analysis and Repacking](MSI-Workflow-en)
4. [CLI and Windows Batch Files](CLI-and-Batch-en)
5. [Troubleshooting](Troubleshooting-en)

## Important Notes

- Always keep a separate backup of the original BIOS/UEFI file.
- Verify repacked output with separate tools before using it for flashing.
- Files with the wrong vendor or unsupported format can be rejected during validation.
- MSI support targets Click BIOS X `$MsI$` Packer entries.
- The repacking feature helps replace images and preserve structure, but it does not guarantee that the resulting file is safe or valid for real hardware flashing.
