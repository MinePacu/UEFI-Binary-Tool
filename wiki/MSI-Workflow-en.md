# MSI Analysis and Repacking

## Supported Scope

The MSI workflow targets `$MsI$` Packer structures in MSI Click BIOS X Section Binaries.

The program does not include MSI image extraction. Prepare the extracted image directory with a separate tool before repacking.

## MSI File Analysis

Run from the GUI:

1. Select `MSI` as the vendor.
2. Open the `Analyze` tab.
3. Choose the MSI BIOS/Section file to analyze.
4. Click `Start Analysis`.

[scene showing MSI analysis logs with `$MsI$` signature count and MSI Entry list]

Run from the CLI:

```bash
python3 msi_main.py analyze /path/to/msi_section.bin
```

The analysis checks:

- Presence of the `$MsI$` signature
- MSI Packer entry structure
- Per-entry offset, image size, and image number
- Image type estimation
- Magic-byte patterns
- Entry count, total image size, and file coverage

Generated file:

```text
<original_name>_msi_analysis_report.txt
```

## Prepare MSI Repacking

The repack input is a directory containing extracted image files.

Recommended structure-preserving folder layout:

```text
msi_extracted/
└── MSI_pack_1/
    ├── image_nr0_off0x1234.png
    ├── image_nr1_off0x5678.bmp
    ├── image_nr2_off0x9ABC.bin
    └── msi_structure_info.txt
```

Supported extensions:

```text
.bin, .jpg, .jpeg, .png, .bmp, .ico
```

Filename convention:

```text
image_nr{number}_off0x{hex_offset}.{extension}
```

[scene showing `msi_extracted/MSI_pack_1` in a file manager with image files and `msi_structure_info.txt`]

## Run MSI Repacking

Run from the GUI:

1. Select `MSI` as the vendor.
2. Open the `Repack` tab.
3. Set `Extracted image directory` to the `msi_extracted` path.
4. Set `Original BIOS file` if available.
5. Set `Output file` if needed.
6. Click `Start Repack`.

[scene showing MSI repacking completed with structure-preservation mode, change detection result, and output path in the operation log]

Run from the CLI:

```bash
python3 msi_main.py repack /path/to/msi_extracted
```

Output files:

```text
<extracted_directory>_msi_repacked.bin
<extracted_directory>_msi_repacked_repack_report.txt
```

## Repack Modes

The MSI repacker checks whether the input directory contains a subdirectory starting with `MSI_pack`.

| Condition | Method |
|---|---|
| `MSI_pack*` folder exists | Structure-preserving mode |
| No `MSI_pack*` folder | Simple mode: repack image files directly under the input directory by name or numeric order |
| Original BIOS file provided | Uses original analysis data for better change detection and structure preservation |
| Original BIOS file omitted | Repackages based on extracted folder contents and metadata |

If the original file is provided and all extracted images match the original bytes, the tool copies the original file unchanged.

## Drag-and-Drop Integrated Processing

On Windows, passing a `.bin` file to `batch\msi_tools.bat` or the `msi_main.py` drag-and-drop flow attempts integrated processing.

Integrated flow:

1. Analyze the original MSI file
2. Check for `msi_extracted` beside the original file
3. Check for an `MSI_pack_` folder
4. Run structure-preserving repack
5. Generate the analysis report and repacked file

Note: this flow still does not perform extraction. The `msi_extracted/MSI_pack_*` folder must already exist.
