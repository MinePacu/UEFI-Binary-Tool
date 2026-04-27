# ASUS Analysis and Repacking

## Supported Scope

The ASUS workflow targets BIOS/UEFI Section Binaries that contain ASUS Packer structures. The program searches for ASUS Packer package patterns, then analyzes or repacks based on package image metadata and image payloads.

## ASUS File Analysis

Run from the GUI:

1. Select `ASUS` as the vendor.
2. Open the `Analyze` tab.
3. Choose the BIOS/Section file to analyze.
4. Click `Start Analysis`.

[scene showing ASUS analysis logs with the ASUS Packer package count and analysis progress]

Run from the CLI:

```bash
python3 asus_main.py analyze /path/to/asus_section.bin
```

The analysis checks:

- ASUS Packer package validation
- Magic-byte analysis
- String and pattern search for UEFI, BIOS, ASUS, Intel, AMD, and related markers
- Embedded image candidates such as PNG, JPEG, and BMP
- Entropy analysis
- NULL byte sequences and alignment structure
- Analysis summary generation

Generated files:

```text
<original_name>_analysis.txt
<original_name>_analysis.md
```

## Prepare ASUS Repacking

ASUS repacking requires:

1. The original ASUS BIOS/Section binary
2. A directory containing extracted and edited image files

Expected folder structure:

```text
asus_extracted/
└── asus_pack_1/
    ├── image_nr1_off0x00001234.png
    ├── image_nr2_off0x00005678.bmp
    └── ...
```

Image files are mapped by the original image number and offset.

```text
image_nr{number}_off0x{8_digit_hex_offset}.{extension}
```

Example:

```text
image_nr1_off0x0000a240.png
```

If the filename convention is broken, that image can be skipped during repacking.

[scene showing `asus_extracted/asus_pack_1` in a file manager with `image_nr..._off0x...` image files]

## Run ASUS Repacking

Run from the GUI:

1. Select `ASUS` as the vendor.
2. Open the `Repack` tab.
3. Set `Original BIOS file` to the original ASUS Section Binary.
4. Set `Extracted image directory` to the `asus_extracted` path.
5. Set `Output file` if needed.
6. Click `Start Repack`.

[scene showing ASUS repacking completed with change summary, output path, and completion message in the operation log]

Run from the CLI:

```bash
python3 asus_main.py repack /path/to/original_asus_section.bin
```

The CLI mode asks for the extracted directory and output file name during execution.

## How Repacking Works

The ASUS repacker first reads ASUS Packer packages and image metadata from the original file. It then compares images in the extracted folder against original image bytes and replaces only files that actually changed.

The processing path depends on size changes:

| Condition | Method |
|---|---|
| Total size change of edited images is 0 bytes | Direct byte replacement at the original offsets |
| Size changed | Rebuild while preserving package headers, special patterns, image order, and 4-byte alignment |
| No modified images | Copy the original file unchanged |

If the image container type changes, the image is skipped. For example, if the original is `png` and the edited file is `jpg`, it is not replaced.

## Recommended Workflow

1. Back up the original file.
2. Extract images from the ASUS Packer structure.
3. Edit images while preserving filenames and extensions.
4. Run ASUS repacking from the GUI or CLI.
5. Verify the generated `_asus_repacked.bin` with separate tools.
