# Troubleshooting

## GUI Does Not Open

If Tkinter is unavailable when running `python3 gui_main.py`, the program automatically switches to the web UI. Check whether the terminal prints an address like this:

```text
UEFI Binary Tool web UI: http://127.0.0.1:port/
```

If the browser does not open automatically, enter the address manually.

[scene showing the local web UI address printed in the terminal]

## The Web UI Has No File Picker

This is expected. Because of browser security restrictions, the web UI cannot pass local file paths through a file picker. Enter the full path manually.

Examples:

```text
/Users/name/Desktop/bios.bin
C:\Users\name\Desktop\bios.bin
```

## `File path is empty`

A required input path is empty.

Check:

- `BIOS/Section file` on the Analyze tab
- `Original BIOS file` on the Repack tab
- `Extracted image directory` on the Repack tab
- Whether full paths were typed manually when using the web UI

## `File not found`

The entered path does not point to an existing file.

Check:

- Whether quotation marks were included in the path
- Whether the filename is correct
- Whether Windows backslashes are missing
- Whether a directory path and file path were mixed up

## ASUS Packer Structure Was Not Found

Example:

```text
ASUS Packer package structure was not found.
```

Possible causes:

- The selected file is not an ASUS Packer Section Binary
- The required Section has not been extracted from the full BIOS image
- The file is damaged or too small
- An MSI file was selected while the vendor is set to ASUS

Fix:

- Confirm the selected vendor.
- Confirm that the file is a Section Binary that can be extracted/repacked with ASUS Packer.
- Prepare the original file again.

## MSI `$MsI$` Signature Was Not Found

Example:

```text
MSI Packer signature '$MsI$' was not found.
```

Possible causes:

- The file is not an MSI Click BIOS X Section Binary
- The file is Click BIOS 5 or another unsupported format
- An ASUS file was selected while the vendor is set to MSI
- The target Section has not been extracted from the full BIOS image

Fix:

- Confirm the selected vendor.
- Confirm that this is the target MSI Click BIOS X Section.
- Extract the correct Section with a separate tool and analyze it again.

## ASUS Repacking Skips an Image

Possible causes:

- The filename does not follow `image_nr{number}_off0x{offset}.{extension}`
- The edited image type differs from the original image type
- Required package folders such as `asus_pack_1` or `asus_pack_2` are missing

Fix:

- Preserve filenames from extraction.
- Keep the same container type, such as PNG to PNG or BMP to BMP.
- Check the `asus_extracted/asus_pack_*` structure.

## MSI Repacking Cannot Find Image Files

Possible causes:

- The input directory is empty
- Files use unsupported extensions
- The `MSI_pack*` subfolder is in the wrong location

Supported extensions:

```text
.bin, .jpg, .jpeg, .png, .bmp, .ico
```

Fix:

- Confirm that image files exist under `msi_extracted/MSI_pack_*`.
- In simple mode, confirm that image files exist directly under the selected input directory.

## The Repacked Output Is Identical to the Original

If no edited images are detected, the program copies the original file unchanged.

Check:

- Whether the image files were actually edited
- Whether edited files were saved in the correct extracted folder
- Whether filenames still follow the original mapping convention
- Whether the original and edited files are byte-for-byte identical

## Generated Files Are Hard to Find

After completion, check `[OUTPUTS]` or `[OUTPUT]` near the bottom of the GUI operation log.

Common generated files:

```text
*_analysis.txt
*_analysis.md
*_msi_analysis_report.txt
*_asus_repacked.bin
*_msi_repacked.bin
*_repack_report.txt
```

[scene showing output file paths listed at the bottom of the operation log]
