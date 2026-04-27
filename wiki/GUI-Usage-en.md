# GUI Usage

## Launch

Run this command from the project root:

```bash
python3 gui_main.py
```

Or run the package module:

```bash
python3 -m uefi_binary_tool
```

If Python includes Tkinter, the desktop GUI opens. If Tkinter is unavailable, the local web UI starts instead, and the `http://127.0.0.1:port/` address printed in the terminal opens in a browser.

## Language

The UI language follows the operating system locale by default.

- Korean OS: Korean UI
- Other locales: English UI

Use the environment variable below to force a language:

```bash
UEFI_BINARY_TOOL_LANG=ko python3 gui_main.py
UEFI_BINARY_TOOL_LANG=en python3 gui_main.py
```

## Layout

The GUI contains these areas:

- Vendor selector: `ASUS` or `MSI`
- Analyze tab: analyzes a BIOS/Section file
- Repack tab: selects the original file, extracted image directory, and output file path
- Operation log: shows validation, analysis, repacking progress, and output paths
- Status bar: shows the current operation state

[scene showing the main GUI window with the vendor selector, Analyze tab, Repack tab, and operation log]

## Run Analysis

1. Select the vendor.
2. Open the `Analyze` tab.
3. Set the `BIOS/Section file`.
4. Click `Start Analysis`.
5. Check the operation log and completion message.

[scene showing ASUS selected, a BIOS/Section path filled in on the Analyze tab, just before clicking Start Analysis]

Generated files after successful analysis:

| Vendor | Output files |
|---|---|
| ASUS | `<original_name>_analysis.txt`, `<original_name>_analysis.md` |
| MSI | `<original_name>_msi_analysis_report.txt` |

## Run Repack

1. Select the vendor.
2. Open the `Repack` tab.
3. Set the `Original BIOS file`.
4. Set the `Extracted image directory`.
5. Set the `Output file`, or leave it empty to use the default name.
6. Click `Start Repack`.
7. Check `[OUTPUTS]` or `[OUTPUT]` in the operation log for generated files.

[scene showing the Repack tab with original BIOS file, extracted image directory, and output file path filled in]

Default output file names:

| Vendor | Default output name |
|---|---|
| ASUS | `<original_name>_asus_repacked.bin` |
| MSI | `<input_directory>_msi_repacked.bin` |

For MSI repacking, the original BIOS file can be left empty. Providing it is recommended because the tool can use original analysis data for better structure preservation and change detection.

## Web UI Differences

The web UI cannot pass local file paths through a file picker because of browser security restrictions. Enter full local paths manually in each field.

[scene showing the browser-based web UI with full file paths typed manually]

The web UI uses these internal APIs:

- `POST /api/run`: starts analysis or repacking
- `GET /api/status`: refreshes status and logs

Regular users do not need to call these APIs directly.
