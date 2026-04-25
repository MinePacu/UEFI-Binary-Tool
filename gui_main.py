#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Launch the graphical UEFI Binary Tool application."""

try:
    from uefi_binary_tool.ui.app import main
except ModuleNotFoundError as exc:
    if exc.name != "_tkinter":
        raise
    from uefi_binary_tool.web.app import main


if __name__ == "__main__":
    main()
