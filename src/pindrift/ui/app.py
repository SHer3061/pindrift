"""Entry point for the optional desktop UI."""

from __future__ import annotations

import sys
from pathlib import Path

from . import controller

EXIT_USAGE = 64


def main(
    root: Path | None = None,
    include_project: bool = True,
    dedupe: bool = True,
) -> int:
    try:
        import tkinter as tk
    except Exception as exc:  # noqa: BLE001 - tkinter can fail as ImportError or OSError
        print(
            "pindrift gui: tkinter is not available "
            f"({exc}); install python3-tk to use the desktop UI",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        window = tk.Tk()
    except Exception as exc:  # noqa: BLE001 - TclError or platform display errors
        print(f"pindrift gui: cannot open a display: {exc}", file=sys.stderr)
        return EXIT_USAGE

    from .views import PindriftApp

    settings = controller.Settings(
        root=(root or Path.cwd()).resolve(),
        include_project=include_project,
        dedupe=dedupe,
    )
    PindriftApp(window, settings)
    window.mainloop()
    return 0
