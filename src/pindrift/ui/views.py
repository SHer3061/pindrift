"""Tkinter views for the desktop UI.

This module imports tkinter at the top. It is imported lazily by ``app.main`` and by
``pindrift gui``, so a machine without Tk can still use every CLI command.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import sources
from ..models import Severity, State
from . import controller

BG = "#14171a"
SIDEBAR = "#0f1215"
PANEL = "#1b2026"
PANEL_ALT = "#20262d"
BORDER = "#2a3138"
FG = "#e6e8eb"
MUTED = "#98a2ad"
ACCENT = "#d97757"
GREEN = "#3fb950"
YELLOW = "#d29922"
RED = "#f85149"
BLUE = "#58a6ff"

FONT = ("Segoe UI", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")

STATE_COLORS = {
    State.OK: GREEN,
    State.DRIFT: RED,
    State.NEW: BLUE,
    State.MISSING: YELLOW,
    State.UNKNOWN: YELLOW,
}


class PindriftApp:
    def __init__(self, root: tk.Tk, settings: controller.Settings) -> None:
        self.root = root
        self.settings = settings
        self.inventory: controller.Inventory | None = None
        self.report = None
        self.server_rows: dict[str, dict] = {}
        self.source_rows: dict[str, controller.SourceRow] = {}
        self.queue: queue.Queue = queue.Queue()
        self.busy = False
        self.current_view = "overview"

        root.title("pindrift")
        root.geometry("1180x760")
        root.minsize(980, 620)
        root.configure(bg=BG)
        self._configure_styles()
        self._build_layout()
        self._show_view("overview")
        self.root.after(120, self._poll)
        self.root.after(200, self._refresh_inventory)

    # -- style -----------------------------------------------------------------

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                        rowheight=27, borderwidth=0, font=FONT)
        style.configure("Treeview.Heading", background=BG, foreground=MUTED,
                        relief="flat", font=FONT_SMALL)
        style.map("Treeview", background=[("selected", "#2b3a4a")],
                  foreground=[("selected", FG)])
        style.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                        foreground=FG, arrowcolor=FG)
        style.configure("TSpinbox", fieldbackground=PANEL, background=PANEL,
                        foreground=FG, arrowcolor=FG)

    # -- layout ----------------------------------------------------------------

    def _build_layout(self) -> None:
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        sidebar = tk.Frame(self.root, bg=SIDEBAR, width=196)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=18, pady=(22, 18))
        tk.Label(brand, text="pindrift", bg=SIDEBAR, fg=ACCENT, font=FONT_TITLE,
                 anchor="w").pack(fill="x")
        tk.Label(brand, text="MCP drift monitor", bg=SIDEBAR, fg=MUTED,
                 font=FONT_SMALL, anchor="w").pack(fill="x", pady=(2, 0))

        self.nav_buttons: dict[str, tk.Button] = {}
        for key, label in (
            ("overview", "Overview"),
            ("servers", "Servers"),
            ("sources", "Sources"),
            ("settings", "Settings"),
        ):
            button = tk.Button(
                sidebar, text=label, anchor="w", relief="flat", bd=0,
                bg=SIDEBAR, fg=MUTED, activebackground=PANEL_ALT,
                activeforeground=FG, font=FONT, padx=20, pady=9,
                command=lambda name=key: self._show_view(name),
            )
            button.pack(fill="x")
            self.nav_buttons[key] = button

        footer = tk.Frame(sidebar, bg=SIDEBAR)
        footer.pack(side="bottom", fill="x", padx=18, pady=16)
        tk.Label(footer, text="read-only checks by default", bg=SIDEBAR,
                 fg=MUTED, font=FONT_SMALL, anchor="w").pack(fill="x")

        main = tk.Frame(self.root, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        header = tk.Frame(main, bg=BG, height=58)
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(14, 0))
        header.grid_columnconfigure(0, weight=1)
        self.page_title = tk.Label(header, text="Overview", bg=BG, fg=FG,
                                   font=("Segoe UI", 14, "bold"), anchor="w")
        self.page_title.grid(row=0, column=0, sticky="w")

        actions = tk.Frame(header, bg=BG)
        actions.grid(row=0, column=1, sticky="e")
        self.action_buttons: list[tk.Button] = []
        for text, command in (
            ("Scan", self._refresh_inventory),
            ("Check", self._check),
            ("Pin", self._pin),
            ("Approve", self._approve),
        ):
            button = tk.Button(
                actions, text=text, relief="flat", bd=0, bg=PANEL_ALT,
                fg=FG, activebackground=BORDER, activeforeground=FG,
                font=FONT, padx=14, pady=6, command=command,
            )
            button.pack(side="left", padx=(6, 0))
            self.action_buttons.append(button)

        self.content = tk.Frame(main, bg=BG)
        self.content.grid(row=1, column=0, sticky="nsew", padx=22, pady=(12, 8))
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.views: dict[str, tk.Frame] = {}
        for key in ("overview", "servers", "sources", "settings"):
            frame = tk.Frame(self.content, bg=BG)
            frame.grid(row=0, column=0, sticky="nsew")
            self.views[key] = frame
        self._build_overview(self.views["overview"])
        self._build_servers(self.views["servers"])
        self._build_sources(self.views["sources"])
        self._build_settings(self.views["settings"])

        status = tk.Frame(main, bg=SIDEBAR, height=26)
        status.grid(row=2, column=0, sticky="ew")
        self.status_var = tk.StringVar(value="Loading sources...")
        tk.Label(status, textvariable=self.status_var, bg=SIDEBAR, fg=MUTED,
                 font=FONT_SMALL, anchor="w", padx=12).pack(fill="x")

    def _build_overview(self, frame: tk.Frame) -> None:
        metrics = tk.Frame(frame, bg=BG)
        metrics.pack(fill="x")
        self.metric_vars: dict[str, tk.StringVar] = {}
        for key, label, color in (
            ("ok", "OK", GREEN),
            ("drift", "DRIFT", RED),
            ("new", "NEW", BLUE),
            ("unknown", "UNKNOWN", YELLOW),
            ("missing", "MISSING", YELLOW),
        ):
            card = tk.Frame(metrics, bg=PANEL, highlightbackground=BORDER,
                            highlightthickness=1)
            card.pack(side="left", fill="x", expand=True, padx=(0, 8))
            tk.Label(card, text=label, bg=PANEL, fg=MUTED, font=FONT_SMALL,
                     anchor="w").pack(fill="x", padx=12, pady=(10, 0))
            value = tk.StringVar(value="0")
            self.metric_vars[key] = value
            tk.Label(card, textvariable=value, bg=PANEL, fg=color,
                     font=("Segoe UI", 24, "bold"), anchor="w").pack(
                fill="x", padx=12, pady=(0, 10)
            )

        info = tk.Frame(frame, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        info.pack(fill="both", expand=True, pady=(18, 0))
        self.overview_text = tk.Text(
            info, bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
            font=FONT, wrap="word", padx=18, pady=16, state="disabled",
        )
        self.overview_text.pack(fill="both", expand=True)
        self._set_text(
            self.overview_text,
            "pindrift pins the MCP state you approved and shows what changed.\n\n"
            "Scan loads the current inventory without executing any server.\n"
            "Check probes servers that already have a pin; an unpinned server is never run.\n\n"
            "Pin records the selected servers as trusted. Approve does the same after a review.",
        )

    def _build_servers(self, frame: tk.Frame) -> None:
        panes = tk.PanedWindow(frame, bg=BG, sashwidth=8, bd=0, relief="flat")
        panes.pack(fill="both", expand=True)

        left = tk.Frame(panes, bg=PANEL)
        columns = ("server", "clients", "state", "transport")
        self.server_tree = ttk.Treeview(left, columns=columns, show="headings",
                                        selectmode="browse")
        for column, label, width in (
            ("server", "SERVER", 220),
            ("clients", "CLIENTS", 150),
            ("state", "STATE", 90),
            ("transport", "TRANSPORT", 90),
        ):
            self.server_tree.heading(column, text=label)
            self.server_tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.server_tree.yview)
        self.server_tree.configure(yscrollcommand=scroll.set)
        self.server_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.server_tree.bind("<<TreeviewSelect>>", self._server_selected)
        for state, color in STATE_COLORS.items():
            self.server_tree.tag_configure(state.value, foreground=color)
        self.server_tree.tag_configure("unchecked", foreground=MUTED)
        panes.add(left, minsize=420, stretch="always")

        right = tk.Frame(panes, bg=PANEL)
        self.server_detail = tk.Text(
            right, bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
            font=FONT, wrap="word", padx=16, pady=14, state="disabled",
        )
        self.server_detail.pack(fill="both", expand=True)
        panes.add(right, minsize=300, stretch="always")

    def _build_sources(self, frame: tk.Frame) -> None:
        toolbar = tk.Frame(frame, bg=BG)
        toolbar.pack(fill="x", pady=(0, 8))
        for text, command in (
            ("Add source", self._add_source),
            ("Remove", self._remove_source),
            ("Test", self._test_source),
        ):
            button = tk.Button(toolbar, text=text, relief="flat", bd=0,
                               bg=PANEL_ALT, fg=FG, activebackground=BORDER,
                               activeforeground=FG, font=FONT, padx=12, pady=5,
                               command=command)
            button.pack(side="left", padx=(0, 6))

        panes = tk.PanedWindow(frame, bg=BG, sashwidth=8, bd=0, relief="flat")
        panes.pack(fill="both", expand=True)
        left = tk.Frame(panes, bg=PANEL)
        columns = ("client", "scope", "origin", "status", "path")
        self.source_tree = ttk.Treeview(left, columns=columns, show="headings",
                                        selectmode="browse")
        for column, label, width in (
            ("client", "CLIENT", 130),
            ("scope", "SCOPE", 70),
            ("origin", "ORIGIN", 70),
            ("status", "STATUS", 90),
            ("path", "PATH", 380),
        ):
            self.source_tree.heading(column, text=label)
            self.source_tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.source_tree.yview)
        self.source_tree.configure(yscrollcommand=scroll.set)
        self.source_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.source_tree.bind("<<TreeviewSelect>>", self._source_selected)
        panes.add(left, minsize=480, stretch="always")

        right = tk.Frame(panes, bg=PANEL)
        self.source_detail = tk.Text(
            right, bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
            font=FONT, wrap="word", padx=16, pady=14, state="disabled",
        )
        self.source_detail.pack(fill="both", expand=True)
        panes.add(right, minsize=260, stretch="always")

    def _build_settings(self, frame: tk.Frame) -> None:
        card = tk.Frame(frame, bg=PANEL, highlightbackground=BORDER,
                        highlightthickness=1)
        card.pack(fill="x")
        self.root_var = tk.StringVar(value=str(self.settings.root))
        self.timeout_var = tk.StringVar(value=str(self.settings.timeout))
        self.fail_on_var = tk.StringVar(value=self.settings.fail_on.value)
        self.project_var = tk.BooleanVar(value=self.settings.include_project)
        self.dedupe_var = tk.BooleanVar(value=self.settings.dedupe)

        rows = [
            ("Project root", tk.Entry(card, textvariable=self.root_var, bg=BG,
                                      fg=FG, insertbackground=FG, relief="flat",
                                      font=FONT)),
            ("Probe timeout (seconds)", ttk.Spinbox(card, from_=1, to=300,
                                                    textvariable=self.timeout_var,
                                                    width=12)),
            ("Fail on", ttk.Combobox(card, textvariable=self.fail_on_var,
                                     values=[s.value for s in Severity],
                                     state="readonly", width=12)),
        ]
        for index, (label, widget) in enumerate(rows):
            tk.Label(card, text=label, bg=PANEL, fg=MUTED, font=FONT,
                     anchor="w").grid(row=index, column=0, sticky="w",
                                      padx=18, pady=(16 if index == 0 else 8, 4))
            widget.grid(row=index, column=1, sticky="ew", padx=18,
                        pady=(16 if index == 0 else 8, 4))
        card.grid_columnconfigure(1, weight=1)

        tk.Checkbutton(card, text="Include project-scoped configs",
                       variable=self.project_var, bg=PANEL, fg=FG,
                       selectcolor=BG, activebackground=PANEL,
                       activeforeground=FG, font=FONT, anchor="w").grid(
            row=3, column=0, columnspan=2, sticky="w", padx=18, pady=(8, 4)
        )
        tk.Checkbutton(card, text="Dedupe identical servers across clients",
                       variable=self.dedupe_var, bg=PANEL, fg=FG,
                       selectcolor=BG, activebackground=PANEL,
                       activeforeground=FG, font=FONT, anchor="w").grid(
            row=4, column=0, columnspan=2, sticky="w", padx=18, pady=(4, 4)
        )
        tk.Button(card, text="Apply settings", relief="flat", bd=0,
                  bg=ACCENT, fg="#1a1a1a", activebackground="#e8896a",
                  activeforeground="#1a1a1a", font=FONT_BOLD, padx=14,
                  pady=6, command=self._apply_settings).grid(
            row=5, column=0, columnspan=2, sticky="w", padx=18, pady=16
        )

        note = (
            "Check only executes servers that already have a pin. "
            "Dedupe must match the mode used when the baseline was pinned."
        )
        tk.Label(frame, text=note, bg=BG, fg=MUTED, font=FONT_SMALL,
                 anchor="w", justify="left", wraplength=760).pack(
            fill="x", pady=(14, 0)
        )

    # -- navigation ------------------------------------------------------------

    def _show_view(self, name: str) -> None:
        self.current_view = name
        self.page_title.configure(text=name.capitalize())
        for key, button in self.nav_buttons.items():
            active = key == name
            button.configure(bg=PANEL_ALT if active else SIDEBAR,
                             fg=FG if active else MUTED)
        self.views[name].tkraise()
        if name == "sources":
            self._refresh_sources()

    # -- tasks -----------------------------------------------------------------

    def _set_busy(self, busy: bool, message: str = "") -> None:
        self.busy = busy
        for button in self.action_buttons:
            button.configure(state="disabled" if busy else "normal")
        if message:
            self.status_var.set(message)

    def _run(self, label: str, work, done) -> None:
        if self.busy:
            return
        self._set_busy(True, f"{label}...")

        def target() -> None:
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - surfaced in the status bar
                self.queue.put((label, None, exc, done))
            else:
                self.queue.put((label, result, None, done))

        threading.Thread(target=target, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                label, result, error, done = self.queue.get_nowait()
                self._set_busy(False, f"{label} finished" if error is None else "")
                if error is not None:
                    self.status_var.set(f"{label} failed: {error}")
                    messagebox.showerror("pindrift", f"{label} failed:\n{error}")
                else:
                    done(result)
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    # -- overview / servers ----------------------------------------------------

    def _refresh_inventory(self) -> None:
        self._run("Scan", lambda: controller.load_inventory(self.settings),
                  self._inventory_done)

    def _inventory_done(self, inventory: controller.Inventory) -> None:
        self.inventory = inventory
        self.report = None
        rows = []
        for spec, fingerprint in zip(inventory.specs, inventory.fingerprints):
            rows.append(
                {
                    "fingerprint": fingerprint,
                    "state": None,
                    "result": None,
                    "spec": spec,
                }
            )
        self._populate_servers(rows)
        pinned = sum(1 for fp in inventory.fingerprints if fp.server_id in inventory.pinned_ids)
        self._set_overview_counts(ok=0, drift=0, new=0, unknown=0, missing=0)
        self._set_text(
            self.overview_text,
            f"Sources scanned: {len(inventory.sources)}\n"
            f"Servers found: {len(inventory.specs)}\n"
            f"Pinned: {pinned}\n\n"
            "Press Check to compare against the baseline. Only pinned servers are probed.",
        )
        self.status_var.set(
            f"loaded {len(inventory.specs)} server(s); "
            f"{len(inventory.errors)} source warning(s)"
        )

    def _check(self) -> None:
        self._run("Check", lambda: controller.check(self.settings), self._report_done)

    def _report_done(self, report) -> None:
        self.report = report
        rows = []
        for result in report.results:
            rows.append(
                {
                    "fingerprint": result.fingerprint,
                    "state": result.state,
                    "result": result,
                    "spec": None,
                }
            )
        self._populate_servers(rows)
        summary = report.summary
        self._set_overview_counts(
            ok=summary.ok,
            drift=summary.drift,
            new=summary.new,
            unknown=summary.unknown,
            missing=summary.missing,
        )
        lines = [
            controller.summary_text(report),
            "",
            f"Baseline: {report.baseline_label}",
            f"Sources: {len(report.sources)}",
        ]
        errors = controller.errors_text(report.errors)
        if errors:
            lines += ["", "Source warnings:", errors]
        self._set_text(self.overview_text, "\n".join(lines))
        self.status_var.set(controller.summary_text(report))

    def _populate_servers(self, rows: list[dict]) -> None:
        self.server_tree.delete(*self.server_tree.get_children())
        self.server_rows.clear()
        for index, row in enumerate(rows):
            fp = row["fingerprint"]
            iid = f"row-{index}"
            state = row["state"]
            label = controller.state_label(state)
            tag = state.value if state is not None else "unchecked"
            self.server_tree.insert(
                "", "end", iid=iid,
                values=(
                    fp.server_id,
                    ", ".join(fp.all_clients),
                    label,
                    fp.transport,
                ),
                tags=(tag,),
            )
            self.server_rows[iid] = row
        if rows:
            first = next(iter(self.server_rows))
            self.server_tree.selection_set(first)
            self.server_tree.focus(first)
            self._render_server(first)
        else:
            self._set_text(self.server_detail, "No servers discovered.")

    def _server_selected(self, _event=None) -> None:
        selected = self.server_tree.selection()
        if selected:
            self._render_server(selected[0])

    def _render_server(self, iid: str) -> None:
        row = self.server_rows.get(iid)
        if row is None:
            return
        result = row["result"]
        if result is not None:
            text = controller.result_for(result)
        else:
            fingerprint = row["fingerprint"]
            pinned = bool(self.inventory and fingerprint.server_id in self.inventory.pinned_ids)
            text = controller.inventory_detail(fingerprint, pinned)
        self._set_text(self.server_detail, text)

    def _set_overview_counts(self, **counts: int) -> None:
        for key, value in counts.items():
            if key in self.metric_vars:
                self.metric_vars[key].set(str(value))

    # -- pin / approve ---------------------------------------------------------

    def _selected_specs(self) -> list:
        selected = self.server_tree.selection()
        specs = []
        by_id = (
            {spec.server_id: spec for spec in self.inventory.specs}
            if self.inventory is not None
            else {}
        )
        for iid in selected:
            row = self.server_rows.get(iid)
            if not row:
                continue
            spec = row.get("spec")
            if spec is None:
                spec = by_id.get(row["fingerprint"].server_id)
            if spec is not None:
                specs.append(spec)
        return specs

    def _pin(self) -> None:
        specs = self._selected_specs()
        if not specs:
            messagebox.showinfo("pindrift", "Select one or more servers in the Servers view first.")
            self._show_view("servers")
            return
        names = ", ".join(spec.server_id for spec in specs)
        if not messagebox.askyesno(
            "Pin servers",
            f"Pin these servers as trusted?\n\n{names}\n\n"
            "Pinning probes each selected server, which executes it once.",
        ):
            return
        self._run("Pin", lambda: controller.pin(specs, self.settings), self._after_write)

    def _approve(self) -> None:
        specs = self._selected_specs()
        if not specs:
            messagebox.showinfo("pindrift", "Select one or more servers in the Servers view first.")
            self._show_view("servers")
            return
        names = ", ".join(spec.server_id for spec in specs)
        if not messagebox.askyesno(
            "Approve current state",
            f"Replace the pin with the current state for:\n\n{names}\n\n"
            "Review the Check findings before approving.",
        ):
            return
        self._run("Approve", lambda: controller.approve(specs, self.settings),
                  self._after_write)

    def _after_write(self, fingerprints: list) -> None:
        self.status_var.set(f"wrote {len(fingerprints)} pin(s)")
        self._refresh_inventory()

    # -- sources ---------------------------------------------------------------

    def _refresh_sources(self) -> None:
        try:
            rows = controller.source_rows(self.settings)
        except Exception as exc:  # noqa: BLE001 - shown in the status bar
            self.status_var.set(f"sources failed: {exc}")
            return
        self.source_tree.delete(*self.source_tree.get_children())
        self.source_rows.clear()
        for index, row in enumerate(rows):
            iid = f"source-{index}"
            status = "ok" if row.exists else "missing"
            if not row.supported:
                status = "unsupported"
            self.source_tree.insert(
                "", "end", iid=iid,
                values=(row.client, row.scope, row.origin, status, row.path),
            )
            self.source_rows[iid] = row
        self._set_text(
            self.source_detail,
            "Built-in sources cover known clients. Use Add source for anything else.\n"
            "A manually registered source is additive; it cannot hide a built-in path.",
        )

    def _selected_source(self) -> controller.SourceRow | None:
        selected = self.source_tree.selection()
        return self.source_rows.get(selected[0]) if selected else None

    def _source_selected(self, _event=None) -> None:
        row = self._selected_source()
        if row:
            self._set_text(self.source_detail, controller.source_detail(row))

    def _add_source(self) -> None:
        SourceDialog(self.root, self._source_added)

    def _source_added(self) -> None:
        self._refresh_sources()

    def _remove_source(self) -> None:
        row = self._selected_source()
        if row is None or not row.identifier:
            messagebox.showinfo("pindrift", "Select a custom source first.")
            return
        if not messagebox.askyesno("Remove source", f"Remove {row.path} from the registry?"):
            return
        try:
            removed = controller.remove_source(row.identifier)
        except sources.SourceRegistryError as exc:
            messagebox.showerror("pindrift", str(exc))
            return
        if not removed:
            messagebox.showwarning("pindrift", "Source was not found.")
        self._refresh_sources()

    def _test_source(self) -> None:
        row = self._selected_source()
        if row is None:
            messagebox.showinfo("pindrift", "Select a source first.")
            return
        if not row.identifier:
            messagebox.showinfo("pindrift", "Built-in sources are tested by Scan and Check.")
            return
        try:
            count, lines = controller.test_source(row.identifier)
        except sources.SourceRegistryError as exc:
            messagebox.showerror("pindrift", str(exc))
            return
        messagebox.showinfo("Source test", "\n".join(lines))
        self.status_var.set(f"source test: {count} server(s)")

    # -- settings --------------------------------------------------------------

    def _apply_settings(self) -> None:
        try:
            timeout = float(self.timeout_var.get())
        except ValueError:
            messagebox.showerror("pindrift", "Timeout must be a number.")
            return
        self.settings = controller.Settings(
            root=Path(self.root_var.get()).expanduser(),
            include_project=bool(self.project_var.get()),
            dedupe=bool(self.dedupe_var.get()),
            timeout=timeout,
            fail_on=Severity(self.fail_on_var.get()),
        )
        self.status_var.set("settings applied")
        self._refresh_inventory()

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")


class SourceDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, on_saved) -> None:
        super().__init__(parent)
        self.on_saved = on_saved
        self.title("Add config source")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.client_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.scope_var = tk.StringVar(value="user")
        self.format_var = tk.StringVar(value="json")
        self.container_var = tk.StringVar()

        body = tk.Frame(self, bg=PANEL, padx=18, pady=16,
                        highlightbackground=BORDER, highlightthickness=1)
        body.pack(fill="both", expand=True, padx=14, pady=14)
        body.grid_columnconfigure(1, weight=1)

        def field(row: int, label: str, widget: tk.Widget) -> None:
            tk.Label(body, text=label, bg=PANEL, fg=MUTED, font=FONT,
                     anchor="w").grid(row=row, column=0, sticky="w", pady=6)
            widget.grid(row=row, column=1, sticky="ew", pady=6)

        field(0, "Client", tk.Entry(body, textvariable=self.client_var, bg=BG,
                                    fg=FG, insertbackground=FG, relief="flat"))
        path_frame = tk.Frame(body, bg=PANEL)
        tk.Entry(path_frame, textvariable=self.path_var, bg=BG, fg=FG,
                 insertbackground=FG, relief="flat").pack(side="left", fill="x",
                                                          expand=True)
        tk.Button(path_frame, text="Browse", relief="flat", bd=0, bg=PANEL_ALT,
                  fg=FG, command=self._browse).pack(side="left", padx=(6, 0))
        field(1, "Config path", path_frame)
        field(2, "Scope", ttk.Combobox(body, textvariable=self.scope_var,
                                       values=("user", "project"), state="readonly"))
        field(3, "Format", ttk.Combobox(body, textvariable=self.format_var,
                                       values=("json", "jsonc", "toml"),
                                       state="readonly"))
        field(4, "Container key", tk.Entry(body, textvariable=self.container_var,
                                          bg=BG, fg=FG, insertbackground=FG,
                                          relief="flat"))

        tk.Label(body, text="The path must be absolute. YAML configs are not supported.",
                 bg=PANEL, fg=MUTED, font=FONT_SMALL, anchor="w").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )

        buttons = tk.Frame(body, bg=PANEL)
        buttons.grid(row=6, column=0, columnspan=2, sticky="e", pady=(14, 0))
        tk.Button(buttons, text="Cancel", relief="flat", bd=0, bg=PANEL_ALT,
                  fg=FG, command=self.destroy).pack(side="left", padx=(0, 6))
        tk.Button(buttons, text="Add", relief="flat", bd=0, bg=ACCENT,
                  fg="#1a1a1a", font=FONT_BOLD,
                  command=self._save).pack(side="left")

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Select an MCP config file",
            filetypes=(("JSON", "*.json *.jsonc"), ("TOML", "*.toml"), ("All files", "*.*")),
        )
        if path:
            self.path_var.set(path)

    def _save(self) -> None:
        try:
            controller.add_source(
                client=self.client_var.get(),
                path=self.path_var.get(),
                scope=self.scope_var.get(),
                format=self.format_var.get(),
                container=self.container_var.get().strip() or None,
            )
        except sources.SourceRegistryError as exc:
            messagebox.showerror("pindrift", str(exc), parent=self)
            return
        self.on_saved()
        self.destroy()
