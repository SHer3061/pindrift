"""pywebview JS bridge.

The bridge is deliberately narrow: ids, enums and plain values. It never accepts an
arbitrary command, URL or filesystem read. The only path-like input is a source file
selected through the native file dialog and then validated by the source registry.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import sources as source_store
from ..discover import ServerSpec
from ..models import Severity
from . import controller, present
from . import prefs as prefs_store
from .controller import Settings, SourceRow

JobWork = Callable[[Callable[[int, int, str], None]], dict[str, Any]]


class PindriftApi:
    def __init__(
        self,
        settings: Settings,
        prefs: dict[str, Any],
        window: Any | None = None,
    ) -> None:
        self.settings = settings
        self.prefs = prefs
        self.window = window
        self.inventory = None
        self.report = None
        self._lock = threading.Lock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._active_job: str | None = None

    # -- envelopes -------------------------------------------------------------

    @staticmethod
    def _ok(data: Any) -> dict[str, Any]:
        return {"ok": True, "data": data}

    @staticmethod
    def _fail(message: str, code: str = "error", hint: str | None = None) -> dict[str, Any]:
        error = {"code": code, "message": str(message)}
        if hint:
            error["hint"] = hint
        return {"ok": False, "error": error}

    def _safe(self, fn, *args, **kwargs) -> dict[str, Any]:
        try:
            return self._ok(fn(*args, **kwargs))
        except source_store.SourceRegistryError as exc:
            return self._fail(str(exc), "source_error")
        except PermissionError as exc:
            return self._fail(str(exc), "permission")
        except FileNotFoundError as exc:
            return self._fail(str(exc), "not_found")
        except Exception as exc:  # noqa: BLE001 - every UI call must get an envelope
            return self._fail(str(exc), "internal", "Close and reopen the window if this persists.")

    # -- settings --------------------------------------------------------------

    def _prefs_public(self) -> dict[str, Any]:
        return dict(self.prefs)

    def _settings_from_prefs(self, values: dict[str, Any]) -> Settings:
        return Settings(
            root=Path(str(values["root"])).expanduser(),
            include_project=bool(values.get("includeProject", True)),
            dedupe=bool(values.get("dedupe", True)),
            timeout=float(values.get("timeout", 20)),
            fail_on=Severity(str(values.get("failOn", "high"))),
        )

    def _refresh_sources(self) -> list[SourceRow]:
        return controller.source_rows(self.settings)

    def _refresh_inventory(self):
        self.inventory = controller.load_inventory(self.settings)
        return self.inventory

    # -- bootstrap / scan ------------------------------------------------------

    def bootstrap(self) -> dict[str, Any]:
        return self._safe(self._bootstrap)

    def _bootstrap(self) -> dict[str, Any]:
        inventory = self._refresh_inventory()
        sources = self._refresh_sources()
        return present.bootstrap_payload(inventory, self._prefs_public(), sources)

    def scan(self) -> dict[str, Any]:
        return self._safe(self._scan)

    def _scan(self) -> dict[str, Any]:
        inventory = self._refresh_inventory()
        payload = present.inventory_payload(inventory)
        payload["sources"] = [
            present.source_row(row) for row in self._refresh_sources()
        ]
        return payload

    def server(self, server_id: str) -> dict[str, Any]:
        return self._safe(self._server, server_id)

    def _server(self, server_id: str) -> dict[str, Any]:
        if not isinstance(server_id, str) or not server_id:
            raise ValueError("server id is required")
        if self.inventory is None:
            self._refresh_inventory()
        assert self.inventory is not None
        fingerprint = next(
            (fp for fp in self.inventory.fingerprints if fp.server_id == server_id),
            None,
        )
        if fingerprint is None:
            raise ValueError(f"unknown server {server_id!r}")
        result = None
        if self.report is not None:
            result = next(
                (item for item in self.report.results if item.fingerprint.server_id == server_id),
                None,
            )
        return present.server_row(
            fingerprint,
            pinned=server_id in self.inventory.pinned_ids,
            result=result,
        )

    # -- jobs ------------------------------------------------------------------

    def _start_job(self, kind: str, work: JobWork) -> dict[str, Any]:
        with self._lock:
            if self._active_job is not None:
                active = self._jobs.get(self._active_job)
                if active and active["state"] == "running":
                    return self._fail("another operation is running", "job_busy")
            job_id = uuid.uuid4().hex
            job = {
                "id": job_id,
                "kind": kind,
                "state": "running",
                "done": 0,
                "total": 0,
                "current": "",
                "started": time.time(),
                "finished": None,
                "result": None,
                "error": None,
            }
            self._jobs[job_id] = job
            self._active_job = job_id

        def progress(done: int, total: int, current: str) -> None:
            with self._lock:
                job["done"] = done
                job["total"] = total
                job["current"] = current

        def target() -> None:
            try:
                result = work(progress)
            except Exception as exc:  # noqa: BLE001 - job failure is data
                with self._lock:
                    job["state"] = "failed"
                    job["error"] = {"message": str(exc), "code": "job_failed"}
                    job["finished"] = time.time()
            else:
                with self._lock:
                    job["state"] = "done"
                    job["result"] = result
                    job["finished"] = time.time()
            finally:
                with self._lock:
                    if self._active_job == job_id:
                        self._active_job = None
                    if len(self._jobs) > 20:
                        oldest = min(self._jobs, key=lambda key: self._jobs[key]["started"])
                        if oldest != job_id:
                            self._jobs.pop(oldest, None)

        threading.Thread(target=target, daemon=True).start()
        return self._ok({"jobId": job_id})

    def start_check(self) -> dict[str, Any]:
        return self._start_job("check", self._run_check)

    def _run_check(self, progress) -> dict[str, Any]:
        report = controller.check(self.settings, progress)
        self.report = report
        self._refresh_inventory()
        return present.report_payload(report)

    def start_write(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return self._fail("payload must be an object", "invalid_request")
        if payload.get("confirm") is not True:
            return self._fail("write requires explicit confirmation", "confirm_required")
        mode = payload.get("mode")
        if mode not in ("pin", "approve"):
            return self._fail("mode must be pin or approve", "invalid_mode")
        ids = payload.get("ids")
        if (
            not isinstance(ids, list)
            or not ids
            or not all(isinstance(item, str) for item in ids)
        ):
            return self._fail("ids must be a non-empty list", "invalid_ids")
        deduped = list(dict.fromkeys(ids))
        job_kind = "pin" if mode == "pin" else "approve"
        return self._start_job(job_kind, self._write_job(mode, deduped))

    def _write_job(self, mode: str, ids: list[str]) -> JobWork:
        def work(progress) -> dict[str, Any]:
            if self.inventory is None:
                self._refresh_inventory()
            assert self.inventory is not None
            by_id = {spec.server_id: spec for spec in self.inventory.specs}
            specs: list[ServerSpec] = []
            for server_id in ids:
                spec = by_id.get(server_id)
                if spec is None:
                    raise ValueError(f"unknown server {server_id!r}")
                specs.append(spec)
            if mode == "pin":
                fingerprints = controller.pin(specs, self.settings, progress)
            else:
                fingerprints = controller.approve(specs, self.settings, progress)
            self._refresh_inventory()
            return {"written": [fingerprint.server_id for fingerprint in fingerprints], "mode": mode}

        return work

    def job_status(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            job = self._jobs.get(str(job_id))
            if job is None:
                return self._fail("unknown job", "unknown_job")
            snapshot = dict(job)
        return self._ok(snapshot)

    # -- sources ---------------------------------------------------------------

    def sources(self) -> dict[str, Any]:
        return self._safe(
            lambda: [present.source_row(row) for row in self._refresh_sources()]
        )

    def add_source(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return self._fail("payload must be an object", "invalid_request")
        return self._safe(
            self._add_source,
            str(payload.get("client") or ""),
            str(payload.get("path") or ""),
            str(payload.get("scope") or "user"),
            payload.get("format") or None,
            payload.get("container") or None,
        )

    def _add_source(self, client, path, scope, format, container):
        controller.add_source(
            client=client,
            path=path,
            scope=scope,
            format=format,
            container=container,
        )
        return [present.source_row(row) for row in self._refresh_sources()]

    def remove_source(self, identifier: str) -> dict[str, Any]:
        return self._safe(self._remove_source, str(identifier))

    def _remove_source(self, identifier: str) -> list[dict[str, Any]]:
        if not controller.remove_source(identifier):
            raise ValueError("source was not found")
        return [present.source_row(row) for row in self._refresh_sources()]

    def test_source(self, identifier: str) -> dict[str, Any]:
        return self._safe(self._test_source, str(identifier))

    def _test_source(self, identifier: str) -> dict[str, Any]:
        count, lines = controller.test_source(identifier)
        return {"count": count, "lines": [present.text(line, 400) for line in lines]}

    def pick_file(self) -> dict[str, Any]:
        if self.window is None:
            return self._fail("file dialog is unavailable", "no_window")
        try:
            import webview

            result = self.window.create_file_dialog(
                webview.OPEN_DIALOG,
                allow_multiple=False,
                file_types=(
                    "MCP config (*.json;*.jsonc;*.toml)",
                    "All files (*.*)",
                ),
            )
        except Exception as exc:  # noqa: BLE001 - dialog failures are reported to the UI
            return self._fail(str(exc), "dialog_failed")
        if not result:
            return self._ok({"path": None})
        return self._ok({"path": str(result[0])})

    # -- prefs -----------------------------------------------------------------

    def save_prefs(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            return self._fail("payload must be an object", "invalid_request")
        root = payload.get("root")
        if not isinstance(root, str) or not root.strip():
            return self._fail("root is required", "invalid_root")
        candidate = Path(root).expanduser()
        if not candidate.is_absolute() or not candidate.is_dir():
            return self._fail("root must be an existing absolute directory", "invalid_root")
        timeout = payload.get("timeout")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            return self._fail("timeout must be a number", "invalid_timeout")
        if not 1 <= float(timeout) <= 300:
            return self._fail("timeout must be between 1 and 300 seconds", "invalid_timeout")
        fail_on = payload.get("failOn")
        if fail_on not in {severity.value for severity in Severity}:
            return self._fail("invalid failOn", "invalid_fail_on")
        theme = payload.get("theme")
        if theme not in prefs_store.THEMES:
            return self._fail("invalid theme", "invalid_theme")
        if not isinstance(payload.get("dedupe"), bool) or not isinstance(
            payload.get("includeProject"), bool
        ):
            return self._fail("dedupe and includeProject must be booleans", "invalid_request")
        try:
            cleaned = prefs_store.save(payload)
        except OSError as exc:
            return self._fail(str(exc), "prefs_write_failed")
        self.prefs = cleaned
        self.settings = self._settings_from_prefs(cleaned)
        return self._ok({"prefs": cleaned, "needsRescan": True})
