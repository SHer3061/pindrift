"use strict";

const state = {
  data: null,
  servers: [],
  sources: [],
  stats: {},
  prefs: null,
  view: "overview",
  selectedServer: null,
  selectedSource: null,
  detailTab: "overview",
  filter: "all",
  query: "",
  activity: [],
  busy: false,
};

const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function apiReady() {
  if (window.pywebview && window.pywebview.api) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("pywebview bridge did not become ready")), 8000);
    window.addEventListener("pywebviewready", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}

async function api(method, ...args) {
  if (!window.pywebview || !window.pywebview.api || typeof window.pywebview.api[method] !== "function") {
    throw new Error(`bridge method unavailable: ${method}`);
  }
  const response = await window.pywebview.api[method](...args);
  if (!response || response.ok !== true) {
    const error = response && response.error ? response.error : {};
    const message = error.message || "request failed";
    const hint = error.hint ? ` ${error.hint}` : "";
    throw new Error(message + hint);
  }
  return response.data;
}

function setStatus(text, right) {
  $("statusText").textContent = text;
  if (right !== undefined) $("statusRight").textContent = right;
}

function toast(message, bad) {
  const node = el("div", "toast" + (bad ? " bad" : ""), message);
  $("toastHost").appendChild(node);
  setTimeout(() => {
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 250);
  }, 3200);
}

function showError(message) {
  const banner = $("errorBanner");
  banner.textContent = message || "";
  banner.classList.toggle("hidden", !message);
}

function clearError() {
  showError("");
}

function addActivity(text, kind) {
  state.activity.unshift({
    text,
    kind: kind || "",
    at: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  });
  state.activity = state.activity.slice(0, 12);
  renderActivity();
}

function themeValue(value) {
  if (value === "system") {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return value === "dark" ? "dark" : "light";
}

function applyTheme(value) {
  document.documentElement.dataset.theme = themeValue(value || "system");
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  document.querySelectorAll(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${view}`);
  });
  const titles = { overview: "Overview", servers: "Servers", sources: "Sources", settings: "Settings" };
  $("pageTitle").textContent = titles[view] || "Overview";
  if (view === "servers") renderServerTable();
  if (view === "sources") renderSources();
  if (view === "settings") fillSettings();
}

function setBusy(visible) {
  state.busy = visible;
  $("busy").classList.toggle("hidden", !visible);
  ["scanBtn", "checkBtn"].forEach((id) => { $(id).disabled = visible; });
}

function busy(title, copy) {
  $("busyTitle").textContent = title;
  $("busyCopy").textContent = copy || "";
  $("progressBar").style.width = "0%";
  $("progressBar").parentElement.classList.add("indeterminate");
  setBusy(true);
}

function busyProgress(done, total, current) {
  const bar = $("progressBar");
  bar.parentElement.classList.remove("indeterminate");
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  bar.style.width = `${pct}%`;
  $("busyCopy").textContent = total > 0 ? `${done}/${total} · ${current}` : current || "";
}

function hideBusy() {
  setBusy(false);
}

function metricCard(key, label) {
  const raw = state.stats ? state.stats[key] : null;
  const empty = raw === null || raw === undefined;
  const card = el("div", `metric ${key}` + (empty ? " metric-empty" : ""));
  card.appendChild(el("div", "metric-label", label));
  card.appendChild(el("div", "metric-value", empty ? "n/a" : raw));
  return card;
}

function renderMetrics() {
  const host = $("metrics");
  clear(host);
  [["ok", "OK"], ["drift", "Drift"], ["new", "New"], ["unknown", "Unknown"], ["missing", "Missing"]]
    .forEach(([key, label]) => host.appendChild(metricCard(key, label)));
}

function renderActivity() {
  const host = $("activityList");
  clear(host);
  if (!state.activity.length) {
    host.appendChild(el("div", "activity-empty", "No actions yet. Scan or check to begin."));
    return;
  }
  state.activity.forEach((item) => {
    const row = el("div", `activity-item ${item.kind}`);
    row.appendChild(el("div", "activity-dot"));
    const body = el("div");
    body.appendChild(document.createTextNode(item.text));
    body.appendChild(el("span", "activity-time", item.at));
    row.appendChild(body);
    host.appendChild(row);
  });
}

function renderOverview() {
  renderMetrics();
  renderActivity();
  renderOverviewServers();
  const baseline = state.data ? state.data.baselineLabel : "no baseline";
  $("baselineValue").textContent = baseline && baseline.includes("no baseline") ? "No baseline yet" : (baseline || "No baseline yet");
  const total = state.stats.total || 0;
  const pinned = state.stats.pinned || 0;
  $("baselineMeta").textContent = `${total} target(s) · ${pinned} pinned · ${Math.max(total - pinned, 0)} unpinned`;
  if (state.data && state.data.app) {
    $("versionLabel").textContent = `pindrift ${state.data.app.version}`;
    $("statusRight").textContent = `pindrift ${state.data.app.version}`;
  }
}

function renderOverviewServers() {
  const body = $("overviewRows");
  if (!body) return;
  clear(body);
  if (!state.servers.length) {
    const row = el("tr");
    const cell = el("td", "muted", "No servers discovered yet. Run Scan.");
    cell.colSpan = 4;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  const priority = { drift: 0, unknown: 1, new: 2, missing: 3, ok: 4 };
  const servers = state.servers.slice().sort((a, b) => {
    const left = priority[a.state] === undefined ? 5 : priority[a.state];
    const right = priority[b.state] === undefined ? 5 : priority[b.state];
    return left - right || a.id.localeCompare(b.id);
  }).slice(0, 5);
  servers.forEach((server) => {
    const row = el("tr");
    row.addEventListener("click", () => {
      setView("servers");
      state.filter = "all";
      document.querySelectorAll("#serverFilters .seg").forEach((item) => {
        item.classList.toggle("active", item.dataset.filter === "all");
      });
      renderServerTable();
      selectServer(server.id);
    });
    row.appendChild(el("td", "server-name", server.id));
    row.appendChild(el("td", "muted", (server.clients || []).join(", ")));
    const stateCell = el("td");
    stateCell.appendChild(statePill(server));
    row.appendChild(stateCell);
    row.appendChild(el("td", "muted", server.transport));
    body.appendChild(row);
  });
}

function statePill(server) {
  const value = server.state === null || server.state === undefined ? "unchecked" : server.state;
  return el("span", `pill state-${value}`, value);
}

function filteredServers() {
  const query = state.query.trim().toLowerCase();
  return state.servers.filter((server) => {
    const matchesQuery = !query || [server.id, server.name, ...(server.clients || [])]
      .join(" ").toLowerCase().includes(query);
    if (!matchesQuery) return false;
    if (state.filter === "pinned") return server.pinned;
    if (state.filter === "unpinned") return !server.pinned;
    if (state.filter === "drift") return server.state === "drift";
    return true;
  });
}

function selectServer(id) {
  state.selectedServer = id;
  state.detailTab = "overview";
  document.querySelectorAll("#serverRows tr").forEach((row) => {
    row.classList.toggle("selected", row.dataset.id === id);
  });
  renderDetail();
}

function renderServerTable() {
  const body = $("serverRows");
  clear(body);
  const rows = filteredServers();
  $("serverCount").textContent = `${rows.length} of ${state.servers.length}`;
  $("serverEmpty").classList.toggle("hidden", rows.length > 0);

  rows.forEach((server) => {
    const row = el("tr");
    row.dataset.id = server.id;
    if (server.id === state.selectedServer) row.classList.add("selected");
    row.addEventListener("click", () => selectServer(server.id));

    const name = el("td", "server-name", server.id);
    const clients = el("td", "muted", (server.clients || []).join(", ") || server.id.split(":")[0]);
    const stateCell = el("td");
    stateCell.appendChild(statePill(server));
    const transport = el("td", "muted", server.transport || "unknown");
    row.append(name, clients, stateCell, transport);
    body.appendChild(row);
  });

  if (state.selectedServer && rows.some((server) => server.id === state.selectedServer)) {
    renderDetail();
  } else if (!rows.length) {
    state.selectedServer = null;
    renderDetail();
  }
}

function findSelectedServer() {
  return state.servers.find((server) => server.id === state.selectedServer) || null;
}

function kvRow(term, value) {
  const dt = el("dt", "", term);
  const dd = el("dd", "", value === null || value === undefined || value === "" ? "—" : value);
  return [dt, dd];
}

function renderDetail() {
  const host = $("serverDetail");
  clear(host);
  const server = findSelectedServer();
  if (!server) {
    const empty = el("div", "detail-empty");
    empty.appendChild(el("div", "empty-title", "Select a server"));
    empty.appendChild(el("div", "empty-copy", "Its tools, capabilities and findings will appear here."));
    host.appendChild(empty);
    return;
  }

  const head = el("div", "detail-head");
  const headRow = el("div", "detail-head-row");
  const titleWrap = el("div");
  titleWrap.appendChild(el("div", "detail-title", server.id));
  titleWrap.appendChild(el("div", "detail-sub", `${(server.clients || []).join(", ")} · ${server.transport}`));
  headRow.appendChild(titleWrap);
  headRow.appendChild(statePill(server));
  head.appendChild(headRow);

  const actions = el("div", "detail-actions");
  const pin = el("button", "btn ghost", "Pin");
  pin.type = "button";
  pin.addEventListener("click", () => startWrite("pin"));
  const approve = el("button", "btn ghost", server.pinned ? "Approve" : "Approve (pin first)");
  approve.type = "button";
  approve.disabled = !server.pinned;
  approve.addEventListener("click", () => startWrite("approve"));
  actions.append(pin, approve);
  head.appendChild(actions);
  host.appendChild(head);

  const tabs = el("div", "tabs");
  [["overview", "Overview"], ["tools", "Tools"], ["findings", "Findings"]].forEach(([key, label]) => {
    const tab = el("button", "tab" + (state.detailTab === key ? " active" : ""), label);
    tab.type = "button";
    tab.addEventListener("click", () => { state.detailTab = key; renderDetail(); });
    tabs.appendChild(tab);
  });
  host.appendChild(tabs);

  const body = el("div", "detail-body");
  if (state.detailTab === "overview") renderOverviewTab(body, server);
  if (state.detailTab === "tools") renderToolsTab(body, server);
  if (state.detailTab === "findings") renderFindingsTab(body, server);
  host.appendChild(body);
}

function renderOverviewTab(host, server) {
  const capabilities = server.capabilities || [];
  if (capabilities.length) {
    const capSection = el("div", "section-gap");
    capSection.appendChild(el("div", "mini-title", "Capabilities"));
    const chips = el("div", "chip-row");
    capabilities.forEach((cap) => {
      chips.appendChild(el("span", `pill risk-${cap.risk}`, `${cap.label} · ${cap.facet}`));
    });
    capSection.appendChild(chips);
    host.appendChild(capSection);
  }

  const kv = el("dl", "kv");
  const rows = [
    ["Pinned", server.pinned ? "yes" : "no"],
    ["Config", server.configPath],
    ["Artifact", `${server.artifact.kind} ${server.artifact.target}`.trim()],
    ["Artifact sha", server.artifact.sha256 || "unknown"],
    ["Tools", server.hasManifest ? `${server.tools.length} captured` : "not captured"],
    ["Tools sha", server.toolsHash || "—"],
    ["Probe error", server.probeError || "—"],
    ["Aliases", (server.aliases || []).join(", ")],
  ];
  rows.forEach(([term, value]) => {
    const [dt, dd] = kvRow(term, value);
    if (term === "Config" || term === "Artifact sha" || term === "Artifact" || term === "Tools sha") {
      dd.classList.add("mono");
    }
    kv.append(dt, dd);
  });
  host.appendChild(kv);

  if (!server.hasManifest) {
    const note = el("div", "no-findings",
      "Manifest not captured. Check probes pinned servers; pin captures the first manifest.");
    host.appendChild(note);
  }
}

function renderToolsTab(host, server) {
  if (!server.tools || !server.tools.length) {
    host.appendChild(el("div", "no-findings", "No tool manifest captured for this server."));
    return;
  }
  server.tools.forEach((tool) => {
    const item = el("div", "tool-item");
    item.appendChild(el("div", "tool-name", tool.name));
    if (tool.description) item.appendChild(el("div", "tool-desc", tool.description));
    if (tool.properties && tool.properties.length) {
      item.appendChild(el("div", "tool-meta", `parameters: ${tool.properties.join(", ")}`));
    }
    if (tool.capabilities && tool.capabilities.length) {
      const chips = el("div", "chip-row");
      tool.capabilities.forEach((cap) => {
        chips.appendChild(el("span", `pill risk-${cap.risk}`, `${cap.label} · ${cap.facet}`));
      });
      item.appendChild(chips);
    }
    if (tool.contentRisk && tool.contentRisk.severity) {
      item.appendChild(el("div", "tool-meta", `content risk: ${tool.contentRisk.severity}`));
      if (tool.contentRisk.summary.length) {
        const pre = el("pre", "evidence", tool.contentRisk.summary.join("\n"));
        item.appendChild(pre);
      }
    }
    host.appendChild(item);
  });
}

function renderFindingsTab(host, server) {
  if (!server.findings || !server.findings.length) {
    host.appendChild(el("div", "no-findings",
      server.state === null ? "Run Check to compare this server with the baseline." : "No findings."));
    return;
  }
  server.findings.forEach((finding) => {
    const item = el("div", `finding sev-${finding.severity}`);
    item.appendChild(el("div", "finding-title", `[${finding.severity}] ${finding.title}`));
    if (finding.detail) item.appendChild(el("div", "finding-detail", finding.detail));
    if (finding.evidence && finding.evidence.length) {
      item.appendChild(el("pre", "evidence", finding.evidence.join("\n")));
    }
    host.appendChild(item);
  });
}

function renderSources() {
  const body = $("sourceRows");
  if (!body) return;
  clear(body);
  $("sourceMeta").textContent = `${state.sources.length} source(s) · ${state.sources.filter((source) => source.custom).length} custom`;
  state.sources.forEach((source) => {
    const row = el("tr");
    row.dataset.id = source.id || "";
    if (source.id && source.id === state.selectedSource) row.classList.add("selected");
    row.appendChild(el("td", "", source.client));
    row.appendChild(el("td", "muted", source.scope));
    row.appendChild(el("td", "muted", source.origin));
    const status = !source.supported ? "unsupported" : source.exists ? "ok" : "missing";
    row.appendChild(el("td", "", status));
    row.appendChild(el("td", "path-cell", source.path));
    row.addEventListener("click", () => {
      state.selectedSource = source.id || null;
      renderSources();
      renderSourceDetail(source);
    });
    body.appendChild(row);
  });
  if (!state.sources.length) {
    $("sourceDetail").textContent = "No config sources found.";
  }
}

function renderSourceDetail(source) {
  const host = $("sourceDetail");
  const lines = [
    `${source.client} · ${source.scope} · ${source.origin}`,
    source.path,
    `format: ${source.format} · exists: ${source.exists ? "yes" : "no"} · supported: ${source.supported ? "yes" : "no"}`,
  ];
  if (source.note) lines.push(source.note);
  host.textContent = lines.join("\n");
}

function fillSettings() {
  if (!state.prefs) return;
  $("prefRoot").value = state.prefs.root || "";
  $("prefTimeout").value = state.prefs.timeout || 20;
  $("prefFailOn").value = state.prefs.failOn || "high";
  $("prefTheme").value = state.prefs.theme || "system";
  $("prefProject").checked = state.prefs.includeProject !== false;
  $("prefDedupe").checked = state.prefs.dedupe !== false;
}

function applyPayload(payload) {
  if (!payload) return;
  const previous = state.data || {};
  state.data = Object.assign({}, previous, payload);
  if (!payload.sources || payload.sources.length === 0) {
    state.data.sources = previous.sources || state.sources;
  }
  if (payload.servers) state.servers = payload.servers;
  if (payload.sources && payload.sources.length) state.sources = payload.sources;
  if (payload.stats) state.stats = payload.stats;
  if (payload.prefs) state.prefs = payload.prefs;
  if (payload.app && payload.app.version) {
    $("versionLabel").textContent = `pindrift ${payload.app.version}`;
    $("statusRight").textContent = `pindrift ${payload.app.version}`;
  }
  renderOverview();
  renderServerTable();
  renderSources();
  fillSettings();
  const errors = (payload.errors || []).filter((error) => error.level !== "info");
  showError(errors.map((error) => `${error.client}: ${error.message}`).join(" · "));
}

async function scan() {
  if (state.busy) return;
  clearError();
  busy("Scanning configuration sources", "No server is executed during a scan.");
  try {
    const payload = await api("scan");
    applyPayload(payload);
    addActivity(`Scanned ${state.servers.length} server(s)`, "ok");
    setStatus(`loaded ${state.servers.length} server(s)`, `pindrift ${state.data.app ? state.data.app.version : ""}`);
    toast("Scan complete");
  } catch (error) {
    showError(error.message);
    toast(error.message, true);
  } finally {
    hideBusy();
  }
}

async function pollJob(jobId, label) {
  let last = null;
  for (;;) {
    const job = await api("job_status", jobId);
    last = job;
    if (job.total > 0) busyProgress(job.done, job.total, job.current);
    else $("busyCopy").textContent = job.current || label;
    if (job.state === "done") return job.result;
    if (job.state === "failed") throw new Error(job.error ? job.error.message : `${label} failed`);
    await sleep(350);
  }
  return last;
}

async function check() {
  if (state.busy) return;
  clearError();
  busy("Checking against the baseline", "Only servers with a pin are probed.");
  try {
    const start = await api("start_check");
    const result = await pollJob(start.jobId, "Check");
    applyPayload(result);
    addActivity(
      `${result.stats.drift} drift · ${result.stats.ok} ok · ${result.stats.unknown} unknown`,
      result.stats.drift > 0 ? "bad" : "ok",
    );
    toast(`Check complete: ${result.stats.drift} drift, ${result.stats.unknown} unknown`);
    setStatus(`checked ${result.stats.total} target(s)`, `exit ${result.exitCode}`);
  } catch (error) {
    showError(error.message);
    toast(error.message, true);
  } finally {
    hideBusy();
  }
}

function openModal(builder) {
  const host = $("modalHost");
  clear(host);
  host.classList.remove("hidden");
  builder(host);
  const first = host.querySelector("button, input, select");
  if (first) first.focus();
}

function closeModal() {
  const host = $("modalHost");
  host.classList.add("hidden");
  clear(host);
}

function confirmWrite(mode) {
  const server = findSelectedServer();
  if (!server) {
    toast("Select a server first", true);
    return;
  }
  if (mode === "approve" && !server.pinned) {
    toast("Pin the server before approving a change", true);
    return;
  }
  const label = mode === "pin" ? "Pin server" : "Approve current state";
  openModal((host) => {
    const modal = el("div", "modal");
    modal.appendChild(el("div", "modal-title", label));
    const copy = mode === "pin"
      ? "This records the current state as trusted and probes the server once, which executes it."
      : "This replaces the existing pin with the current state. Review the findings before approving.";
    modal.appendChild(el("div", "modal-copy", copy));
    const list = el("ul", "modal-list");
    list.appendChild(el("li", "", `${server.id} (${server.transport})`));
    modal.appendChild(list);
    const actions = el("div", "modal-actions");
    const cancel = el("button", "btn ghost", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    const ok = el("button", "btn primary", label);
    ok.type = "button";
    ok.addEventListener("click", () => {
      closeModal();
      runWrite(mode, [server.id]);
    });
    actions.append(cancel, ok);
    modal.appendChild(actions);
    host.appendChild(modal);
  });
}

async function runWrite(mode, ids) {
  if (state.busy) return;
  clearError();
  busy(mode === "pin" ? "Pinning server(s)" : "Approving current state", "Probing selected servers once.");
  try {
    const start = await api("start_write", { ids, mode, confirm: true });
    const result = await pollJob(start.jobId, mode);
    hideBusy();
    await scan();
    addActivity(`${mode === "pin" ? "Pinned" : "Approved"} ${result.written.length} server(s)`, "ok");
    toast(`${mode === "pin" ? "Pinned" : "Approved"} ${result.written.length} server(s)`);
    setStatus(`wrote ${result.written.length} pin(s)`);
  } catch (error) {
    showError(error.message);
    toast(error.message, true);
  } finally {
    hideBusy();
  }
}

function startWrite(mode) {
  confirmWrite(mode);
}

function openSourceModal() {
  openModal((host) => {
    const modal = el("div", "modal");
    modal.appendChild(el("div", "modal-title", "Add config source"));
    modal.appendChild(el("div", "modal-copy",
      "Register a JSON, JSONC or TOML config for a client that is not built in. The path must be absolute."));
    const form = el("form", "modal-form");
    form.id = "sourceForm";

    function field(name, label, input) {
      const wrap = el("label");
      wrap.appendChild(el("span", "", label));
      wrap.appendChild(input);
      form.appendChild(wrap);
    }

    const client = el("input"); client.placeholder = "my-agent";
    field("client", "Client", client);
    const pathRow = el("div", "path-row");
    const pathInput = el("input"); pathInput.placeholder = "C:\\Users\\me\\.my-agent\\mcp.json";
    const browse = el("button", "btn ghost", "Browse"); browse.type = "button";
    browse.addEventListener("click", async () => {
      try {
        const result = await api("pick_file");
        if (result.path) pathInput.value = result.path;
      } catch (error) { toast(error.message, true); }
    });
    pathRow.append(pathInput, browse);
    field("path", "Config path", pathRow);
    const scope = el("select");
    ["user", "project"].forEach((value) => {
      const option = el("option", "", value); option.value = value; scope.appendChild(option);
    });
    field("scope", "Scope", scope);
    const format = el("select");
    ["json", "jsonc", "toml"].forEach((value) => {
      const option = el("option", "", value); option.value = value; format.appendChild(option);
    });
    field("format", "Format", format);
    const container = el("input"); container.placeholder = "mcpServers (optional)";
    field("container", "Container key", container);

    const actions = el("div", "modal-actions");
    const cancel = el("button", "btn ghost", "Cancel"); cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    const save = el("button", "btn primary", "Add source"); save.type = "submit";
    save.setAttribute("form", "sourceForm");
    actions.append(cancel, save);
    modal.appendChild(form);
    modal.appendChild(actions);
    host.appendChild(modal);

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const rows = await api("add_source", {
          client: client.value,
          path: pathInput.value,
          scope: scope.value,
          format: format.value,
          container: container.value || null,
        });
        state.sources = rows;
        renderSources();
        closeModal();
        toast("Source added");
        addActivity(`Added source ${client.value}`, "ok");
      } catch (error) {
        toast(error.message, true);
      }
    });
  });
}

async function removeSource() {
  const source = state.sources.find((item) => item.id && item.id === state.selectedSource);
  if (!source) {
    toast("Select a custom source first", true);
    return;
  }
  openModal((host) => {
    const modal = el("div", "modal");
    modal.appendChild(el("div", "modal-title", "Remove source"));
    modal.appendChild(el("div", "modal-copy", `Remove ${source.path} from the registry?`));
    const actions = el("div", "modal-actions");
    const cancel = el("button", "btn ghost", "Cancel"); cancel.type = "button";
    cancel.addEventListener("click", closeModal);
    const ok = el("button", "btn primary", "Remove"); ok.type = "button";
    ok.addEventListener("click", async () => {
      try {
        const rows = await api("remove_source", source.id);
        state.sources = rows;
        state.selectedSource = null;
        renderSources();
        closeModal();
        toast("Source removed");
      } catch (error) { toast(error.message, true); }
    });
    actions.append(cancel, ok);
    modal.appendChild(actions);
    host.appendChild(modal);
  });
}

async function testSource() {
  const source = state.sources.find((item) => item.id && item.id === state.selectedSource);
  if (!source) {
    toast("Select a custom source first", true);
    return;
  }
  try {
    const result = await api("test_source", source.id);
    openModal((host) => {
      const modal = el("div", "modal");
      modal.appendChild(el("div", "modal-title", "Source test"));
      modal.appendChild(el("div", "modal-copy", result.lines.join("\n")));
      const actions = el("div", "modal-actions");
      const close = el("button", "btn primary", "Close"); close.type = "button";
      close.addEventListener("click", closeModal);
      actions.appendChild(close);
      modal.appendChild(actions);
      host.appendChild(modal);
    });
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveSettings(event) {
  event.preventDefault();
  try {
    const result = await api("save_prefs", {
      root: $("prefRoot").value,
      timeout: Number($("prefTimeout").value),
      failOn: $("prefFailOn").value,
      theme: $("prefTheme").value,
      includeProject: $("prefProject").checked,
      dedupe: $("prefDedupe").checked,
    });
    state.prefs = result.prefs;
    applyTheme(state.prefs.theme);
    toast("Settings saved");
    addActivity("Updated workspace settings", "ok");
    await scan();
  } catch (error) {
    toast(error.message, true);
    showError(error.message);
  }
}

function updateSearch(value) {
  state.query = value;
  renderServerTable();
}

function bind() {
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.view));
  });
  document.querySelectorAll("[data-view-jump]").forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.viewJump));
  });
  document.querySelectorAll("[data-action]").forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.action === "check") check();
      if (button.dataset.action === "servers") setView("servers");
    });
  });
  $("scanBtn").addEventListener("click", scan);
  $("checkBtn").addEventListener("click", check);
  $("overviewCheck").addEventListener("click", check);
  $("searchInput").addEventListener("input", (event) => updateSearch(event.target.value));
  $("serverFilters").addEventListener("click", (event) => {
    const button = event.target.closest("[data-filter]");
    if (!button) return;
    state.filter = button.dataset.filter;
    document.querySelectorAll("#serverFilters .seg").forEach((item) => {
      item.classList.toggle("active", item === button);
    });
    renderServerTable();
  });
  $("addSourceBtn").addEventListener("click", openSourceModal);
  $("removeSourceBtn").addEventListener("click", removeSource);
  $("testSourceBtn").addEventListener("click", testSource);
  $("settingsForm").addEventListener("submit", saveSettings);
  $("resetSettings").addEventListener("click", () => { fillSettings(); applyTheme(state.prefs ? state.prefs.theme : "system"); });
  $("prefTheme").addEventListener("change", (event) => applyTheme(event.target.value));

  document.addEventListener("keydown", (event) => {
    const tag = event.target.tagName;
    const typing = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    if (event.key === "Escape") closeModal();
    if (!typing && event.key === "/") {
      event.preventDefault();
      $("searchInput").focus();
    }
    if (!typing && event.key === "c") check();
    if (!typing && event.key === "s") scan();
    if (!typing && event.key === "p") startWrite("pin");
    if (!typing && event.key === "a") startWrite("approve");
  });

  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (state.prefs && state.prefs.theme === "system") applyTheme("system");
    });
  }
}

async function boot() {
  bind();
  setStatus("Connecting to pindrift…");
  try {
    await apiReady();
    const payload = await api("bootstrap");
    applyPayload(payload);
    applyTheme(payload.prefs ? payload.prefs.theme : "system");
    addActivity("Loaded workspace", "ok");
    setStatus(`loaded ${state.servers.length} server(s)`);
    const errors = (payload.errors || []).filter((error) => error.level !== "info");
    if (errors.length) showError(errors.map((error) => `${error.client}: ${error.message}`).join(" · "));
  } catch (error) {
    showError(error.message);
    setStatus("Bridge unavailable");
    toast(error.message, true);
  }
}

boot();
