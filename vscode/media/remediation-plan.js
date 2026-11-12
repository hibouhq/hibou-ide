(() => {
  const vscode = acquireVsCodeApi();
  const $ = (id) => document.getElementById(id);
  let prepared;
  let busy = false;
  let completed = false;
  let needsRevision = false;
  let page = 0;
  const pageSize = 40;
  const saved = vscode.getState() || {};
  const choices = new Map(Array.isArray(saved.choices) ? saved.choices : []);
  const selected = new Set();
  const keyOf = (unit, pkg) => `${unit.id}\0${pkg.name}`;
  const save = () => vscode.setState({ choices: [...choices] });
  const clearError = () => { $("error").hidden = true; $("error").textContent = ""; };
  const setError = (text) => { $("error").textContent = text; $("error").hidden = false; $("error").focus(); };
  function controls() {
    $("generate").disabled = busy || completed || needsRevision || selected.size === 0;
    $("revise").hidden = !(completed || needsRevision);
    $("revise").disabled = busy;
    $("review").hidden = !completed;
    $("review").disabled = busy;
    $("upgrade-level").disabled = busy || completed || needsRevision;
    $("reset").disabled = busy || completed || needsRevision;
    $("major-warning").hidden = $("upgrade-level").value !== "major";
    document.querySelectorAll(".module input").forEach((input) => { input.disabled = busy || completed || needsRevision; });
  }
  function renderRows() {
    if (!prepared) return;
    const filter = $("filter").value.trim().toLowerCase();
    const rows = prepared.units.flatMap((unit) => (unit.direct_packages || []).map((pkg) => ({ unit, pkg })))
      .filter(({ unit, pkg }) => selected.has(unit.id) && `${pkg.name} ${unit.manifest}`.toLowerCase().includes(filter));
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    page = Math.max(0, Math.min(page, pages - 1));
    const body = $("versions");
    body.replaceChildren();
    for (const { unit, pkg } of rows.slice(page * pageSize, (page + 1) * pageSize)) {
      const key = keyOf(unit, pkg);
      const choice = choices.get(key) || { mode: "automatic", version: "", allow_prerelease: false };
      const tr = document.createElement("tr");
      const identity = document.createElement("td");
      const name = document.createElement("code"); name.textContent = pkg.name;
      const module = document.createElement("small"); module.textContent = unit.manifest;
      identity.append(name, module);
      const current = document.createElement("td"); current.textContent = pkg.version;
      if (pkg.declared) { const declaration = document.createElement("small"); declaration.className = "row-help"; declaration.textContent = `Declared: ${pkg.declared}`; current.append(declaration); }
      const modeCell = document.createElement("td");
      const mode = document.createElement("select");
      mode.setAttribute("aria-label", `Version selection for ${pkg.name} in ${unit.manifest}`);
      for (const [value, label] of [["automatic", "Automatic"], ["gossip", "Suggested by deps.dev"], ["exact", "Exact version"]]) {
        const option = document.createElement("option"); option.value = value; option.textContent = label;
        option.disabled = (value !== "automatic" && pkg.can_select_version === false) || (value === "gossip" && !pkg.recommended_version);
        mode.append(option);
      }
      mode.value = choice.mode; mode.disabled = busy || completed || needsRevision;
      modeCell.append(mode);
      const target = document.createElement("td");
      const input = document.createElement("input"); input.type = "text";
      input.setAttribute("aria-label", `Exact target version for ${pkg.name} in ${unit.manifest}`);
      input.value = choice.mode === "gossip" ? pkg.recommended_version || "" : choice.version;
      input.placeholder = "e.g. 1.2.3";
      input.hidden = choice.mode === "automatic";
      input.readOnly = choice.mode === "gossip";
      input.disabled = busy || completed || needsRevision;
      const help = document.createElement("small"); help.className = "row-help";
      help.textContent = choice.mode === "automatic" ? "Resolved during generation; not necessarily the smallest or latest version."
        : choice.mode === "gossip" ? "Suggestion only. Project compatibility and policy are checked during generation."
        : "One published version. No silent substitution; range/tag inputs are not supported.";
      if (pkg.can_select_version === false) help.textContent = "This declaration uses a complex range. Only Automatic is supported for this dependency.";
      if (choice.mode === "gossip" && pkg.recommendation_fetched_at) help.textContent += ` Fetched ${new Date(pkg.recommendation_fetched_at).toLocaleString()}.`;
      const preLabel = document.createElement("label"); preLabel.className = "prerelease";
      const pre = document.createElement("input"); pre.type = "checkbox"; pre.checked = choice.allow_prerelease;
      pre.disabled = busy || completed || needsRevision;
      preLabel.append(pre, document.createTextNode(" Allow a prerelease target"));
      preLabel.hidden = choice.mode === "automatic";
      target.append(input, help, preLabel);
      const update = () => { choices.set(key, { mode: mode.value, version: mode.value === "gossip" ? pkg.recommended_version : input.value, allow_prerelease: pre.checked }); save(); };
      mode.addEventListener("change", () => { update(); renderRows(); });
      input.addEventListener("input", update);
      pre.addEventListener("change", update);
      tr.append(identity, current, modeCell, target);
      body.append(tr);
    }
    if (rows.length === 0) {
      const tr = document.createElement("tr"); const td = document.createElement("td"); td.colSpan = 4;
      td.textContent = "No matching direct dependencies. Automatic transitive remediation still applies to selected modules."; tr.append(td); body.append(tr);
    }
    $("page-label").textContent = `${rows.length} direct dependencies · page ${page + 1} of ${pages}`;
    $("previous").disabled = page === 0; $("next").disabled = page + 1 >= pages;
  }
  function renderPrepared(data, resetSelection) {
    prepared = data;
    $("root").textContent = data.root; $("commit").textContent = data.base_sha;
    $("toolchain").textContent = `npm ${data.manager_version} · Node ${data.runtime_version} · local tooling`;
    $("tool-path").textContent = data.manager_path;
    if (resetSelection) { selected.clear(); data.units.forEach((unit) => selected.add(unit.id)); }
    const modules = $("modules"); modules.replaceChildren();
    for (const unit of data.units) {
      const label = document.createElement("label"); label.className = "module";
      const input = document.createElement("input"); input.type = "checkbox"; input.checked = selected.has(unit.id);
      const detail = document.createElement("span"); const code = document.createElement("code"); code.textContent = unit.manifest;
      const advisory = document.createElement("small"); advisory.textContent = `${unit.vulns.length} advisory ID(s): ${unit.vulns.join(", ")}`;
      detail.append(code, advisory); label.append(input, detail);
      input.addEventListener("change", () => { if (input.checked) selected.add(unit.id); else selected.delete(unit.id); controls(); renderRows(); });
      modules.append(label);
    }
    const unavailable = $("unavailable"); unavailable.replaceChildren();
    for (const explanation of data.unavailable) { const li = document.createElement("li"); li.textContent = explanation; unavailable.append(li); }
    $("unavailable-block").hidden = data.unavailable.length === 0;
    controls(); renderRows();
  }
  $("filter").addEventListener("input", () => { page = 0; renderRows(); });
  $("previous").addEventListener("click", () => { page--; renderRows(); });
  $("next").addEventListener("click", () => { page++; renderRows(); });
  $("upgrade-level").addEventListener("change", controls);
  $("reset").addEventListener("click", () => { choices.clear(); save(); renderRows(); });
  $("revise").addEventListener("click", () => vscode.postMessage({ type: "revise" }));
  $("review").addEventListener("click", () => vscode.postMessage({ type: "review" }));
  $("generate").addEventListener("click", () => {
    clearError();
    if ($("upgrade-level").value === "major" && !$("allow-major").checked) { setError("Acknowledge major upgrades before generating."); return; }
    const version_targets = Object.create(null);
    for (const unit of prepared.units) {
      if (!selected.has(unit.id)) continue;
      for (const pkg of unit.direct_packages || []) {
        const choice = choices.get(keyOf(unit, pkg));
        if (!choice || choice.mode === "automatic") continue;
        const version = (choice.mode === "gossip" ? pkg.recommended_version : choice.version || "").trim();
        if (!version) { setError(`Enter a target version for ${pkg.name}.`); return; }
        (version_targets[unit.id] ||= []).push({ name: pkg.name, mode: choice.mode, version, allow_prerelease: choice.allow_prerelease });
      }
    }
    vscode.postMessage({ type: "generate", selection: { unit_ids: [...selected], version_targets, upgrade_level: $("upgrade-level").value, allow_major: $("allow-major").checked } });
  });
  window.addEventListener("message", ({ data }) => {
    if (data.type === "prepared") renderPrepared(data.prepared, true);
    if (data.type === "busy") { busy = true; clearError(); $("status").textContent = data.message; }
    if (data.type === "error") { busy = false; needsRevision = true; setError(`${data.message}\nRevise choices to create a new draft. Close and prepare again to refresh source or suggestions.`); $("status").textContent = "No patch is ready from this generation."; }
    if (data.type === "readyArtifact") { busy = false; completed = true; $("status").textContent = "Patch generated. Review the diff before applying; nothing has been applied automatically."; }
    if (data.type === "reviewError") { busy = false; completed = true; setError(data.message); $("status").textContent = "Patch is still ready. Review the local state before retrying apply/export."; }
    if (data.type === "revised") { busy = false; completed = false; needsRevision = false; clearError(); renderPrepared(data.prepared, false); $("status").textContent = "New draft at the same committed base. Choices will be revalidated during generation."; }
    controls(); renderRows();
  });
  vscode.postMessage({ type: "ready" });
})();
