// hibou side panel (webview). Plain DOM, no framework. Every server-provided
// string goes through textContent, never innerHTML.
(function () {
  const vscode = acquireVsCodeApi();
  const app = document.getElementById("app");
  const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
  const PAGE = 200;

  let data = null;
  const shown = {}; // group key -> rows shown
  let draftQuery = null; // text typed but not applied yet

  window.addEventListener("message", (event) => {
    if (event.data && event.data.type === "update") {
      data = event.data;
      render();
    }
  });
  vscode.postMessage({ type: "ready" });

  function send(msg) {
    vscode.postMessage(msg);
  }
  function setView(patch) {
    send({ type: "setView", patch });
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "style") Object.assign(node.style, v); // CSSOM: allowed by the CSP, unlike style="" attributes
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v === true ? "" : String(v));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }
  const icon = (name, cls) => el("span", { class: `codicon codicon-${name}${cls ? " " + cls : ""}`, "aria-hidden": "true" });

  function tabOf(f) {
    if (f.type === "dependency" || f.type === "container") return "dependencies";
    if (f.type === "secret") return "secrets";
    return "code";
  }
  const carried = (f) => f.presence && f.presence !== "reported";
  const muted = (f) => f.status === "suppressed" || f.accepted;

  function filtered(tab) {
    const st = data.state;
    return data.findings.filter(
      (f) =>
        tabOf(f) === tab &&
        (!st.thisFile || (f.uri && f.uri === data.activeUri)) &&
        (!st.hideUnconfirmed || !carried(f)),
    );
  }

  function counts(list) {
    const c = {};
    for (const f of list) if (!muted(f)) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }

  function sevBadges(list) {
    const c = counts(list);
    return el(
      "span",
      { class: "badges" },
      SEVERITIES.filter((s) => c[s]).map((s) => el("span", { class: `badge sev-${s}`, title: `${c[s]} ${s}`, text: String(c[s]) })),
    );
  }

  function render() {
    if (!data) return;
    const active = document.activeElement && document.activeElement.id;
    app.replaceChildren(overview(), tabs(), toolbar(), body());
    if (active) {
      const again = document.getElementById(active);
      if (again) again.focus();
    }
  }

  // ---- overview -----------------------------------------------------------
  function overview() {
    const st = data.status;
    if (!st || st.state !== "ready") return emptyState(st);
    const all = data.findings.filter((f) => !muted(f));
    const c = counts(all);
    const total = Object.values(c).reduce((a, b) => a + b, 0);
    const repo = st.repo ? `${st.repo.org}/${st.repo.repo}` : "";
    const snap = st.snapshot;
    let scan = "";
    if (snap) {
      scan = snap.atHead ? "scan of this commit" : `scan of ${snap.commit.slice(0, 7)} on ${snap.ref}`;
      scan += " · " + ago(snap.createdAt);
    }
    const gate = st.gate
      ? el(
          "button",
          {
            class: `gate gate-${st.gate.state === "pending" ? "pending" : st.gate.passed ? "pass" : "fail"}`,
            title: (st.gate.reasons || []).join("\n") || "Open the gate in hibou",
            onclick: () => st.gate.url && send({ type: "openWeb", url: st.gate.url }),
          },
          icon(st.gate.state === "pending" ? "sync" : st.gate.passed ? "pass" : "error"),
          ` PR #${st.gate.pr} gate ${st.gate.state === "pending" ? "pending" : st.gate.passed ? "passed" : "failed"}`,
        )
      : null;
    return el(
      "section",
      { class: "overview" },
      el(
        "div",
        { class: "repo-line" },
        icon("repo"),
        el("span", { class: "repo", text: repo }),
        st.branch ? el("span", { class: "branch" }, icon("git-branch"), st.branch) : null,
        el("span", { class: "spacer" }),
        el("button", { class: "icon-btn", title: "Open in hibou", onclick: () => send({ type: "command", command: "hibou.openRepo" }) }, icon("link-external")),
        el("button", { class: "icon-btn", title: "Refresh", onclick: () => send({ type: "refresh" }) }, icon(data.loading ? "loading codicon-modifier-spin" : "refresh")),
      ),
      el("div", { class: "scan", text: scan }),
      gate,
      el(
        "div",
        { class: "sevbar", title: total ? "" : "No open findings" },
        total
          ? SEVERITIES.filter((s) => c[s]).map((s) => el("span", { class: `seg sev-${s}`, style: { flexGrow: String(c[s]) }, title: `${c[s]} ${s}` }))
          : el("span", { class: "seg seg-empty" }),
      ),
      el(
        "div",
        { class: "legend" },
        total
          ? SEVERITIES.filter((s) => c[s]).map((s) => el("span", { class: "legend-item" }, el("span", { class: `dot sev-${s}` }), `${c[s]} ${s}`))
          : el("span", { class: "muted", text: "No open findings in this scan" }),
      ),
    );
  }

  function emptyState(st) {
    const state = st ? st.state : "starting";
    const box = (iconName, title, detail, ...actions) =>
      el("section", { class: "empty" }, icon(iconName, "big"), el("div", { class: "empty-title", text: title }), detail ? el("div", { class: "muted", text: detail }) : null, el("div", { class: "actions" }, actions));
    const btn = (label, command, primary) => el("button", { class: primary ? "btn primary" : "btn", onclick: () => send({ type: "command", command }) }, label);
    switch (state) {
      case "unconfigured":
        return box("plug", "Connect to hibou", "Set your hibou server to see security findings in your code.", btn("Set server URL", "hibou.setServer", true));
      case "signedOut":
        return box("account", "Sign in to hibou", st && st.message, btn("Sign in", "hibou.signIn", true));
      case "untracked":
        return box("circle-slash", "Not tracked by hibou", st && st.message);
      case "noSnapshot":
        return box("history", "No scan yet", st && st.message);
      case "error":
        return box("warning", "hibou is unavailable", st && st.message, btn("Set server URL", "hibou.setServer"));
      default:
        return box("loading codicon-modifier-spin", "Starting…", "");
    }
  }

  // ---- tabs and toolbar ---------------------------------------------------
  function tabs() {
    if (!data.status || data.status.state !== "ready") return el("span");
    const st = data.state;
    const tab = (id, label, iconName) => {
      const list = filtered(id).filter((f) => !muted(f));
      return el(
        "button",
        { class: `tab${st.tab === id ? " active" : ""}`, role: "tab", "aria-selected": st.tab === id, onclick: () => setView({ tab: id }) },
        icon(iconName),
        ` ${label}`,
        el("span", { class: "tab-count", text: String(list.length) }),
      );
    };
    return el("nav", { class: "tabs", role: "tablist" }, tab("code", "Code", "code"), tab("dependencies", "Dependencies", "package"), tab("secrets", "Secrets", "key"));
  }

  function toolbar() {
    if (!data.status || data.status.state !== "ready") return el("span");
    const st = data.state;
    const value = draftQuery !== null ? draftQuery : st.query;
    const input = el("input", {
      id: "q",
      type: "text",
      spellcheck: "false",
      placeholder: "Filter: severity:high AND file:cmd/",
      value,
      title: "Same filter language as the hibou web UI. Enter to apply.",
      oninput: (e) => (draftQuery = e.target.value),
      onkeydown: (e) => {
        if (e.key === "Enter") {
          setView({ query: e.target.value.trim() });
          draftQuery = null;
        } else if (e.key === "Escape") {
          draftQuery = null;
          setView({ query: "" });
        }
      },
    });
    const presets = el(
      "select",
      {
        class: "presets",
        title: data.presetsError || "Your hibou search presets",
        disabled: !data.presets.length,
        onchange: (e) => {
          if (e.target.value) {
            draftQuery = null;
            setView({ query: e.target.value });
          }
        },
      },
      el("option", { value: "", text: data.presets.length ? "Presets" : "No presets" }),
      data.presets.map((p) => el("option", { value: p.query, title: p.query, selected: p.query === st.query, text: p.name })),
    );
    const chip = (label, on, iconName, patch, title) =>
      el("button", { class: `chip${on ? " on" : ""}`, title, "aria-pressed": on, onclick: () => setView(patch) }, icon(iconName), ` ${label}`);
    const group = el(
      "select",
      { class: "group", title: "Group by", disabled: st.tab === "dependencies", onchange: (e) => setView({ groupBy: e.target.value }) },
      [
        ["file", "By file"],
        ["severity", "By severity"],
        ["rule", "By rule"],
      ].map(([v, label]) => el("option", { value: v, selected: st.groupBy === v, text: label })),
    );
    return el(
      "section",
      { class: "toolbar" },
      el(
        "div",
        { class: "search" },
        icon("filter"),
        input,
        st.query ? el("button", { class: "icon-btn", title: "Clear filter", onclick: () => ((draftQuery = null), setView({ query: "" })) }, icon("close")) : null,
      ),
      data.error ? el("div", { class: "error" }, icon("error"), " ", data.error) : null,
      el(
        "div",
        { class: "row" },
        presets,
        group,
        chip("This file", st.thisFile, "file", { thisFile: !st.thisFile }, "Only findings in the active editor's file"),
        chip("Re-confirmed only", st.hideUnconfirmed, "eye-closed", { hideUnconfirmed: !st.hideUnconfirmed }, "Hide findings the latest scan did not re-confirm"),
      ),
    );
  }

  // ---- list -----------------------------------------------------------------
  function body() {
    if (!data.status || data.status.state !== "ready") return el("span");
    const st = data.state;
    const list = filtered(st.tab);
    if (!list.length) {
      const why = st.query || st.thisFile || st.hideUnconfirmed ? "Nothing matches the filter." : st.tab === "code" ? "No code findings." : `No ${st.tab}.`;
      return el("section", { class: "empty small" }, icon("check", "big ok"), el("div", { class: "muted", text: why }));
    }
    const groups = groupFindings(list, st.tab === "dependencies" ? "package" : st.groupBy);
    return el("section", { class: "list" }, groups.map((g) => groupNode(g)));
  }

  function groupFindings(list, by) {
    const map = new Map();
    for (const f of list) {
      let key, label, iconName, sub;
      switch (by) {
        case "package":
          key = `${f.package || f.component || "?"}@${f.version || ""}`;
          label = f.package || f.component || "Unknown package";
          sub = f.version || "";
          iconName = "package";
          break;
        case "severity":
          key = f.severity;
          label = f.severity;
          iconName = "circle-filled";
          break;
        case "rule":
          key = `${f.scanner || ""}|${f.rule || f.advisoryId || f.title}`;
          label = f.rule || f.advisoryId || f.title;
          sub = f.scanner || "";
          iconName = "symbol-ruler";
          break;
        default:
          key = f.path || "(no file)";
          label = (f.path || "(no file)").split("/").pop();
          sub = f.path && f.path.includes("/") ? f.path.slice(0, f.path.lastIndexOf("/")) : "";
          iconName = "file";
      }
      if (!map.has(key)) map.set(key, { key, label, sub, iconName, by, items: [] });
      map.get(key).items.push(f);
    }
    const rank = (g) => Math.min(...g.items.map((f) => (muted(f) ? 99 : SEVERITIES.indexOf(f.severity))));
    return [...map.values()].sort((a, b) => (by === "severity" ? SEVERITIES.indexOf(a.key) - SEVERITIES.indexOf(b.key) : rank(a) - rank(b) || b.items.length - a.items.length || a.label.localeCompare(b.label)));
  }

  function groupNode(g) {
    const st = data.state;
    const key = `${st.tab}:${g.by}:${g.key}`;
    const collapsed = st.collapsed.includes(key);
    const toggle = () => setView({ collapsed: collapsed ? st.collapsed.filter((k) => k !== key) : [...st.collapsed, key] });
    const limit = shown[key] || PAGE;
    const items = g.items.slice().sort((a, b) => (muted(a) - muted(b)) || SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.range.start.line - b.range.start.line);
    return el(
      "div",
      { class: "group" },
      el(
        "button",
        { class: "group-head", "aria-expanded": !collapsed, onclick: toggle, title: g.by === "file" ? g.key : g.label },
        icon(collapsed ? "chevron-right" : "chevron-down", "chev"),
        g.by === "severity" ? el("span", { class: `dot sev-${g.key}` }) : icon(g.iconName),
        el("span", { class: "group-label", text: g.label }),
        g.sub ? el("span", { class: "group-sub", text: g.sub }) : null,
        el("span", { class: "spacer" }),
        sevBadges(g.items),
      ),
      collapsed
        ? null
        : el(
            "div",
            { class: "rows" },
            items.slice(0, limit).map((f) => row(f, g.by)),
            items.length > limit
              ? el("button", { class: "more", onclick: () => ((shown[key] = limit + PAGE), render()) }, `Show ${Math.min(PAGE, items.length - limit)} more of ${items.length - limit}`)
              : null,
          ),
    );
  }

  function row(f, by) {
    const line = f.range.start.line + 1;
    let meta;
    if (f.history) meta = `commit ${(f.commit || "").slice(0, 7)}`;
    else if (by === "package") meta = f.advisoryId || "";
    else if (by === "file") meta = [f.rule, f.uri ? `L${line}` : ""].filter(Boolean).join(" · ");
    else meta = [f.path ? `${f.path.split("/").pop()}${f.uri ? ":" + line : ""}` : f.component].filter(Boolean).join(" · ");
    const tags = [];
    if (f.kev) tags.push(["kev", "Known exploited vulnerability (CISA KEV)"]);
    if (f.history) tags.push(["history", `No longer in the code, still in git history (commit ${(f.commit || "").slice(0, 7)}): rotate the secret`]);
    if (f.status === "suppressed") tags.push(["suppressed", "Suppressed in source"]);
    if (f.accepted) tags.push(["accepted", "Accepted in hibou"]);
    if (carried(f)) tags.push(["unconfirmed", "Not re-confirmed by the latest scan"]);
    if (f.edited) tags.push(["changed", "Code changed since the scan"]);
    const open = () => (f.uri ? send({ type: "open", uri: f.uri, line: f.range.start.line }) : send({ type: "openWeb", url: f.webUrl }));
    return el(
      "div",
      {
        class: `item${muted(f) ? " muted" : ""}${carried(f) ? " carried" : ""}`,
        tabindex: "0",
        role: "button",
        title: [f.title, f.scanner && `Scanner: ${f.scanner}`, f.rule && `Rule: ${f.rule}`, f.component && `Package: ${f.component}`, ...tags.map((t) => t[1])].filter(Boolean).join("\n"),
        onclick: open,
        onkeydown: (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), open()),
      },
      el("span", { class: `dot sev-${f.severity}`, title: f.severity, role: "img", "aria-label": f.severity }),
      el("span", { class: "title", text: f.title || f.rule || f.advisoryId || "finding" }),
      tags.map(([t, title]) => el("span", { class: `tag tag-${t}`, title, text: t })),
      el("span", { class: "meta", text: meta }),
      el(
        "button",
        { class: "icon-btn row-action", title: "Open in hibou", onclick: (e) => (e.stopPropagation(), send({ type: "openWeb", url: f.webUrl })) },
        icon("link-external"),
      ),
    );
  }

  function ago(iso) {
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (!isFinite(s)) return "";
    if (s < 90) return "just now";
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  }
})();
