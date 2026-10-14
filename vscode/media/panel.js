// hibou side panel (webview). Plain DOM, no framework. Every server-provided
// string goes through textContent, never innerHTML.
(function () {
  const vscode = acquireVsCodeApi();
  const app = document.getElementById("app");
  const SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"];
  const PAGE = 200;

  // The web UI's findings filters (site/src/views/repo/VulnerabilitiesTab.vue,
  // lib/riskFilters.ts, lib/cweFilters.ts): same keys, values and wording.
  const FIELDS = [
    { key: "type", label: "Type", options: ["dependency", "sast", "secret", "malware", "dast", "container", "fuzzing", "manual", "generic"] },
    { key: "severity", label: "Severity", options: ["critical", "high", "medium", "unknown", "low", "info"] },
    { key: "status", label: "Status", options: ["detected", "resolved", "suppressed"] },
    { key: "acceptance", label: "Triage", options: ["open", "accepted", "risk_accepted", "false_positive", "disputed"] },
    { key: "presence", label: "Presence", options: ["reported", "not-rechecked", "unconfirmed"], description: "Whether the latest scan re-confirmed the finding" },
    { key: "tool", label: "Sources", dynamic: (f) => f.scanner },
    { key: "file", label: "File", dynamic: (f) => f.path, freeform: true },
    { key: "exploited", label: "Exploited", options: ["true", "false"], description: "Known-exploited dependency findings (CISA KEV / ENISA EUVD)" },
    { key: "cvss", label: "CVSS", description: "The CVSS score a finding uses: cvss:>=7, cvss:<4, cvss:none", suggestions: [[">=9", "critical"], [">=7", "high and above"], [">=4", "medium and above"], ["none", "unscored"]] },
    { key: "epss", label: "EPSS", description: "Probability of exploitation in the next 30 days (FIRST): epss:>=10%", suggestions: [[">=10%", "top exploitation risk"], [">=1%", "elevated"], ["none", "unscored"]] },
    { key: "epss-percentile", label: "EPSS percentile", description: "Rank among all scored CVEs: epss-percentile:>=95", suggestions: [[">=99", "top 1%"], [">=95", "top 5%"]] },
    { key: "cwe", label: "CWE", description: "Findings carrying a CWE: cwe:79, cwe:CWE-89, cwe:none", freeform: true },
    { key: "cwe-tree", label: "CWE + sub-types", description: "A CWE and its sub-types: cwe-tree:74 (Injection)", freeform: true },
    { key: "cwe-set", label: "CWE list", description: "Named CWE lists: CWE Top 25, OWASP Top 10", freeform: true },
    { key: "cwe-category", label: "CWE category", description: "MITRE View 1400 categories (Injection, Encryption, …)", freeform: true },
  ];
  const CONNECTIVES = [["AND", "both conditions"], ["OR", "either condition"], ["NOT", "exclude what follows"]];

  let data = null;
  let suggest = { items: [], index: 0, start: 0, end: 0 };
  const shown = {}; // group key -> rows shown
  let draftQuery = null; // text typed but not applied yet

  // CWE catalog answers (async): sets once, searches per query.
  let cweSets = null;
  const cweSearches = new Map(); // query -> entries
  let cweRequest = 0;

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (!msg) return;
    if (msg.type === "update") {
      data = msg;
      render();
    } else if (msg.type === "cwe") {
      if (msg.kind === "cweSets") cweSets = msg.data;
      else cweSearches.set(msg.query, (msg.data && msg.data.entries) || []);
      const input = document.getElementById("q");
      if (input && document.activeElement === input) {
        computeSuggestions(input);
        renderSuggestions();
      }
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

  // The tabs are shortcuts that write a type condition into the filter, so
  // the filter bar always shows what is applied (like the web UI's CWE page,
  // which opens the findings list with a query).
  const TAB_TERMS = {
    code: "-type:dependency,container,secret",
    dependencies: "type:dependency,container",
    secrets: "type:secret",
  };
  const TYPE_TERM = /(^|\s)-?type:\S+/g;

  function activeTab(query) {
    const terms = (query.match(TYPE_TERM) || []).map((t) => t.trim());
    if (terms.length !== 1) return "";
    return Object.keys(TAB_TERMS).find((k) => TAB_TERMS[k] === terms[0]) || "";
  }

  function withTab(query, tab) {
    const rest = query.replace(TYPE_TERM, " ").replace(/\s+/g, " ").trim();
    return tab ? `${TAB_TERMS[tab]}${rest ? " " + rest : ""}` : rest;
  }

  function visibleFindings() {
    const st = data.state;
    return data.findings.filter((f) => (!st.thisFile || (f.uri && f.uri === data.activeUri)) && (!st.hideUnconfirmed || !carried(f)));
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
    // Updates arrive while the user types: keep focus, caret and the open
    // suggestions across the redraw.
    const focused = document.activeElement;
    const active = focused && focused.id;
    const caret = active === "q" ? [focused.selectionStart, focused.selectionEnd] : null;
    app.replaceChildren(overview(), tabs(), toolbar(), body());
    if (active) {
      const again = document.getElementById(active);
      if (again) {
        again.focus();
        if (caret) {
          again.setSelectionRange(caret[0], caret[1]);
          renderSuggestions();
        }
      }
    }
  }

  // ---- overview -----------------------------------------------------------
  function overview() {
    const st = data.status;
    if (!st || st.state !== "ready") return emptyState(st);
    const all = (data.all || data.findings).filter((f) => !muted(f));
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
    const current = activeTab(data.state.query);
    const tab = (id, label, iconName) => {
      const n = (data.all || data.findings).filter((f) => tabOf(f) === id && !muted(f)).length;
      const on = current === id;
      return el(
        "button",
        {
          class: `tab${on ? " active" : ""}`,
          role: "tab",
          "aria-selected": on,
          title: on ? "Remove this filter" : `Filter: ${TAB_TERMS[id]}`,
          onclick: () => {
            draftQuery = null;
            setView({ query: withTab(data.state.query, on ? "" : id) });
          },
        },
        icon(iconName),
        ` ${label}`,
        el("span", { class: "tab-count", text: String(n) }),
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
      autocomplete: "off",
      role: "combobox",
      "aria-autocomplete": "list",
      "aria-expanded": suggest.items.length > 0,
      placeholder: "Filter: severity:high AND file:cmd/",
      value,
      title: "Same filter language as the hibou web UI. Enter to apply, Tab to complete.",
      oninput: (e) => {
        draftQuery = e.target.value;
        computeSuggestions(e.target);
        renderSuggestions();
      },
      onfocus: (e) => {
        computeSuggestions(e.target);
        renderSuggestions();
      },
      onblur: () => setTimeout(() => ((suggest.items = []), renderSuggestions()), 120),
      onkeydown: (e) => {
        const open = suggest.items.some(selectable);
        if (open && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
          e.preventDefault();
          const step = e.key === "ArrowDown" ? 1 : suggest.items.length - 1;
          let next = suggest.index;
          for (let i = 0; i < suggest.items.length; i++) {
            next = (next + step) % suggest.items.length;
            if (selectable(suggest.items[next])) break;
          }
          suggest.index = next;
          renderSuggestions();
        } else if (open && (e.key === "Tab" || (e.key === "Enter" && suggest.picked))) {
          e.preventDefault();
          accept(e.target, suggest.items[suggest.index]);
        } else if (e.key === "Enter") {
          suggest.items = [];
          setView({ query: e.target.value.trim() });
          draftQuery = null;
        } else if (e.key === "Escape") {
          if (open) {
            suggest.items = [];
            renderSuggestions();
          } else {
            draftQuery = null;
            setView({ query: "" });
          }
        }
        if (e.key === "ArrowDown" || e.key === "ArrowUp") suggest.picked = true;
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
      { class: "group", title: "Group by (dependencies always group by package)", onchange: (e) => setView({ groupBy: e.target.value }) },
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
        el("div", { id: "suggest", class: "suggest", role: "listbox" }),
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

  // ---- filter completion ----------------------------------------------------
  function wordAt(text, cursor) {
    let start = cursor;
    while (start > 0 && !/[\s()]/.test(text[start - 1])) start--;
    let end = cursor;
    while (end < text.length && !/[\s()]/.test(text[end])) end++;
    return { start, end, word: text.slice(start, cursor) };
  }

  function valueCounts(field) {
    const counts = new Map();
    for (const f of data.all || data.findings) {
      const v = field.dynamic(f);
      if (v) counts.set(v, (counts.get(v) || 0) + 1);
      if (field.key === "file" && v && v.includes("/")) {
        const dir = v.slice(0, v.lastIndexOf("/") + 1);
        counts.set(dir, (counts.get(dir) || 0) + 1);
      }
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  }

  // CWEs in the current findings, with their titles and counts.
  function cwesInView() {
    const byId = new Map();
    for (const f of data.all || data.findings) {
      for (const c of f.cwes || []) {
        const e = byId.get(c.id) || { id: c.id, name: c.name, count: 0 };
        e.count++;
        byId.set(c.id, e);
      }
    }
    return [...byId.values()].sort((a, b) => b.count - a.count || a.id - b.id);
  }

  function requestCWESearch(query, roots) {
    const key = roots ? "" : query;
    if (cweSearches.has(key)) return cweSearches.get(key);
    cweSearches.set(key, null); // pending
    send({ type: "cweSearch", id: ++cweRequest, query: key, roots });
    return null;
  }

  function computeSuggestions(input) {
    const text = input.value;
    const cursor = input.selectionStart ?? text.length;
    const { start, end, word } = wordAt(text, cursor);
    const items = [];
    const header = (label) => items.push({ kind: "header", label });
    const colon = word.indexOf(":");
    const negated = word.startsWith("-") ? "-" : "";
    if (colon > 0) {
      const key = word.slice(negated.length, colon).toLowerCase();
      const field = FIELDS.find((f) => f.key === key);
      const rawValue = word.slice(colon + 1);
      const comma = rawValue.lastIndexOf(",");
      const before = word.slice(0, colon + 1) + rawValue.slice(0, comma + 1);
      const prefix = rawValue.slice(comma + 1);
      const lower = prefix.toLowerCase();
      const value = (v, sub, count, iconName) => items.push({ insert: before + quote(v), label: v, sub, count, kind: "value", iconName });
      if (field) {
        if (!negated && !rawValue) items.push({ insert: `-${field.key}:`, label: `Exclude ${field.label.toLowerCase()}`, count: `-${field.key}:`, kind: "exclude" });
        if (field.key === "cwe" || field.key === "cwe-tree") {
          const id = lower.replace(/^cwe-/, "");
          const local = cwesInView().filter((c) => !id || String(c.id).startsWith(id) || c.name.toLowerCase().includes(lower));
          if (local.length) {
            header("In this view");
            for (const c of local.slice(0, 20)) value(String(c.id), c.name, String(c.count));
          }
          const remote = id ? requestCWESearch(id, false) : field.key === "cwe-tree" ? requestCWESearch("", true) : [];
          const seen = new Set(local.map((c) => c.id));
          const rest = (remote || []).filter((c) => !seen.has(c.id));
          if (rest.length) {
            header(id ? "CWE catalog" : "Start from a pillar");
            for (const c of rest.slice(0, 20)) value(String(c.id), c.name, c.descendants ? `${c.descendants} sub-types` : "");
          } else if (remote === null) {
            items.push({ kind: "hint", label: "Searching the CWE catalog…" });
          }
          if (!items.some((i) => i.kind === "value") && remote !== null && field.description) items.push({ kind: "hint", label: field.description });
        } else if (field.key === "cwe-set" || field.key === "cwe-category") {
          if (!cweSets) {
            send({ type: "cweSets" });
            items.push({ kind: "hint", label: "Loading CWE lists…" });
          } else {
            const list = field.key === "cwe-set" ? cweSets.sets || [] : cweSets.categories || [];
            for (const set of list) {
              if (!lower || set.slug.includes(lower) || set.name.toLowerCase().includes(lower)) value(set.slug, `${set.name} · ${set.member_count} CWEs`);
            }
          }
        } else {
          let options = [];
          if (field.options) options = field.options.map((o) => [o, "", ""]);
          if (field.suggestions) options = field.suggestions.map(([v, label]) => [v, label, ""]);
          if (field.dynamic) options = valueCounts(field).map(([v, n]) => [v, "", String(n)]);
          for (const [v, sub, count] of options) {
            if (v.toLowerCase().includes(lower) && v.toLowerCase() !== lower) value(v, sub, count);
          }
          if (!items.some((i) => i.kind === "value") && field.description) items.push({ kind: "hint", label: field.description });
        }
      }
    } else {
      const prefix = word.slice(negated.length).toLowerCase();
      for (const field of FIELDS) {
        if (field.key.startsWith(prefix) || (prefix && field.label.toLowerCase().startsWith(prefix))) {
          items.push({ insert: `${negated}${field.key}:`, label: `${field.key}:`, sub: field.label, kind: "key" });
        }
      }
      const before = text.slice(0, start).trim();
      if (before && !/\b(AND|OR|NOT)$/i.test(before) && !before.endsWith("(")) {
        for (const [c, sub] of CONNECTIVES) if (c.toLowerCase().startsWith(prefix)) items.push({ insert: c, label: c, sub, kind: "op" });
      }
      if (!prefix) items.splice(12);
    }
    const list = items.slice(0, 60);
    // Pre-select the first real completion, not "Exclude …": Tab must not
    // negate the filter by accident.
    let first = list.findIndex((i) => selectable(i) && i.kind !== "exclude");
    if (first < 0) first = list.findIndex(selectable);
    suggest = { items: list, index: Math.max(first, 0), start, end, picked: false };
  }

  const selectable = (item) => item.kind !== "header" && item.kind !== "hint";

  function quote(value) {
    return /[\s(),]/.test(value) ? JSON.stringify(value) : value;
  }

  function accept(input, item) {
    if (!item || !selectable(item)) return;
    const text = input.value;
    const tail = text.slice(suggest.end);
    // A field name (or its negation, "-cwe:") waits for its value: no space.
    const glue = item.kind === "key" || item.kind === "exclude" ? "" : tail.startsWith(" ") ? "" : " ";
    const next = text.slice(0, suggest.start) + item.insert + glue + tail;
    const cursor = suggest.start + item.insert.length + glue.length;
    input.value = next;
    draftQuery = next;
    input.setSelectionRange(cursor, cursor);
    computeSuggestions(input);
    renderSuggestions();
  }

  function renderSuggestions() {
    const box = document.getElementById("suggest");
    const input = document.getElementById("q");
    if (!box || !input) return;
    input.setAttribute("aria-expanded", String(suggest.items.length > 0));
    const iconFor = (item) =>
      item.kind === "exclude" ? icon("remove", "sg-exclude-icon") : item.kind === "key" ? icon("symbol-field") : item.kind === "op" ? icon("symbol-operator") : null;
    box.replaceChildren(
      ...suggest.items.map((item, i) => {
        if (item.kind === "header") return el("div", { class: "sg-header", role: "presentation", text: item.label });
        if (item.kind === "hint") return el("div", { class: "sg sg-hint", role: "presentation" }, icon("info"), el("span", { text: item.label }));
        return el(
          "div",
          {
            class: `sg sg-${item.kind}${i === suggest.index ? " active" : ""}`,
            role: "option",
            "aria-selected": i === suggest.index,
            onmousedown: (e) => {
              e.preventDefault();
              accept(input, item);
            },
          },
          iconFor(item),
          el("span", { class: "sg-text" }, el("span", { class: "sg-label", text: item.kind === "value" && /^\d+$/.test(item.label) && suggest.items.some((x) => x.kind === "header") ? `CWE-${item.label}` : item.label }), item.sub ? el("span", { class: "sg-sub", text: item.sub }) : null),
          item.count ? el("span", { class: "sg-count", text: item.count }) : null,
        );
      }),
    );
    box.classList.toggle("open", suggest.items.length > 0);
    const active = box.querySelector(".sg.active");
    if (active) active.scrollIntoView({ block: "nearest" });
  }

  // ---- list -----------------------------------------------------------------
  function body() {
    if (!data.status || data.status.state !== "ready") return el("span");
    const st = data.state;
    const list = visibleFindings();
    if (!list.length) {
      const why = st.query || st.thisFile || st.hideUnconfirmed ? "Nothing matches the filter." : "No open findings.";
      return el("section", { class: "empty small" }, icon("check", "big ok"), el("div", { class: "muted", text: why }));
    }
    const by = activeTab(st.query) === "dependencies" ? "package" : st.groupBy;
    const groups = groupFindings(list, by);
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
          if (!f.path && f.package) {
            // A dependency without a manifest location: group by package.
            key = `${f.package}@${f.version || ""}`;
            label = f.package;
            sub = f.version || "";
            iconName = "package";
            break;
          }
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
    const key = `${g.by}:${g.key}`;
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
    if (f.history) meta = (f.commit || "").slice(0, 7);
    else if (by === "package") meta = f.advisoryId || "";
    else if (by === "file") meta = f.uri ? `L${line}` : "";
    else meta = f.path ? `${f.path.split("/").pop()}${f.uri ? ":" + line : ""}` : f.component || "";
    // State as small icons (tooltip explains), so the title keeps the room.
    const marks = [];
    if (f.history) marks.push(["history", "mark-warn", `No longer in the code, still in git history (commit ${(f.commit || "").slice(0, 7)}): rotate the secret`]);
    if (f.status === "suppressed") marks.push(["eye-closed", "", "Suppressed in source"]);
    if (f.accepted) marks.push(["pass", "", "Accepted in hibou"]);
    if (carried(f)) marks.push(["unverified", "", "Not re-confirmed by the latest scan"]);
    if (f.edited && !f.history) marks.push(["diff-modified", "", "Code changed since the scan; may already be fixed"]);
    const open = () => (f.uri ? send({ type: "open", uri: f.uri, line: f.range.start.line }) : send({ type: "openWeb", url: f.webUrl }));
    return el(
      "div",
      {
        class: `item${muted(f) ? " muted" : ""}${carried(f) ? " carried" : ""}`,
        tabindex: "0",
        role: "button",
        title: [f.title, f.scanner && `Scanner: ${f.scanner}`, f.rule && `Rule: ${f.rule}`, f.component && `Package: ${f.component}`, f.path && `${f.path}${f.uri ? ":" + line : ""}`, ...marks.map((m) => m[2])].filter(Boolean).join("\n"),
        onclick: open,
        onkeydown: (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), open()),
      },
      el("span", { class: `dot sev-${f.severity}`, title: f.severity, role: "img", "aria-label": f.severity }),
      el("span", { class: "title", text: f.title || f.rule || f.advisoryId || "finding" }),
      f.kev ? el("span", { class: "tag tag-kev", title: "Known exploited vulnerability (CISA KEV)", text: "KEV" }) : null,
      marks.length ? el("span", { class: "marks" }, marks.map(([name, cls, title]) => el("span", { class: `codicon codicon-${name} mark ${cls}`, title, "aria-label": title, role: "img" }))) : null,
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
