// Pure formatting of the language server's hibou/status payload.

export interface RepoRef {
  provider: string;
  org: string;
  repo: string;
}

export interface GateStatus {
  pr: string;
  state: string;
  passed: boolean;
  reasons?: string[];
  url?: string;
}

export interface Status {
  root: string;
  state: "unconfigured" | "signedOut" | "untracked" | "noSnapshot" | "ready" | "error";
  message?: string;
  server?: string;
  user?: string;
  repo?: RepoRef;
  webUrl?: string;
  branch?: string;
  snapshot?: { id: string; commit: string; ref: string; createdAt: string; atHead: boolean };
  counts?: Record<string, number>;
  truncated?: boolean;
  gate?: GateStatus;
}

const order = ["critical", "high", "medium", "low", "info", "unknown"];

/** "2 critical · 5 high" for the severities present, most severe first. */
export function countsLabel(counts: Record<string, number> | undefined, max = 2): string {
  if (!counts) return "";
  const parts = order.filter((s) => (counts[s] ?? 0) > 0).map((s) => `${counts[s]} ${s}`);
  if (parts.length === 0) return "no open findings";
  return parts.slice(0, max).join(" · ") + (parts.length > max ? " …" : "");
}

export interface StatusBarView {
  text: string;
  tooltip: string;
  warning: boolean;
}

/** Status bar text for the workspace the active editor belongs to. */
export function statusBar(st: Status | undefined): StatusBarView {
  if (!st) return { text: "$(shield) hibou", tooltip: "hibou is starting", warning: false };
  switch (st.state) {
    case "unconfigured":
      return { text: "$(shield) hibou: set server", tooltip: st.message ?? "Set the hibou server URL", warning: false };
    case "signedOut":
      return { text: "$(sign-in) hibou: sign in", tooltip: st.message ?? "Sign in to hibou", warning: true };
    case "untracked":
      return { text: "$(shield) hibou: not tracked", tooltip: st.message ?? "This repository is not tracked by hibou", warning: false };
    case "noSnapshot":
      return { text: "$(shield) hibou: no scan", tooltip: st.message ?? "No hibou scan for this commit", warning: false };
    case "error":
      return { text: "$(warning) hibou", tooltip: st.message ?? "hibou error", warning: true };
  }
  const parts = [`$(shield) ${countsLabel(st.counts)}`];
  if (st.gate) {
    if (st.gate.state === "pending") parts.push("$(sync) gate pending");
    else parts.push(st.gate.passed ? "$(check) gate" : "$(x) gate");
  }
  const lines = [`hibou — ${st.repo ? `${st.repo.org}/${st.repo.repo}` : st.root}`];
  if (st.snapshot) {
    const at = st.snapshot.atHead ? "this commit" : `ancestor ${st.snapshot.commit.slice(0, 8)} on ${st.snapshot.ref}`;
    lines.push(`Scan of ${at}, ${new Date(st.snapshot.createdAt).toLocaleString()}`);
  }
  if (st.truncated) lines.push("Only the first 10,000 findings are shown.");
  if (st.gate) {
    lines.push(`PR #${st.gate.pr}: gate ${st.gate.state}${st.gate.passed ? " (passed)" : ""}`);
    for (const r of st.gate.reasons ?? []) lines.push(`  • ${r}`);
  }
  if (st.user) lines.push(`Signed in as ${st.user}`);
  const failing = !!st.gate && st.gate.state !== "pending" && !st.gate.passed;
  return { text: parts.join("  "), tooltip: lines.join("\n"), warning: failing };
}

/** Picks the status of the workspace containing a file path. */
export function statusForPath(statuses: Status[], fsPath: string | undefined): Status | undefined {
  if (statuses.length === 0) return undefined;
  if (fsPath) {
    const norm = (p: string) => p.replace(/\\/g, "/").toLowerCase();
    const target = norm(fsPath);
    const match = statuses
      .filter((s) => s.root && (target === norm(s.root) || target.startsWith(norm(s.root) + "/")))
      .sort((a, b) => b.root.length - a.root.length)[0];
    if (match) return match;
  }
  return statuses[0];
}
