import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import { LanguageClient, State } from "vscode-languageclient/node";
import { Status } from "./format";

/** A row of hibou/findings (PROTOCOL.md). */
export interface PanelFinding {
  fingerprint: string;
  title: string;
  severity: string;
  status: string;
  accepted: boolean;
  type: string;
  rule?: string;
  scanner?: string;
  component?: string;
  package?: string;
  version?: string;
  advisoryId?: string;
  path?: string;
  uri?: string;
  range: { start: { line: number; character: number }; end: { line: number; character: number } };
  edited?: boolean;
  kev?: boolean;
  presence?: string;
  history?: boolean;
  commit?: string;
  cwes?: { id: number; name: string }[];
  webUrl: string;
}

interface Preset {
  id: string;
  name: string;
  query: string;
}

/** View options the user changes in the panel; kept per workspace. */
interface ViewState {
  tab: "code" | "dependencies" | "secrets";
  groupBy: "file" | "severity" | "rule";
  query: string;
  thisFile: boolean;
  hideUnconfirmed: boolean;
  collapsed: string[];
  /** Work tree shown; "" follows the active editor's repository, "*" shows
   * every repository of the workspace, grouped by repository. */
  root: string;
}

// Every repository by default, grouped by repository when there are several
// (nested checkouts); a single repository shows as a plain list.
const defaultView: ViewState = { tab: "code", groupBy: "file", query: "", thisFile: false, hideUnconfirmed: false, collapsed: [], root: "*" };
const stateKey = "hibou.panel.v2";

type FromWebview =
  | { type: "ready" }
  | { type: "open"; uri: string; line: number }
  | { type: "openWeb"; url: string }
  | { type: "setView"; patch: Partial<ViewState> }
  | { type: "refresh" }
  | { type: "command"; command: string }
  | { type: "cweSets" }
  | { type: "cweSearch"; id: number; query: string; roots?: boolean };

/**
 * The hibou side panel: overview (repository, scan, gate, severities), tabs,
 * the web UI's filter language and presets, and grouped findings. Filtering
 * by query runs on the server; tabs, grouping and toggles run in the view.
 */
export class FindingsPanel implements vscode.WebviewViewProvider, vscode.Disposable {
  static readonly viewType = "hibou.findings";

  private view: vscode.WebviewView | undefined;
  private state: ViewState;
  private findings: PanelFinding[] = [];
  /** Every finding, unfiltered: tab counts and "in this view" completion. */
  private all: PanelFinding[] = [];
  private error = "";
  private presets: Preset[] = [];
  private presetsError = "";
  private loading = false;
  /** Root the current findings were fetched for. */
  private loadedRoot = "";
  private timer: NodeJS.Timeout | undefined;
  private readonly subs: vscode.Disposable[] = [];

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly client: () => LanguageClient | undefined,
    private readonly status: () => Status | undefined,
    private readonly supports: (request: string) => boolean,
    private readonly statuses: () => Status[],
  ) {
    this.state = { ...defaultView, ...context.workspaceState.get<Partial<ViewState>>(stateKey, {}) };
    this.subs.push(
      // Switching to a file of another repository switches the panel to it.
      vscode.window.onDidChangeActiveTextEditor(() =>
        this.state.root !== "*" && (this.current()?.root ?? "") !== this.loadedRoot ? this.refresh(0) : this.post(),
      ),
      vscode.languages.onDidChangeDiagnostics(() => this.refresh(1500)),
    );
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    const media = vscode.Uri.joinPath(this.context.extensionUri, "media");
    const codicons = vscode.Uri.joinPath(this.context.extensionUri, "dist", "codicons");
    view.webview.options = { enableScripts: true, localResourceRoots: [media, codicons] };
    view.webview.html = this.html(view.webview, media, codicons);
    view.webview.onDidReceiveMessage((msg: FromWebview) => this.onMessage(msg), undefined, this.subs);
    view.onDidChangeVisibility(() => view.visible && this.refresh(0), undefined, this.subs);
  }

  /** Re-fetches findings (and presets) after delay ms; coalesces calls. */
  refresh(delay = 300): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.load(), delay);
  }

  /** The repository shown: the one chosen in the panel, else the active
   * editor's. A workspace can hold several (nested checkouts). */
  private current(): Status | undefined {
    if (this.state.root && this.state.root !== "*") {
      const chosen = this.statuses().find((s) => s.root === this.state.root);
      if (chosen) return chosen;
    }
    return this.status();
  }

  /** Re-renders without fetching (status or active editor changed). */
  post(): void {
    const status = this.current();
    const repos = this.statuses()
      .filter((s) => s.root)
      .map((s) => ({ root: s.root, label: s.repo ? `${s.repo.org}/${s.repo.repo}` : s.root.split(/[\\/]/).pop() || s.root, state: s.state }));
    void this.view?.webview.postMessage({
      type: "update",
      state: this.state,
      status,
      findings: this.findings,
      all: this.all,
      error: this.error,
      presets: this.presets,
      presetsError: this.presetsError,
      repos,
      followsEditor: !this.state.root,
      allRepos: this.state.root === "*",
      loading: this.loading,
      activeUri: vscode.window.activeTextEditor?.document.uri.toString() ?? "",
    });
  }

  private async load(): Promise<void> {
    const client = this.client();
    if (!this.view?.visible) return;
    if (!client || client.state !== State.Running) {
      this.findings = [];
      this.post();
      return;
    }
    this.loading = true;
    this.post();
    // "*": every repository (the language server's list is unscoped).
    const root = this.state.root === "*" ? "" : (this.current()?.root ?? "");
    this.loadedRoot = this.state.root === "*" ? "*" : root;
    try {
      const all = await client.sendRequest<{ findings: PanelFinding[] }>("hibou/findings", { root });
      this.all = all.findings ?? [];
      if (this.state.query) {
        const res = await client.sendRequest<{ findings: PanelFinding[]; error?: string }>("hibou/findings", { root, query: this.state.query });
        this.findings = res.findings ?? [];
        this.error = res.error ?? "";
      } else {
        this.findings = this.all;
        this.error = "";
      }
    } catch (err) {
      this.findings = [];
      this.error = err instanceof Error ? err.message : String(err);
    }
    if (this.supports("hibou/presets")) {
      try {
        const res = await client.sendRequest<{ presets: Preset[]; error?: string }>("hibou/presets");
        this.presets = res.presets ?? [];
        this.presetsError = res.error ?? "";
      } catch {
        this.presets = [];
      }
    }
    this.loading = false;
    this.post();
  }

  private async onMessage(msg: FromWebview): Promise<void> {
    switch (msg.type) {
      case "ready":
        this.post();
        this.refresh(0);
        return;
      case "open": {
        const pos = new vscode.Position(msg.line, 0);
        await vscode.window.showTextDocument(vscode.Uri.parse(msg.uri), { selection: new vscode.Range(pos, pos), preview: true });
        return;
      }
      case "openWeb":
        if (/^https?:\/\//.test(msg.url)) await vscode.env.openExternal(vscode.Uri.parse(msg.url));
        return;
      case "setView": {
        const queryChanged =
          (msg.patch.query !== undefined && msg.patch.query !== this.state.query) || (msg.patch.root !== undefined && msg.patch.root !== this.state.root);
        this.state = { ...this.state, ...msg.patch };
        await this.context.workspaceState.update(stateKey, this.state);
        if (queryChanged) this.refresh(0);
        else this.post();
        return;
      }
      case "refresh":
        await vscode.commands.executeCommand("hibou.refresh");
        this.refresh(0);
        return;
      case "cweSets":
      case "cweSearch": {
        const client = this.client();
        const request = msg.type === "cweSets" ? "hibou/cweSets" : "hibou/cweSearch";
        if (!client || client.state !== State.Running || !this.supports(request)) return;
        try {
          const data = await client.sendRequest(request, msg.type === "cweSearch" ? { query: msg.query, roots: msg.roots } : undefined);
          void this.view?.webview.postMessage({ type: "cwe", kind: msg.type, id: msg.type === "cweSearch" ? msg.id : 0, query: msg.type === "cweSearch" ? msg.query : "", data });
        } catch {
          // Completion is best effort.
        }
        return;
      }
      case "command":
        if (["hibou.signIn", "hibou.setServer", "hibou.openRepo", "hibou.checkStagedSecrets"].includes(msg.command)) {
          await vscode.commands.executeCommand(msg.command);
        }
        return;
    }
  }

  private html(webview: vscode.Webview, media: vscode.Uri, codicons: vscode.Uri): string {
    const nonce = randomBytes(18).toString("base64url");
    const uri = (base: vscode.Uri, file: string) => webview.asWebviewUri(vscode.Uri.joinPath(base, file));
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; font-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${uri(codicons, "codicon.css")}">
<link rel="stylesheet" href="${uri(media, "panel.css")}">
</head>
<body>
<div id="app"></div>
<script nonce="${nonce}" src="${uri(media, "panel.js")}"></script>
</body>
</html>`;
  }

  dispose(): void {
    clearTimeout(this.timer);
    for (const s of this.subs) s.dispose();
  }
}
