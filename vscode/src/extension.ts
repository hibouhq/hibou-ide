import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as vscode from "vscode";
import { LanguageClient, LanguageClientOptions, ResponseError, ServerOptions, State, WorkspaceEdit } from "vscode-languageclient/node";
import { resolveBinary } from "./binary";
import { Status, statusBar, statusForPath } from "./format";
import { isInsecureRemote, normalizeServer } from "./platform";

/** JSON-RPC error the language server returns when the hibou server predates
 * device login (ADR-043): fall back to pasting a token. */
const loginUnsupported = -32901;

/** Highest hibou/* protocol version this extension understands. `hibou lsp`
 * ships with each hibou release while the extension updates from the stores,
 * so it must cope with older and newer servers (PROTOCOL.md). */
export const supportedProtocol = 1;

interface PanelFinding {
  fingerprint: string;
  title: string;
  severity: string;
  status: string;
  accepted: boolean;
  type: string;
  rule?: string;
  scanner?: string;
  component?: string;
  path?: string;
  uri?: string;
  range: { start: { line: number; character: number }; end: { line: number; character: number } };
  edited?: boolean;
  kev?: boolean;
  webUrl: string;
}

let ext: Extension | undefined;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  ext = new Extension(context);
  await ext.start();
}

export async function deactivate(): Promise<void> {
  await ext?.stop();
}

class Extension {
  private client: LanguageClient | undefined;
  private server: string | undefined;
  private statuses: Status[] = [];
  private readonly log: vscode.LogOutputChannel;
  private readonly statusItem: vscode.StatusBarItem;
  private readonly tree: FindingsTree;
  private readonly coverage: CoverageGutter;
  private schemaRegistered = false;
  /** hibou/* requests the running server advertised at initialize. */
  private serverRequests = new Set<string>();

  constructor(private readonly context: vscode.ExtensionContext) {
    this.log = vscode.window.createOutputChannel("hibou", { log: true });
    this.statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
    this.statusItem.command = "hibou.showMenu";
    this.tree = new FindingsTree(() => this.client);
    this.coverage = new CoverageGutter(() => this.client);
    const c = context.subscriptions;
    c.push(this.log, this.statusItem, this.coverage);
    c.push(vscode.window.registerTreeDataProvider("hibou.findings", this.tree));

    const cmd = (id: string, fn: (...args: any[]) => unknown) => c.push(vscode.commands.registerCommand(id, fn));
    cmd("hibou.signIn", () => this.signIn());
    cmd("hibou.signOut", () => this.signOut());
    cmd("hibou.setServer", () => this.setServer());
    cmd("hibou.refresh", () => this.refresh());
    cmd("hibou.openRepo", () => this.openRepo());
    cmd("hibou.toggleCoverage", () => this.toggleCoverage());
    cmd("hibou.showMenu", () => this.showMenu());
    cmd("hibou.restart", () => this.restart());
    cmd("hibou.checkStagedSecrets", () => this.checkStagedSecrets());
    cmd("hibou.suppress", (arg: { uri: string; fingerprint: string; line: number }) => this.suppress(arg));
    cmd("hibou.triage", (arg: { uri: string; fingerprint: string; action: string }) => this.triage(arg));
    cmd("hibou.openFindingItem", (f: PanelFinding) => openFinding(f));

    c.push(vscode.window.onDidChangeActiveTextEditor(() => this.renderStatus()));
    c.push(
      vscode.workspace.onDidChangeConfiguration((e) => {
        if (["hibou.server", "hibou.path", "hibou.org", "hibou.repo", "hibou.pollSeconds", "hibou.showSuppressed", "hibou.secretCheck.enabled"].some((k) => e.affectsConfiguration(k))) {
          void this.restart();
        } else if (e.affectsConfiguration("hibou.coverage.enabled")) {
          this.coverage.refreshAll();
        }
      }),
    );
  }

  async start(): Promise<void> {
    this.server = await resolveServer();
    if (!this.server) {
      this.setStatuses([{ root: "", state: "unconfigured", message: "Set the hibou server URL." }]);
      return;
    }
    if (isInsecureRemote(this.server)) {
      this.setStatuses([{ root: "", state: "error", message: `Refusing plain http to ${this.server}: use https.` }]);
      return;
    }

    let binary: string;
    try {
      binary = await resolveBinary(this.context, this.server, this.log);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.log.appendLine(`Cannot start the language server: ${msg}`);
      this.setStatuses([{ root: "", state: "error", message: msg }]);
      return;
    }

    const env: NodeJS.ProcessEnv = { ...process.env, HIBOU_SERVER: this.server };
    const token = await this.context.secrets.get(secretKey(this.server));
    if (token) env.HIBOU_TOKEN = token; // environment, never argv (ADR-042 §3)

    const cfg = vscode.workspace.getConfiguration("hibou");
    const serverOptions: ServerOptions = { command: binary, args: ["lsp"], options: { env } };
    const clientOptions: LanguageClientOptions = {
      documentSelector: [{ scheme: "file" }],
      outputChannel: this.log,
      initializationOptions: {
        server: this.server,
        clientId: "hibou-vscode",
        clientName: os.hostname(),
        org: cfg.get<string>("org") ?? "",
        repo: cfg.get<string>("repo") ?? "",
        pollSeconds: cfg.get<number>("pollSeconds") ?? 120,
        showSuppressed: cfg.get<boolean>("showSuppressed") ?? false,
        // Consent to send staged diffs is read from user settings only.
        secretCheck: cfg.inspect<boolean>("secretCheck.enabled")?.globalValue === true,
      },
    };
    const client = new LanguageClient("hibou", "hibou", serverOptions, clientOptions);
    this.client = client;
    client.onDidChangeState((e) => {
      if (e.newState === State.Stopped && this.client === client) {
        this.setStatuses([{ root: "", state: "error", message: "The hibou language server stopped. Run “hibou: Restart Language Server”." }]);
      }
    });
    try {
      await client.start();
    } catch (err) {
      this.log.appendLine(`Language server failed to start: ${String(err)}`);
      return;
    }
    const advertised = (client.initializeResult?.capabilities as { experimental?: { hibou?: { protocol?: number; requests?: string[] } } } | undefined)?.experimental?.hibou;
    if (!advertised || typeof advertised.protocol !== "number") {
      this.setStatuses([{ root: "", state: "error", message: `${binary} is not a compatible hibou language server. Upgrade your hibou server, or fix hibou.path.` }]);
      await this.stop();
      return;
    }
    this.serverRequests = new Set(advertised.requests ?? []);
    if (advertised.protocol > supportedProtocol) {
      void vscode.window.showWarningMessage(`hibou: your server speaks a newer IDE protocol (${advertised.protocol}) than this extension (${supportedProtocol}). Update the hibou extension.`);
    }
    client.onNotification("hibou/statusChanged", (st: Status) => {
      this.statuses = [...this.statuses.filter((s) => s.root !== st.root && s.root !== ""), st];
      this.renderStatus();
      this.tree.refresh();
      this.coverage.refreshAll();
    });
    this.setStatuses(await client.sendRequest<Status[]>("hibou/status"));
    void this.registerYamlSchema();
  }

  async stop(): Promise<void> {
    const client = this.client;
    this.client = undefined;
    if (client && client.state !== State.Stopped) await client.stop();
  }

  private ready: Promise<void> = Promise.resolve();

  restart(): Promise<void> {
    this.ready = (async () => {
      await this.stop();
      await this.start();
      this.tree.refresh();
    })();
    return this.ready;
  }

  private setStatuses(statuses: Status[]): void {
    this.statuses = statuses;
    this.renderStatus();
    this.tree.refresh();
  }

  private current(): Status | undefined {
    return statusForPath(this.statuses, vscode.window.activeTextEditor?.document.uri.fsPath);
  }

  private renderStatus(): void {
    const st = this.current();
    const view = statusBar(st);
    this.statusItem.text = view.text;
    this.statusItem.tooltip = view.tooltip;
    this.statusItem.backgroundColor = view.warning ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
    this.statusItem.show();
    void vscode.commands.executeCommand("setContext", "hibou.state", st?.state ?? "unconfigured");
  }

  private async signIn(): Promise<void> {
    if (!this.server) {
      await this.setServer();
      if (!this.server) return;
    }
    const client = this.client;
    if (!client) {
      void vscode.window.showErrorMessage("hibou: the language server is not running. Check the hibou output.");
      return;
    }
    let start: { userCode: string; verificationUri: string; verificationUriComplete: string; expiresIn: number };
    try {
      start = await client.sendRequest("hibou/login/start");
    } catch (err) {
      if (err instanceof ResponseError && err.code === loginUnsupported) return this.pasteToken(client);
      void vscode.window.showErrorMessage(`hibou: sign-in failed: ${errorText(err)}`);
      return;
    }

    const target = sameOrigin(start.verificationUriComplete, this.server) ?? sameOrigin(start.verificationUri, this.server) ?? `${this.server}/device`;
    const open = "Copy Code and Open Browser";
    const choice = await vscode.window.showInformationMessage(
      `Sign in to hibou with the code ${start.userCode}`,
      { modal: true, detail: `Approve this request in your browser and check that it shows the same code: ${start.userCode}.\nThe code expires in ${Math.round(start.expiresIn / 60)} minutes.` },
      open,
    );
    if (choice !== open) {
      void client.sendRequest("hibou/login/cancel");
      return;
    }
    await vscode.env.clipboard.writeText(start.userCode);
    await vscode.env.openExternal(vscode.Uri.parse(target));

    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `hibou: waiting for approval of ${start.userCode} in the browser…`, cancellable: true },
      async (_progress, cancel) => {
        cancel.onCancellationRequested(() => void client.sendRequest("hibou/login/cancel"));
        try {
          const res = await client.sendRequest<{ token: string; tokenName?: string; user?: string; expiresAt?: string }>("hibou/login/wait", undefined, cancel);
          await this.context.secrets.store(secretKey(this.server!), res.token);
          const until = res.expiresAt ? ` until ${new Date(res.expiresAt).toLocaleDateString()}` : "";
          void vscode.window.showInformationMessage(`hibou: signed in${res.user ? ` as ${res.user}` : ""} (read-only token${until}).`);
        } catch (err) {
          if (!cancel.isCancellationRequested) void vscode.window.showErrorMessage(`hibou: ${errorText(err)}`);
        }
      },
    );
  }

  private async pasteToken(client: LanguageClient): Promise<void> {
    const token = await vscode.window.showInputBox({
      title: "hibou: this server predates browser sign-in",
      prompt: `Create a read-only API key in ${this.server}/settings (API Keys) and paste it here.`,
      password: true,
      ignoreFocusOut: true,
    });
    if (!token) return;
    try {
      await client.sendRequest("hibou/setToken", { token });
      await this.context.secrets.store(secretKey(this.server!), token.trim());
      void vscode.window.showInformationMessage("hibou: signed in.");
    } catch (err) {
      void vscode.window.showErrorMessage(`hibou: ${errorText(err)}`);
    }
  }

  private async signOut(): Promise<void> {
    if (this.client) {
      try {
        await this.client.sendRequest("hibou/logout");
      } catch (err) {
        this.log.appendLine(`logout: ${errorText(err)}`);
      }
    }
    if (this.server) await this.context.secrets.delete(secretKey(this.server));
    void vscode.window.showInformationMessage("hibou: signed out. A token borrowed from `hibou login` stays valid for the CLI.");
  }

  private async setServer(): Promise<void> {
    const value = await vscode.window.showInputBox({
      title: "hibou server URL",
      value: this.server ?? "",
      placeHolder: "https://hibou.example.com",
      ignoreFocusOut: true,
      validateInput: (v) => {
        const s = normalizeServer(v);
        if (!s) return "Enter the URL of your hibou server.";
        if (isInsecureRemote(s)) return "Use https:// (plain http is only allowed to localhost).";
        return undefined;
      },
    });
    const server = value ? normalizeServer(value) : undefined;
    if (!server) return;
    try {
      const resp = await fetch(`${server}/api/v1/version`, { signal: AbortSignal.timeout(10_000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    } catch (err) {
      const go = await vscode.window.showWarningMessage(`${server} does not answer like a hibou server (${errorText(err)}). Use it anyway?`, "Use Anyway");
      if (go !== "Use Anyway") return;
    }
    await vscode.workspace.getConfiguration("hibou").update("server", server, vscode.ConfigurationTarget.Global);
  }

  private async refresh(): Promise<void> {
    if (!this.client) return this.restart();
    this.setStatuses(await this.client.sendRequest<Status[]>("hibou/refresh"));
  }

  private openRepo(): void {
    const url = this.current()?.webUrl ?? this.server;
    if (url) void vscode.env.openExternal(vscode.Uri.parse(url));
  }

  private async toggleCoverage(): Promise<void> {
    const cfg = vscode.workspace.getConfiguration("hibou");
    await cfg.update("coverage.enabled", !cfg.get<boolean>("coverage.enabled"), vscode.ConfigurationTarget.Global);
  }

  private async showMenu(): Promise<void> {
    const st = this.current();
    const items: (vscode.QuickPickItem & { run: () => unknown })[] = [];
    if (st?.message) items.push({ label: "$(info) " + st.message, run: () => undefined });
    if (st?.state === "signedOut" || st?.state === "unconfigured") items.push({ label: "$(sign-in) Sign in", run: () => this.signIn() });
    if (st?.gate?.url) items.push({ label: `$(git-pull-request) Gate for PR #${st.gate.pr}: ${st.gate.state}`, run: () => vscode.env.openExternal(vscode.Uri.parse(st.gate!.url!)) });
    if (st?.webUrl) items.push({ label: "$(link-external) Open repository in hibou", run: () => this.openRepo() });
    items.push(
      { label: "$(refresh) Refresh findings", run: () => this.refresh() },
      { label: "$(graph-line) Toggle coverage gutter", run: () => this.toggleCoverage() },
      { label: "$(server) Set server URL", description: this.server, run: () => this.setServer() },
    );
    if (st?.user) items.push({ label: "$(sign-out) Sign out", description: st.user, run: () => this.signOut() });
    const pick = await vscode.window.showQuickPick(items, { title: "hibou" });
    await pick?.run();
  }

  private async suppress(arg: { uri: string; fingerprint: string; line: number }): Promise<void> {
    const client = this.client;
    if (!client || !this.supports("hibou/suppressionEdit")) return;
    const reason = await vscode.window.showInputBox({
      title: "Suppress with a native directive",
      prompt: "Why is this safe? The scanner records it as the suppression's justification.",
      ignoreFocusOut: true,
      validateInput: (v) => (v.trim() ? undefined : "A justification is required."),
    });
    if (!reason) return;
    try {
      const edit = await client.sendRequest<WorkspaceEdit>("hibou/suppressionEdit", { ...arg, reason });
      await vscode.workspace.applyEdit(await client.protocol2CodeConverter.asWorkspaceEdit(edit));
    } catch (err) {
      void vscode.window.showErrorMessage(`hibou: ${errorText(err)}`);
    }
  }

  private async triage(arg: { uri: string; fingerprint: string; action: string }): Promise<void> {
    const client = this.client;
    if (!client || !this.supports("hibou/triage")) return;
    let reason = "";
    let expiresInDays = 0;
    const ask = async (title: string, prompt: string) =>
      vscode.window.showInputBox({ title, prompt, ignoreFocusOut: true, validateInput: (v) => (v.trim() ? undefined : "A justification is required.") });
    switch (arg.action) {
      case "accept": {
        const r = await ask("Accept the risk", "Why is the risk acceptable?");
        if (!r) return;
        const exp = await vscode.window.showQuickPick(
          [
            { label: "30 days", days: 30 },
            { label: "90 days", days: 90 },
            { label: "180 days", days: 180 },
            { label: "No expiry", days: 0 },
          ],
          { title: "Re-review the acceptance after" },
        );
        if (!exp) return;
        reason = r;
        expiresInDays = exp.days;
        break;
      }
      case "false_positive": {
        const r = await ask("Mark as false positive", "Why is this not a real issue?");
        if (!r) return;
        reason = r;
        break;
      }
      case "dispute": {
        const r = await ask("Dispute the suppression", "Why should this suppressed finding count again?");
        if (!r) return;
        reason = r;
        break;
      }
      default: {
        const ok = await vscode.window.showWarningMessage(arg.action === "reopen" ? "Remove the acceptance and reopen this finding?" : "Withdraw the dispute?", { modal: true }, "Confirm");
        if (ok !== "Confirm") return;
      }
    }
    try {
      const res = await client.sendRequest<{ ok: boolean; message: string; webUrl?: string }>("hibou/triage", { ...arg, reason, expiresInDays });
      if (res.ok) {
        void vscode.window.showInformationMessage(`hibou: ${res.message}`);
        return;
      }
      const pick = await vscode.window.showWarningMessage(`hibou: ${res.message}`, ...(res.webUrl ? ["Open in Browser"] : []));
      if (pick && res.webUrl) void vscode.env.openExternal(vscode.Uri.parse(res.webUrl));
    } catch (err) {
      void vscode.window.showErrorMessage(`hibou: ${errorText(err)}`);
    }
  }

  /** ADR-042 phase 3: sends the staged diff to the server's secret check,
   * which scans it and stores nothing. Off until the user agrees. */
  /** False, with a message, when the running server predates request. */
  private supports(request: string): boolean {
    if (this.serverRequests.has(request)) return true;
    void vscode.window.showWarningMessage("hibou: your hibou server is too old for this feature. Upgrade hibou to use it.");
    return false;
  }

  private async checkStagedSecrets(): Promise<void> {
    if (!this.supports("hibou/secretCheck")) return;
    const cfg = vscode.workspace.getConfiguration("hibou");
    if (cfg.inspect<boolean>("secretCheck.enabled")?.globalValue !== true) {
      const enable = "Enable and Check";
      const pick = await vscode.window.showWarningMessage(
        "Check staged changes for secrets?",
        { modal: true, detail: `This sends your staged diff (git diff --cached) to ${this.server ?? "your hibou server"}. The server scans it and stores nothing. You can turn it off with the hibou.secretCheck.enabled setting.` },
        enable,
      );
      if (pick !== enable) return;
      await cfg.update("secretCheck.enabled", true, vscode.ConfigurationTarget.Global);
      await new Promise((r) => setTimeout(r, 0)); // let the configuration listener restart the server
      await this.ready;
    }
    const client = this.client;
    if (!client) return;
    type Finding = { tool: string; ruleId: string; severity: string; path: string; uri?: string; line: number; secretType: string; verified: boolean };
    try {
      const res = await vscode.window.withProgress({ location: vscode.ProgressLocation.SourceControl, title: "hibou: checking staged changes for secrets" }, () =>
        client.sendRequest<{ block: boolean; findings: Finding[]; message: string }>("hibou/secretCheck", {}),
      );
      if (res.findings.length === 0) {
        void vscode.window.showInformationMessage(`hibou: ${res.message}`);
        return;
      }
      const show = "Show";
      if ((await vscode.window.showWarningMessage(`hibou: ${res.findings.length} secret(s) in the staged changes. Remove them before committing.`, show)) !== show) return;
      const pick = await vscode.window.showQuickPick(
        res.findings.map((f) => ({
          label: `${f.verified ? "$(flame) " : ""}${f.secretType || f.ruleId}`,
          description: `${f.path}:${f.line + 1}`,
          detail: `${f.tool} · ${f.severity}${f.verified ? " · verified live: rotate it" : ""}`,
          f,
        })),
        { title: "Secrets in staged changes" },
      );
      if (pick?.f.uri) {
        const pos = new vscode.Position(pick.f.line, 0);
        await vscode.window.showTextDocument(vscode.Uri.parse(pick.f.uri), { selection: new vscode.Range(pos, pos) });
      }
    } catch (err) {
      void vscode.window.showErrorMessage(`hibou: ${errorText(err)}`);
    }
  }

  /** Validates .hibou.yaml against the server's schema through the Red Hat
   * YAML extension, when it is installed. */
  private async registerYamlSchema(): Promise<void> {
    if (this.schemaRegistered) return;
    const yaml = vscode.extensions.getExtension("redhat.vscode-yaml");
    if (!yaml) return;
    try {
      const api = (await yaml.activate()) as {
        registerContributor?: (schema: string, request: (resource: string) => string | undefined, content: (uri: string) => Promise<string>, label?: string) => boolean;
      };
      if (!api?.registerContributor) return;
      api.registerContributor(
        "hibou",
        (resource) => (/(^|[\\/])\.hibou\.ya?ml$/.test(resource) ? "hibou:/hibou-config.schema.json" : undefined),
        async () => {
          if (!this.server) return "{}";
          const resp = await fetch(`${this.server}/api/v1/schemas/hibou-config.schema.json`, { signal: AbortSignal.timeout(10_000) });
          return resp.ok ? await resp.text() : "{}";
        },
        "hibou",
      );
      this.schemaRegistered = true;
    } catch (err) {
      this.log.appendLine(`YAML schema registration skipped: ${errorText(err)}`);
    }
  }
}

function secretKey(server: string): string {
  return `hibou.token:${server}`;
}

/** Returns url when it points at the configured server's origin. The device
 * page must be on the server the user configured, never elsewhere. */
function sameOrigin(url: string | undefined, server: string): string | undefined {
  if (!url) return undefined;
  try {
    return new URL(url).origin === new URL(server).origin ? url : undefined;
  } catch {
    return undefined;
  }
}

function errorText(err: unknown): string {
  // -32601: the server predates this request (an older hibou release).
  if (err instanceof ResponseError && err.code === -32601) return "your hibou server is too old for this feature; upgrade hibou to use it";
  return err instanceof Error ? err.message : String(err);
}

/** Server URL: the hibou.server user setting, HIBOU_SERVER, then the server
 * saved by `hibou login`. */
async function resolveServer(): Promise<string | undefined> {
  const configured = vscode.workspace.getConfiguration("hibou").inspect<string>("server")?.globalValue;
  for (const candidate of [configured, process.env.HIBOU_SERVER, await cliConfigServer()]) {
    const s = candidate ? normalizeServer(candidate) : undefined;
    if (s) return s;
  }
  return undefined;
}

/** Reads `server:` from the CLI config (Go's os.UserConfigDir()/hibou/config.yaml). */
async function cliConfigServer(): Promise<string | undefined> {
  const base =
    process.platform === "win32"
      ? process.env.APPDATA
      : process.platform === "darwin"
        ? path.join(os.homedir(), "Library", "Application Support")
        : process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  if (!base) return undefined;
  try {
    const text = await fs.readFile(path.join(base, "hibou", "config.yaml"), "utf8");
    const m = /^server:\s*["']?([^"'\s#]+)/m.exec(text);
    return m?.[1];
  } catch {
    return undefined;
  }
}

function severityIcon(f: PanelFinding): vscode.ThemeIcon {
  if (f.status === "suppressed" || f.accepted) return new vscode.ThemeIcon("pass", new vscode.ThemeColor("disabledForeground"));
  switch (f.severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error", new vscode.ThemeColor("problemsErrorIcon.foreground"));
    case "medium":
      return new vscode.ThemeIcon("warning", new vscode.ThemeColor("problemsWarningIcon.foreground"));
    default:
      return new vscode.ThemeIcon("info", new vscode.ThemeColor("problemsInfoIcon.foreground"));
  }
}

async function openFinding(f: PanelFinding): Promise<void> {
  if (!f.uri) {
    await vscode.env.openExternal(vscode.Uri.parse(f.webUrl));
    return;
  }
  const start = new vscode.Position(f.range.start.line, 0);
  await vscode.window.showTextDocument(vscode.Uri.parse(f.uri), { selection: new vscode.Range(start, start) });
}

type Node = { kind: "file"; label: string; findings: PanelFinding[] } | { kind: "finding"; finding: PanelFinding };

/** The Findings view: the repository's findings grouped by file. */
class FindingsTree implements vscode.TreeDataProvider<Node> {
  private readonly changed = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this.changed.event;
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly client: () => LanguageClient | undefined) {
    vscode.languages.onDidChangeDiagnostics(() => this.refresh());
  }

  refresh(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.changed.fire(), 750);
  }

  getTreeItem(node: Node): vscode.TreeItem {
    if (node.kind === "file") {
      const item = new vscode.TreeItem(node.label, vscode.TreeItemCollapsibleState.Expanded);
      item.description = `${node.findings.length}`;
      item.iconPath = vscode.ThemeIcon.File;
      if (node.findings[0]?.uri) item.resourceUri = vscode.Uri.parse(node.findings[0].uri);
      return item;
    }
    const f = node.finding;
    const item = new vscode.TreeItem(f.title || f.rule || "finding", vscode.TreeItemCollapsibleState.None);
    item.description = [f.component, f.rule, f.uri ? `line ${f.range.start.line + 1}` : undefined, f.edited ? "changed since scan" : undefined].filter(Boolean).join(" · ");
    item.tooltip = new vscode.MarkdownString(
      [`**${f.severity.toUpperCase()}** ${f.title}`, f.scanner && `Scanner: ${f.scanner}`, f.kev && "Known exploited (KEV)", f.status === "suppressed" && "Suppressed in source", f.accepted && "Accepted"]
        .filter(Boolean)
        .join("\n\n"),
    );
    item.iconPath = severityIcon(f);
    item.command = { command: "hibou.openFindingItem", title: "Open", arguments: [f] };
    return item;
  }

  async getChildren(node?: Node): Promise<Node[]> {
    if (node?.kind === "file") return node.findings.map((finding) => ({ kind: "finding", finding }));
    if (node) return [];
    const client = this.client();
    if (!client || client.state !== State.Running) return [];
    let findings: PanelFinding[];
    try {
      findings = await client.sendRequest<PanelFinding[]>("hibou/findings", {});
    } catch {
      return [];
    }
    const groups = new Map<string, PanelFinding[]>();
    for (const f of findings) {
      const key = f.path || (f.type === "dependency" ? "Dependencies" : "Other");
      groups.set(key, [...(groups.get(key) ?? []), f]);
    }
    return [...groups.entries()].map(([label, list]) => ({ kind: "file", label, findings: list }));
  }
}

/** Line coverage of the last scan, as a thin left border (ADR-018 hits). */
class CoverageGutter implements vscode.Disposable {
  private readonly covered = vscode.window.createTextEditorDecorationType(border("rgba(46,160,67,0.8)"));
  private readonly uncovered = vscode.window.createTextEditorDecorationType(border("rgba(248,81,73,0.8)"));
  private readonly partial = vscode.window.createTextEditorDecorationType(border("rgba(210,153,34,0.8)"));
  private readonly subs: vscode.Disposable[] = [];
  private timer: NodeJS.Timeout | undefined;

  constructor(private readonly client: () => LanguageClient | undefined) {
    this.subs.push(
      vscode.window.onDidChangeVisibleTextEditors(() => this.refreshAll()),
      vscode.workspace.onDidChangeTextDocument((e) => {
        if (vscode.window.visibleTextEditors.some((ed) => ed.document === e.document)) this.refreshAll();
      }),
    );
  }

  refreshAll(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      for (const editor of vscode.window.visibleTextEditors) void this.render(editor);
    }, 800);
  }

  private async render(editor: vscode.TextEditor): Promise<void> {
    const enabled = vscode.workspace.getConfiguration("hibou").get<boolean>("coverage.enabled");
    const client = this.client();
    if (!enabled || !client || client.state !== State.Running || editor.document.uri.scheme !== "file") {
      this.clear(editor);
      return;
    }
    try {
      const res = await client.sendRequest<{ covered: number[]; uncovered: number[]; partial: number[] }>("hibou/coverage", { uri: editor.document.uri.toString() });
      const ranges = (lines: number[]) => lines.filter((l) => l < editor.document.lineCount).map((l) => editor.document.lineAt(l).range);
      editor.setDecorations(this.covered, ranges(res.covered));
      editor.setDecorations(this.uncovered, ranges(res.uncovered));
      editor.setDecorations(this.partial, ranges(res.partial));
    } catch {
      this.clear(editor);
    }
  }

  private clear(editor: vscode.TextEditor): void {
    for (const d of [this.covered, this.uncovered, this.partial]) editor.setDecorations(d, []);
  }

  dispose(): void {
    clearTimeout(this.timer);
    for (const s of this.subs) s.dispose();
    this.covered.dispose();
    this.uncovered.dispose();
    this.partial.dispose();
  }
}

function border(color: string): vscode.DecorationRenderOptions {
  return { isWholeLine: true, borderWidth: "0 0 0 3px", borderStyle: "solid", borderColor: color, overviewRulerColor: color, overviewRulerLane: vscode.OverviewRulerLane.Left };
}
