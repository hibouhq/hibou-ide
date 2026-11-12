import { randomBytes } from "node:crypto";
import * as vscode from "vscode";
import { parsePlanSelection, PlanSelection } from "./remediationSelection";

export type PreparedRemediation = {
  id: string;
  root: string;
  base_sha: string;
  branch?: string;
  manager_version: string;
  manager_path: string;
  runtime_version: string;
  units: {
    id: string;
    manifest: string;
    vulns: string[];
    direct_packages?: { name: string; version: string; recommended_version?: string; can_select_version?: boolean; declared?: string; recommendation_fetched_at?: string }[];
  }[];
  unavailable: string[];
};

type PlanOptions = {
  extensionUri: vscode.Uri;
  prepared: PreparedRemediation;
  generate: (selection: PlanSelection, token: vscode.CancellationToken) => Promise<void>;
  revise: () => Promise<PreparedRemediation>;
  review: () => Promise<void>;
};

export async function showRemediationPlan(options: PlanOptions): Promise<void> {
  const panel = vscode.window.createWebviewPanel("hibou.dependencyFixes", "Dependency Fixes", vscode.ViewColumn.Active, {
    enableScripts: true, retainContextWhenHidden: true,
    localResourceRoots: [vscode.Uri.joinPath(options.extensionUri, "media")],
  });
  const nonce = randomBytes(18).toString("base64url");
  const stylesheet = panel.webview.asWebviewUri(vscode.Uri.joinPath(options.extensionUri, "media", "remediation-plan.css"));
  const script = panel.webview.asWebviewUri(vscode.Uri.joinPath(options.extensionUri, "media", "remediation-plan.js"));
  panel.webview.html = `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource}; script-src 'nonce-${nonce}';">
<link rel="stylesheet" href="${stylesheet}"><title>Dependency Fixes</title></head>
<body><main>
<header><p class="eyebrow">HIBOU / LOCAL REMEDIATION</p><h1>One batch. Every dependency file.</h1>
<p class="secondary">Choose versions, generate in a temporary workspace, then review the actual diff. Nothing is applied automatically.</p></header>
<section class="target" aria-label="Source and toolchain">
<code id="root"></code><div><span>Committed HEAD</span> <code id="commit"></code></div>
<div id="toolchain"></div><code class="secondary" id="tool-path"></code></section>
<section aria-labelledby="modules-title"><h2 id="modules-title">1. Select modules</h2><div id="modules"></div>
<details id="unavailable-block"><summary>Modules not included</summary><ul id="unavailable"></ul></details></section>
<section aria-labelledby="versions-title"><div class="section-title"><h2 id="versions-title">2. Choose versions</h2>
<label>Upgrade limit <select id="upgrade-level"><option value="patch">Patch only</option><option value="minor" selected>Patch and minor</option><option value="major">Major allowed</option></select></label></div>
<p class="secondary">Automatic changes only what is needed for selected advisories. Direct dependencies are shown for optional overrides; transitive changes appear in the generated diff. Every choice still needs resolution and policy checks.</p>
<label id="major-warning" hidden><input type="checkbox" id="allow-major"> I allow major upgrades; application code changes may be needed and are not generated.</label>
<div class="toolbar"><label>Filter dependencies <input type="search" id="filter" placeholder="Package or module"></label>
<button id="reset" class="secondary-button">Reset all to automatic</button></div>
<div class="table-wrap"><table><thead><tr><th scope="col">Dependency / module</th><th scope="col">Current</th><th scope="col">Target choice</th><th scope="col">Exact target / evidence</th></tr></thead><tbody id="versions"></tbody></table></div>
<div class="pagination"><button id="previous" class="secondary-button">Previous</button><span id="page-label"></span><button id="next" class="secondary-button">Next</button></div></section>
<section class="result"><p id="status" role="status" aria-live="polite">Not resolved yet.</p><p id="error" role="alert" tabindex="-1" hidden></p>
<p class="secondary">Dependency-file consistency must pass. Application builds/tests are not run. Generating does not mark shipped releases fixed.</p></section>
<footer><button id="revise" class="secondary-button" hidden>Revise choices</button><button id="review" class="secondary-button" hidden>Review generated patch</button><button id="generate" disabled>Generate and review patch</button></footer>
</main><script nonce="${nonce}" src="${script}"></script></body></html>`;
  let busy = false;
  let disposed = false;
  let cancellation: vscode.CancellationTokenSource | undefined;
  const send = (message: unknown) => { if (!disposed) void panel.webview.postMessage(message); };
  await new Promise<void>((resolve) => {
    const messages = panel.webview.onDidReceiveMessage(async (message: unknown) => {
      if (message === null || typeof message !== "object" || !("type" in message)) return;
      if (message.type === "ready") { send({ type: "prepared", prepared: options.prepared }); return; }
      if (busy) return;
      busy = true;
      try {
        if (message.type === "generate" && "selection" in message) {
          // The LSP validates the complete request against its saved draft.
          const selection = parsePlanSelection(message.selection);
          cancellation = new vscode.CancellationTokenSource();
          send({ type: "busy", message: "Resolving, relocking and verifying the combined batch..." });
          await options.generate(selection, cancellation.token);
          send({ type: "readyArtifact" });
          try { await options.review(); }
          catch (error) { send({ type:"reviewError",message:error instanceof Error?error.message:String(error) }); }
        } else if (message.type === "revise") {
          send({ type: "busy", message: "Creating a new draft at the same committed base..." });
          const prepared = await options.revise();
          send({ type: "revised", prepared });
        } else if (message.type === "review") {
          await options.review();
        }
      } catch (error) {
        send({ type: "error", message: error instanceof Error ? error.message : String(error) });
      } finally {
        busy = false;
        cancellation?.dispose();
        cancellation = undefined;
      }
    });
    const closing = panel.onDidDispose(() => {
      disposed = true;
      cancellation?.cancel();
      messages.dispose();
      closing.dispose();
      resolve();
    });
  });
}
