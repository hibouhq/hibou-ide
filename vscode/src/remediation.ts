import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { LanguageClient } from "vscode-languageclient/node";
import { decodeArtifact } from "./remediationArtifact";
import { PreparedRemediation, showRemediationPlan } from "./remediationPlan";
import { createManagedPR } from "./remediationManaged";

export class DependencyPatchReview implements vscode.Disposable {
  private readonly previews = new Map<string, string>();
  private readonly provider: vscode.Disposable;
  private applying = false;
  private generating = false;

  constructor(private readonly extensionUri: vscode.Uri) {
    this.provider = vscode.workspace.registerTextDocumentContentProvider("hibou-remediation", {
      provideTextDocumentContent: (uri) => this.previews.get(uri.toString()) ?? "This patch preview has expired.",
    });
  }

  dispose(): void {
    this.provider.dispose();
    this.previews.clear();
  }

  async open(client: LanguageClient, roots: string[]): Promise<void> {
    if (!vscode.workspace.isTrusted) throw new Error("Trust this workspace before applying dependency changes.");
    if (this.applying) throw new Error("A dependency patch is already being applied.");
    const repositories = [...new Set(roots.filter(Boolean))];
    if (repositories.length === 0) throw new Error("No Git repository is registered with hibou.");
    const root = repositories.length === 1 ? repositories[0]
      : (await vscode.window.showQuickPick(repositories.map((r) => ({ label: path.basename(r), description: r, root: r })),
        { title: "Choose the repository for this dependency patch" }))?.root;
    if (!root) return;
    const files = await vscode.window.showOpenDialog({
      canSelectMany: false, filters: { "Hibou dependency-patch artifact": ["json"] },
      title: "Open a trusted Hibou dependency-patch artifact",
    });
    if (!files?.length) return;
    const info = await fs.stat(files[0].fsPath);
    if (info.size > 48 * 1024 * 1024) throw new Error("Dependency-patch artifact exceeds the size limit.");
    const review = decodeArtifact(await fs.readFile(files[0].fsPath, "utf8"));
    await this.review(client,root,review);
  }

  async generate(client: LanguageClient,roots: string[],managedPublication=false): Promise<void> {
    if (!vscode.workspace.isTrusted) throw new Error("Trust this workspace before running local dependency tools.");
    if (this.generating || this.applying) throw new Error("A remediation operation is already running.");
    const repositories = [...new Set(roots.filter(Boolean))];
    if (repositories.length===0) throw new Error("No Git repository is registered with hibou.");
    const root = repositories.length===1 ? repositories[0]
      : (await vscode.window.showQuickPick(repositories.map((r)=>({label:path.basename(r),description:r,root:r})),
        {title:"Choose the repository for dependency fixes"}))?.root;
    if (!root) return;
    const consent = await vscode.window.showWarningMessage("Prepare dependency fixes using local tooling?", {
      modal:true,
      detail:`Repository: ${root}\nInitial support: independent npm package-lock v3 modules, automatic patch/minor upgrades. Hibou runs your installed Node/npm and reads committed HEAD in a temporary workspace. Install scripts are disabled. Package identities/versions are sent to your Hibou server and configured registries; source files are not uploaded. No automatic tool installation, edits to your working tree, commit or push.`,
    },"Prepare locally");
    if (consent!=="Prepare locally") return;
    this.generating = true;
    try {
      let prepared = await vscode.window.withProgress({
        location:vscode.ProgressLocation.Notification,title:"hibou: discovering committed dependency modules",cancellable:true,
      },(_progress,token)=>client.sendRequest<PreparedRemediation>("hibou/remediationPrepare",{root,consent_local:true,upgrade_level:"minor"},token));
      let latest:ReturnType<typeof decodeArtifact>|undefined;
      await showRemediationPlan({
        extensionUri:this.extensionUri,prepared,
        generate:async(selection,panelToken)=>{
          const generated=await vscode.window.withProgress({
            location:vscode.ProgressLocation.Notification,title:"hibou: resolving, relocking and verifying dependency batch",cancellable:true,
          },async(_progress,progressToken)=>{
            const cancellation=new vscode.CancellationTokenSource();
            const links=[panelToken.onCancellationRequested(()=>cancellation.cancel()),progressToken.onCancellationRequested(()=>cancellation.cancel())];
            try {
              return await client.sendRequest<unknown>("hibou/remediationGenerate",{
                root:prepared.root,id:prepared.id,unit_ids:selection.unit_ids,version_targets:selection.version_targets,
                upgrade_level:selection.upgrade_level,allow_major:selection.allow_major,
              },cancellation.token);
            } finally { links.forEach((link)=>link.dispose());cancellation.dispose(); }
          });
          latest=decodeArtifact(JSON.stringify(generated));
        },
        revise:async()=>{
          prepared=await client.sendRequest<PreparedRemediation>("hibou/remediationRevise",{root:prepared.root,id:prepared.id});
          latest=undefined;
          return prepared;
        },
        review:async()=>{ if (latest) await this.review(client,prepared.root,latest,managedPublication?{id:prepared.id,branch:prepared.branch||""}:undefined); },
      });
    } finally {
      this.generating = false;
    }
  }

  private async review(client:LanguageClient,root:string,review:ReturnType<typeof decodeArtifact>,localDraft?:{id:string;branch:string}):Promise<void> {
    await this.previewPatch(review,"dependency-fixes.diff");
    const apply = "Apply batch to working tree";
    const choice = await vscode.window.showInformationMessage(
      `Read-only dependency patch opened: ${review.artifact.changes.length} file(s), ${review.artifact.units.length} resolution unit(s). Review the diff, then apply.`,
      apply,
      "Export Git patch",
      "Export artifact",
      ...(localDraft?["Create PR with Hibou"]:[]),
    );
    if (choice==="Create PR with Hibou" && localDraft) {
      await createManagedPR(client,root,localDraft,(managed)=>this.previewPatch(managed,"managed-dependency-fixes.diff"));
      return;
    }
    if (choice==="Export Git patch" || choice==="Export artifact") {
      const artifact = choice==="Export artifact";
      const target = await vscode.window.showSaveDialog({
        defaultUri:vscode.Uri.file(path.join(root,artifact?"hibou-fix.json":"hibou-fix.patch")),
        filters:artifact?{"Hibou artifact":["json"]}:{"Git patch":["patch","diff"]},
      });
      if (target) {
        await vscode.workspace.fs.writeFile(target,Buffer.from(artifact?JSON.stringify(review.artifact,null,2):review.patch,"utf8"));
        void vscode.window.showInformationMessage("hibou: dependency patch exported; nothing was applied.");
      }
      return;
    }
    if (choice !== apply) return;
    const confirmed = await vscode.window.showWarningMessage(
      "Apply the reviewed dependency batch?",
      { modal: true, detail: `Repository: ${root}\nBase: ${review.artifact.base_sha}\nOnly open artifacts from a trusted source. Reported dependency verification is not a signature of origin. Application build/tests are not run. No commit, staging or push will occur.` },
      apply,
    );
    if (confirmed !== apply) return;
    for (const change of review.artifact.changes) {
      const affected = path.resolve(root, change.path);
      if (vscode.workspace.textDocuments.some((d) => d.uri.scheme === "file" && path.resolve(d.uri.fsPath) === affected && d.isDirty)) {
        throw new Error(`Save or resolve the unsaved buffer for ${change.path} before applying.`);
      }

    }
    if (this.applying) throw new Error("A dependency patch is already being applied.");
    this.applying = true;
    try {
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification, title: "hibou: applying reviewed dependency batch",
      }, () => client.sendRequest<{ already_applied: boolean }>("hibou/remediationApply", { root, artifact: review.artifact }));
      void vscode.window.showInformationMessage(result.already_applied
        ? "hibou: this dependency patch is already applied."
        : "hibou: dependency patch applied locally. Review changes in Source Control; build/tests were not run.");
    } finally {
      this.applying = false;
    }
  }

  private async previewPatch(review:ReturnType<typeof decodeArtifact>,name:string):Promise<void> {
    const uri=vscode.Uri.parse(`hibou-remediation:/${review.artifact.sha256}/${name}`);
    if (this.previews.size>=10) this.previews.delete(this.previews.keys().next().value||"");
    this.previews.set(uri.toString(),review.patch);
    const document=await vscode.workspace.openTextDocument(uri);
    await vscode.languages.setTextDocumentLanguage(document,"diff");
    await vscode.window.showTextDocument(document,{preview:false});
  }
}
