import * as vscode from "vscode";
import { LanguageClient } from "vscode-languageclient/node";
import { decodeArtifact } from "./remediationArtifact";

export async function createManagedPR(client: LanguageClient, root: string, draft: { id: string; branch: string },
  preview: (review: ReturnType<typeof decodeArtifact>) => Promise<void>): Promise<void> {
  const branch = await vscode.window.showInputBox({
    title: "Existing branch for the remediation PR", value: draft.branch,
    prompt: "Hibou regenerates from the same commit using its managed profile. No local source or patch is uploaded.",
    validateInput: (value) => value.trim() ? undefined : "Choose an existing target branch.",
  });
  if (!branch?.trim()) return;
  const consent = await vscode.window.showWarningMessage("Regenerate and review a managed patch?", {
    modal: true, detail: "This uses Hibou-managed compute and your saved version choices. The remote branch must still match the locally reviewed base. The managed patch can differ from the local patch and must be reviewed before publication.",
  }, "Generate managed patch");
  if (consent !== "Generate managed patch") return;
  type Managed = { job_id: string; revision: number; repository: string; target_branch: string; proposal_branch: string; artifact: unknown };
  const managed = await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification, title: "hibou: preparing and verifying managed remediation", cancellable: true,
  }, (_progress, token) => client.sendRequest<Managed>("hibou/remediationManagedGenerate", {
    root, local_id: draft.id, target_branch: branch.trim(), consent_managed: true,
  }, token));
  const reviewed = decodeArtifact(JSON.stringify(managed.artifact));
  await preview(reviewed);
  const publish = await vscode.window.showInformationMessage(
    `Managed patch ready for ${managed.repository} → ${managed.target_branch}. Review this diff, not the earlier local patch.`,
    "Create branch and PR",
  );
  if (publish !== "Create branch and PR") return;
  const confirm = await vscode.window.showWarningMessage("Publish the reviewed managed patch?", {
    modal: true, detail: `Repository: ${managed.repository}\nTarget: ${managed.target_branch}\nProposal: ${managed.proposal_branch}\nBase: ${reviewed.artifact.base_sha}\nNo merge, tag or release publishing will occur. Your working tree will not be pushed.`,
  }, "Create branch and PR");
  if (confirm !== "Create branch and PR") return;
  const pr = await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification, title: "hibou: creating proposal branch and pull request",
  }, () => client.sendRequest<{ number: number; html_url: string }>("hibou/remediationManagedPublish", {
    root, job_id: managed.job_id, revision: managed.revision, sha256: reviewed.artifact.sha256,
  }));
  if ((await vscode.window.showInformationMessage(`hibou: pull request #${pr.number} created.`, "Open PR")) === "Open PR") {
    const target = vscode.Uri.parse(pr.html_url);
    if (target.scheme !== "https" && target.scheme !== "http") throw new Error("The forge returned an invalid pull-request URL.");
    await vscode.env.openExternal(target);
  }
}
