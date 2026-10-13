package com.hibouhq.hibou.ide

import com.google.gson.JsonObject
import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.util.text.StringUtil
import com.redhat.devtools.lsp4ij.LSPIJUtils
import com.redhat.devtools.lsp4ij.commands.LSPCommandAction
import org.eclipse.lsp4j.Command
import org.eclipse.lsp4j.jsonrpc.ResponseErrorException
import java.awt.datatransfer.StringSelection
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit

/** JSON-RPC error `hibou lsp` returns when the server predates device login. */
private const val LOGIN_UNSUPPORTED = -32901

/** Notifications render HTML: text is escaped unless html is set, because it
 * often carries server or scanner messages. */
internal fun notify(project: Project?, text: String, type: NotificationType = NotificationType.INFORMATION, link: String? = null, html: Boolean = false) {
    val content = if (html) text else StringUtil.escapeXmlEntities(text)
    val n = NotificationGroupManager.getInstance().getNotificationGroup("hibou").createNotification(content, type)
    if (link != null) {
        n.addAction(object : AnAction("Open in Browser") {
            override fun actionPerformed(e: AnActionEvent) = BrowserUtil.browse(link)
        })
    }
    n.notify(project)
}

private fun rpcCode(t: Throwable): Int? {
    var c: Throwable? = t
    while (c != null) {
        if (c is ResponseErrorException) return c.responseError.code
        c = c.cause
    }
    return null
}

internal fun message(t: Throwable): String {
    // -32601: the server predates this request (an older hibou release).
    if (rpcCode(t) == -32601) return "your hibou server is too old for this feature; upgrade hibou to use it"
    var c: Throwable = t
    while ((c is ExecutionException || c is java.util.concurrent.CompletionException) && c.cause != null) c = c.cause!!
    return c.message ?: c.toString()
}

/** Runs block on the UI thread and returns its value; for dialogs shown from
 * background work. */
private fun <T> onEdt(block: () -> T): T {
    var result: Result<T>? = null
    ApplicationManager.getApplication().invokeAndWait { result = runCatching(block) }
    return result!!.getOrThrow()
}

private fun background(block: () -> Unit) {
    ApplicationManager.getApplication().executeOnPooledThread(block)
}

abstract class HibouAction : AnAction() {
    override fun getActionUpdateThread() = ActionUpdateThread.BGT
}

class SignInAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val server = ServerUrl.resolve() ?: SetServerAction.ask(project) ?: return
        background { signIn(project, server) }
    }

    companion object {
        /** Runs the device flow (ADR-043). Call from a background thread. */
        fun signIn(project: Project, server: String) {
            val service = HibouProjectService.get(project)
            val api = service.server().get(30, TimeUnit.SECONDS) ?: run {
                notify(project, "The hibou language server is not running. Open a file in the project first.", NotificationType.WARNING)
                return
            }
            val start = try {
                api.loginStart().get(30, TimeUnit.SECONDS)
            } catch (t: Throwable) {
                if (rpcCode(t) == LOGIN_UNSUPPORTED) return pasteToken(project, server, api)
                notify(project, "hibou sign-in failed: ${message(t)}", NotificationType.ERROR)
                return
            }
            val code = start.str("userCode")
            val target = sameOrigin(start.str("verificationUriComplete"), server)
                ?: sameOrigin(start.str("verificationUri"), server)
                ?: "$server/device"
            val choice = onEdt {
                Messages.showOkCancelDialog(
                project,
                "Approve this request in your browser and check that it shows the same code:\n\n    $code\n\nThe code expires in ${start.get("expiresIn")?.asInt?.div(60) ?: 10} minutes.",
                "Sign In to hibou",
                "Copy Code and Open Browser",
                Messages.getCancelButton(),
                Messages.getInformationIcon(),
                )
            }
            if (choice != Messages.OK) {
                api.loginCancel()
                return
            }
            onEdt {
                CopyPasteManager.getInstance().setContents(StringSelection(code))
                BrowserUtil.browse(target)
            }

            ProgressManager.getInstance().run(object : Task.Backgroundable(project, "hibou: waiting for approval of $code in the browser", true) {
                override fun run(indicator: ProgressIndicator) {
                    val wait = api.loginWait()
                    while (!wait.isDone) {
                        if (indicator.isCanceled) {
                            wait.cancel(true)
                            api.loginCancel()
                            return
                        }
                        Thread.sleep(250)
                    }
                    try {
                        val res = wait.get()
                        HibouCredentials.store(server, res.str("token"))
                        val user = res.str("user").takeIf { it.isNotEmpty() }?.let { " as $it" }.orEmpty()
                        notify(project, "Signed in to hibou$user (read-only token).")
                        service.reloadStatus()
                    } catch (_: CancellationException) {
                    } catch (t: Throwable) {
                        notify(project, "hibou: ${message(t)}", NotificationType.ERROR)
                    }
                }
            })
        }

        private fun pasteToken(project: Project, server: String, api: HibouServerApi) {
            val token = onEdt {
                Messages.showPasswordDialog(
                    project,
                    "This hibou server predates browser sign-in. Create a read-only API key in $server/settings (API Keys) and paste it here.",
                    "Sign In to hibou",
                    null,
                )
            }?.trim()
            if (token.isNullOrEmpty()) return
            try {
                api.setToken(JsonObject().apply { addProperty("token", token) }).get(30, TimeUnit.SECONDS)
                HibouCredentials.store(server, token)
                notify(project, "Signed in to hibou.")
            } catch (t: Throwable) {
                notify(project, "hibou: ${message(t)}", NotificationType.ERROR)
            }
        }

        /** The device page must be on the configured server, never elsewhere. */
        private fun sameOrigin(url: String, server: String): String? = runCatching {
            val a = java.net.URI(url)
            val b = java.net.URI(server)
            url.takeIf { a.scheme == b.scheme && a.host == b.host && a.port == b.port }
        }.getOrNull()
    }
}

class SignOutAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val server = ServerUrl.resolve() ?: return
        background {
            runCatching { HibouProjectService.get(project).server().get(10, TimeUnit.SECONDS)?.logout()?.get(15, TimeUnit.SECONDS) }
            HibouCredentials.clear(server)
            notify(project, "Signed out of hibou. A token borrowed from `hibou login` stays valid for the CLI.")
        }
    }
}

class SetServerAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        ask(project)
    }

    companion object {
        fun ask(project: Project): String? {
            val input = Messages.showInputDialog(project, "URL of your hibou server", "hibou Server", null, ServerUrl.resolve().orEmpty(), null) ?: return null
            val server = ServerUrl.normalize(input)
            if (server == null || ServerUrl.isInsecureRemote(server)) {
                Messages.showErrorDialog(project, "Enter an https:// URL (plain http is only allowed to localhost).", "hibou Server")
                return null
            }
            HibouSettings.get().state.server = server
            HibouProjectService.get(project).restart()
            return server
        }
    }
}

class RefreshAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val service = HibouProjectService.get(project)
        service.server().thenCompose { it?.refresh() }.thenAccept { list -> list?.let(service::setStatuses) }
    }
}

class OpenRepoAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val file = FileEditorManager.getInstance(project).selectedFiles.firstOrNull()?.path
        val url = HibouProjectService.get(project).statusFor(file)?.str("webUrl")?.takeIf { it.isNotEmpty() } ?: ServerUrl.resolve()
        url?.let(BrowserUtil::browse)
    }
}

class RestartAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        e.project?.let { HibouProjectService.get(it).restart() }
    }
}

/** ADR-042 phase 3: sends the staged diff to the server's secret check,
 * which scans it and stores nothing. Off until the user agrees. */
class CheckStagedSecretsAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val settings = HibouSettings.get().state
        val service = HibouProjectService.get(project)
        if (!settings.secretCheckEnabled) {
            val ok = Messages.showOkCancelDialog(
                project,
                "This sends your staged diff (git diff --cached) to ${ServerUrl.resolve() ?: "your hibou server"}. The server scans it and stores nothing.\n\nYou can turn it off in Settings › Tools › hibou.",
                "Check Staged Changes for Secrets?",
                "Enable and Check",
                Messages.getCancelButton(),
                Messages.getWarningIcon(),
            )
            if (ok != Messages.OK) return
            settings.secretCheckEnabled = true
            service.restart() // the language server reads the consent at start
        }
        background {
            val res = try {
                var api: HibouServerApi? = null
                repeat(40) { if (api == null) api = service.server().get(30, TimeUnit.SECONDS) ?: run { Thread.sleep(250); null } }
                api?.secretCheck(JsonObject())?.get(60, TimeUnit.SECONDS) ?: return@background
            } catch (t: Throwable) {
                notify(project, "hibou: ${message(t)}", NotificationType.ERROR)
                return@background
            }
            val findings = res.getAsJsonArray("findings")?.map { it.asJsonObject }.orEmpty()
            if (findings.isEmpty()) {
                notify(project, "hibou: ${res.str("message")}")
                return@background
            }
            val lines = findings.joinToString("<br/>") { f ->
                val live = if (f.get("verified")?.asBoolean == true) " — <b>verified live, rotate it</b>" else ""
                val what = "${f.str("path")}:${(f.get("line")?.asInt ?: 0) + 1} ${f.str("secretType").ifEmpty { f.str("ruleId") }} (${f.str("tool")})"
                StringUtil.escapeXmlEntities(what) + live
            }
            notify(project, "hibou: ${findings.size} secret(s) in the staged changes. Remove them before committing.<br/>$lines", NotificationType.WARNING, html = true)
        }
    }
}

class ToggleCoverageAction : HibouAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val s = HibouSettings.get().state
        s.coverageEnabled = !s.coverageEnabled
        e.project?.let { HibouCoverage.refreshAll(it) }
    }
}

private fun argsOf(command: Command): JsonObject? =
    command.arguments?.firstOrNull()?.let { arg ->
        when (arg) {
            is JsonObject -> arg
            else -> runCatching { com.google.gson.JsonParser.parseString(com.google.gson.Gson().toJson(arg)).asJsonObject }.getOrNull()
        }
    }

/** Client-side command "hibou.suppress": asks for the justification, then
 * applies the edit `hibou lsp` computes. LSP4IJ routes commands the server
 * does not advertise to the action with the same ID. */
class SuppressCommandAction : LSPCommandAction() {
    override fun commandPerformed(command: Command, e: AnActionEvent) {
        val project = e.project ?: return
        val args = argsOf(command) ?: return
        val reason = Messages.showInputDialog(
            project,
            "Why is this safe? The scanner records it as the suppression's justification.",
            "Suppress with a Native Directive",
            null,
        )?.trim()
        if (reason.isNullOrEmpty()) return
        args.addProperty("reason", reason)
        HibouProjectService.get(project).server()
            .thenCompose { it?.suppressionEdit(args) }
            .whenComplete { edit, err ->
                if (err != null) return@whenComplete notify(project, "hibou: ${message(err)}", NotificationType.ERROR)
                if (edit == null) return@whenComplete
                ApplicationManager.getApplication().invokeLater {
                    WriteCommandAction.runWriteCommandAction(project, "Suppress hibou Finding", null, { LSPIJUtils.applyWorkspaceEdit(edit) })
                }
            }
    }

    override fun getActionUpdateThread() = ActionUpdateThread.BGT
}

/** Client-side command "hibou.triage" (ADR-042 phase 2). */
class TriageCommandAction : LSPCommandAction() {
    override fun commandPerformed(command: Command, e: AnActionEvent) {
        val project = e.project ?: return
        val args = argsOf(command) ?: return
        val action = args.str("action")
        val prompt = when (action) {
            "accept" -> "Why is the risk acceptable?"
            "false_positive" -> "Why is this not a real issue?"
            "dispute" -> "Why should this suppressed finding count again?"
            else -> null
        }
        if (prompt != null) {
            val reason = Messages.showInputDialog(project, prompt, "hibou Triage", null)?.trim()
            if (reason.isNullOrEmpty()) return
            args.addProperty("reason", reason)
            if (action == "accept") {
                val options = arrayOf("30 days", "90 days", "180 days", "No expiry")
                val pick = Messages.showDialog(project, "Re-review the acceptance after:", "hibou Triage", options, 1, null)
                if (pick < 0) return
                args.addProperty("expiresInDays", intArrayOf(30, 90, 180, 0)[pick])
            }
        } else {
            val text = if (action == "reopen") "Remove the acceptance and reopen this finding?" else "Withdraw the dispute?"
            if (Messages.showYesNoDialog(project, text, "hibou Triage", null) != Messages.YES) return
        }
        HibouProjectService.get(project).server()
            .thenCompose { it?.triage(args) }
            .whenComplete { res, err ->
                when {
                    err != null -> notify(project, "hibou: ${message(err)}", NotificationType.ERROR)
                    res == null -> Unit
                    res.get("ok")?.asBoolean == true -> notify(project, "hibou: ${res.str("message")}")
                    else -> notify(project, "hibou: ${res.str("message")}", NotificationType.WARNING, res.str("webUrl").takeIf { it.isNotEmpty() })
                }
            }
    }

    override fun getActionUpdateThread() = ActionUpdateThread.BGT
}
