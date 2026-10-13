package com.hibouhq.hibou.ide

import com.intellij.openapi.options.BoundConfigurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.ui.DialogPanel
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.dsl.builder.bindIntText
import com.intellij.ui.dsl.builder.bindSelected
import com.intellij.ui.dsl.builder.bindText
import com.intellij.ui.dsl.builder.columns
import com.intellij.ui.dsl.builder.panel

/** Settings › Tools › hibou. */
class HibouConfigurable(private val project: Project) : BoundConfigurable("hibou") {
    private val app = HibouSettings.get().state
    private val proj = HibouProjectSettings.get(project).state

    override fun createPanel(): DialogPanel = panel {
        group("Server") {
            row("Server URL:") {
                textField().columns(40)
                    .bindText({ app.server.orEmpty() }, { app.server = ServerUrl.normalize(it).orEmpty() })
                    .comment("Empty uses HIBOU_SERVER or the server from <code>hibou login</code>. The plugin runs the language server binary this server serves.")
                    .validationOnApply {
                        val v = it.text.trim()
                        when {
                            v.isEmpty() -> null
                            ServerUrl.normalize(v) == null -> ValidationInfo("Enter the URL of your hibou server.")
                            ServerUrl.isInsecureRemote(ServerUrl.normalize(v)!!) -> ValidationInfo("Use https:// (plain http is only allowed to localhost).")
                            else -> null
                        }
                    }
            }
            row("Binary path:") {
                textField().columns(40)
                    .bindText({ app.binaryPath.orEmpty() }, { app.binaryPath = it.trim() })
                    .comment("Optional: a local <code>hibou</code> binary instead of the one downloaded from the server.")
            }
        }
        group("Findings") {
            row("Check for new scans every (seconds):") {
                intTextField(30..86_400).bindIntText({ app.pollSeconds }, { app.pollSeconds = it })
            }
            row {
                checkBox("Show suppressed and accepted findings").bindSelected({ app.showSuppressed }, { app.showSuppressed = it })
            }
            row {
                checkBox("Show line coverage in the gutter").bindSelected({ app.coverageEnabled }, { app.coverageEnabled = it })
                    .comment("The hibou server reads the file from your forge to answer.")
            }
            row {
                checkBox("Allow checking staged changes for secrets").bindSelected({ app.secretCheckEnabled }, { app.secretCheckEnabled = it })
                    .comment("Sends your staged diff to the hibou server, which scans it and stores nothing.")
            }
        }
        group("This Project") {
            row("Org (provider/slug):") {
                textField().bindText({ proj.org.orEmpty() }, { proj.org = it.trim() })
                    .comment("Leave empty to detect it from the git remote.")
            }
            row("Repository:") {
                textField().bindText({ proj.repo.orEmpty() }, { proj.repo = it.trim() })
            }
        }
    }

    override fun apply() {
        super.apply()
        for (p in ProjectManager.getInstance().openProjects) {
            HibouProjectService.get(p).restart()
            HibouCoverage.refreshAll(p)
        }
    }
}
