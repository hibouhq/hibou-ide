package com.hibouhq.hibou.ide

import com.google.gson.JsonObject
import com.intellij.icons.AllIcons
import com.intellij.ide.BrowserUtil
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.DefaultActionGroup
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.editor.markup.HighlighterLayer
import com.intellij.openapi.editor.markup.HighlighterTargetArea
import com.intellij.openapi.editor.markup.LineMarkerRendererEx
import com.intellij.openapi.editor.markup.RangeHighlighter
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.FileEditorManagerListener
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.popup.JBPopupFactory
import com.intellij.openapi.util.Key
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.ColoredListCellRenderer
import com.intellij.ui.JBColor
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.util.Consumer
import com.redhat.devtools.lsp4ij.LSPIJUtils
import java.awt.Color
import java.awt.Graphics
import java.awt.Rectangle
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.DefaultListModel
import javax.swing.JList
import javax.swing.ListSelectionModel

private val severityOrder = listOf("critical", "high", "medium", "low", "info", "unknown")

/** "1 critical · 2 high" for the severities present. */
internal fun countsLabel(counts: JsonObject?): String {
    if (counts == null) return ""
    val parts = severityOrder.mapNotNull { s -> counts.get(s)?.asInt?.takeIf { it > 0 }?.let { "$it $s" } }
    return if (parts.isEmpty()) "no open findings" else parts.take(2).joinToString(" · ") + if (parts.size > 2) " …" else ""
}

internal fun statusText(st: JsonObject?): String = when (st?.str("state")) {
    null, "" -> "hibou"
    "unconfigured" -> "hibou: set server"
    "signedOut" -> "hibou: sign in"
    "untracked" -> "hibou: not tracked"
    "noSnapshot" -> "hibou: no scan"
    "error" -> "hibou: error"
    else -> buildString {
        append("hibou: ").append(countsLabel(st.obj("counts")))
        st.obj("gate")?.let { g ->
            append(" · gate ")
            append(if (g.str("state") == "pending") "pending" else if (g.get("passed")?.asBoolean == true) "✓" else "✗")
        }
    }
}

class HibouStatusWidgetFactory : StatusBarWidgetFactory {
    override fun getId() = "hibou.status"
    override fun getDisplayName() = "hibou"
    override fun createWidget(project: Project): StatusBarWidget = HibouStatusWidget(project)
}

class HibouStatusWidget(private val project: Project) : StatusBarWidget, StatusBarWidget.TextPresentation {
    private var bar: StatusBar? = null

    override fun ID() = "hibou.status"

    override fun install(statusBar: StatusBar) {
        bar = statusBar
        project.messageBus.connect(this).subscribe(HibouStatusListener.TOPIC, HibouStatusListener { update() })
        project.messageBus.connect(this).subscribe(FileEditorManagerListener.FILE_EDITOR_MANAGER, object : FileEditorManagerListener {
            override fun selectionChanged(event: com.intellij.openapi.fileEditor.FileEditorManagerEvent) = update()
        })
        HibouProjectService.get(project).reloadStatus()
    }

    private fun current(): JsonObject? =
        HibouProjectService.get(project).statusFor(FileEditorManager.getInstance(project).selectedFiles.firstOrNull()?.path)

    private fun update() = ApplicationManager.getApplication().invokeLater { bar?.updateWidget(ID()) }

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this
    override fun getText(): String = statusText(current())
    override fun getAlignment(): Float = 0f
    override fun getTooltipText(): String = current()?.let { st ->
        listOfNotNull(
            st.str("message").takeIf { it.isNotEmpty() },
            st.obj("repo")?.let { "Repository: ${it.str("org")}/${it.str("repo")}" },
            st.obj("snapshot")?.let { if (it.get("atHead")?.asBoolean == true) "Scan of this commit" else "Scan of ancestor ${it.str("commit").take(8)} on ${it.str("ref")}" },
            st.obj("gate")?.let { "PR #${it.str("pr")}: gate ${it.str("state")}" },
            st.str("user").takeIf { it.isNotEmpty() }?.let { "Signed in as $it" },
        ).joinToString("\n")
    } ?: "hibou"

    override fun getClickConsumer(): Consumer<MouseEvent> = Consumer { e ->
        val group = ActionManager.getInstance().getAction("hibou.Menu") as DefaultActionGroup
        JBPopupFactory.getInstance()
            .createActionGroupPopup("hibou", group, com.intellij.openapi.actionSystem.DataContext.EMPTY_CONTEXT, JBPopupFactory.ActionSelectionAid.SPEEDSEARCH, true)
            .showUnderneathOf(e.component)
    }

    override fun dispose() {
        bar = null
    }
}

/** The Findings tool window: the repository's findings, most severe first. */
class HibouToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val model = DefaultListModel<JsonObject>()
        val list = JBList(model).apply {
            selectionMode = ListSelectionModel.SINGLE_SELECTION
            cellRenderer = object : ColoredListCellRenderer<JsonObject>() {
                override fun customizeCellRenderer(list: JList<out JsonObject>, f: JsonObject, index: Int, selected: Boolean, focus: Boolean) {
                    icon = when {
                        f.str("status") == "suppressed" || f.get("accepted")?.asBoolean == true -> AllIcons.RunConfigurations.TestIgnored
                        f.str("severity") in setOf("critical", "high") -> AllIcons.General.Error
                        f.str("severity") == "medium" -> AllIcons.General.Warning
                        else -> AllIcons.General.Information
                    }
                    append(f.str("title").ifEmpty { f.str("rule") })
                    val where = f.str("path").ifEmpty { f.str("component") }
                    val line = f.obj("range")?.obj("start")?.get("line")?.asInt
                    append("  $where${if (f.str("uri").isNotEmpty() && line != null) ":${line + 1}" else ""}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                    if (f.get("edited")?.asBoolean == true) append("  changed since scan", SimpleTextAttributes.GRAYED_ITALIC_ATTRIBUTES)
                }
            }
            addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (e.clickCount == 2) selectedValue?.let { open(project, it) }
                }
            })
        }
        val content = ContentFactory.getInstance().createContent(JBScrollPane(list), "Findings", false)
        toolWindow.contentManager.addContent(content)

        fun reload() {
            HibouProjectService.get(project).server()
                .thenCompose { it?.findings(JsonObject()) }
                .thenAccept { arr ->
                    ApplicationManager.getApplication().invokeLater {
                        model.clear()
                        arr?.forEach { model.addElement(it.asJsonObject) }
                    }
                }
        }
        project.messageBus.connect(content).subscribe(HibouStatusListener.TOPIC, HibouStatusListener { reload() })
        reload()
    }

    private fun open(project: Project, f: JsonObject) {
        val uri = f.str("uri")
        if (uri.isEmpty()) {
            f.str("webUrl").takeIf { it.isNotEmpty() }?.let(BrowserUtil::browse)
            return
        }
        val file = LSPIJUtils.findResourceFor(uri) ?: return
        val line = f.obj("range")?.obj("start")?.get("line")?.asInt ?: 0
        OpenFileDescriptor(project, file, line, 0).navigate(true)
    }
}

/** Line coverage of the last scan as a thin gutter strip (ADR-018 hits). */
object HibouCoverage {
    private val KEY = Key.create<List<RangeHighlighter>>("hibou.coverage")
    private val covered = JBColor(Color(46, 160, 67), Color(46, 160, 67))
    private val uncovered = JBColor(Color(248, 81, 73), Color(248, 81, 73))
    private val partial = JBColor(Color(210, 153, 34), Color(210, 153, 34))

    fun refreshAll(project: Project) {
        for (editor in FileEditorManager.getInstance(project).allEditors.filterIsInstance<com.intellij.openapi.fileEditor.TextEditor>().map { it.editor }) {
            render(project, editor)
        }
    }

    fun render(project: Project, editor: Editor) {
        clear(editor)
        if (!HibouSettings.get().state.coverageEnabled) return
        val file: VirtualFile = editor.virtualFile ?: return
        val params = JsonObject().apply { addProperty("uri", LSPIJUtils.toUriAsString(file)) }
        HibouProjectService.get(project).server()
            .thenCompose { it?.coverage(params) }
            .thenAccept { res ->
                if (res == null) return@thenAccept
                ApplicationManager.getApplication().invokeLater {
                    if (editor.isDisposed) return@invokeLater
                    clear(editor)
                    val doc = editor.document
                    val highlighters = mutableListOf<RangeHighlighter>()
                    fun add(key: String, color: Color) {
                        res.getAsJsonArray(key)?.forEach { el ->
                            val line = el.asInt
                            if (line < 0 || line >= doc.lineCount) return@forEach
                            val h = editor.markupModel.addRangeHighlighter(
                                doc.getLineStartOffset(line), doc.getLineEndOffset(line),
                                HighlighterLayer.FIRST, null, HighlighterTargetArea.LINES_IN_RANGE,
                            )
                            h.lineMarkerRenderer = Strip(color)
                            highlighters += h
                        }
                    }
                    add("covered", covered)
                    add("uncovered", uncovered)
                    add("partial", partial)
                    editor.putUserData(KEY, highlighters)
                }
            }
    }

    private fun clear(editor: Editor) {
        editor.getUserData(KEY)?.forEach { editor.markupModel.removeHighlighter(it) }
        editor.putUserData(KEY, null)
    }

    private class Strip(private val color: Color) : LineMarkerRendererEx {
        override fun paint(editor: Editor, g: Graphics, r: Rectangle) {
            g.color = color
            g.fillRect(r.x, r.y, 3, r.height)
        }

        override fun getPosition() = LineMarkerRendererEx.Position.LEFT
    }
}

class HibouCoverageEditorListener(private val project: Project) : FileEditorManagerListener {
    override fun fileOpened(source: FileEditorManager, file: VirtualFile) {
        source.getAllEditors(file).filterIsInstance<com.intellij.openapi.fileEditor.TextEditor>().forEach { HibouCoverage.render(project, it.editor) }
    }
}
