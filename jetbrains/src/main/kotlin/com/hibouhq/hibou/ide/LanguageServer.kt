package com.hibouhq.hibou.ide

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.util.messages.Topic
import com.redhat.devtools.lsp4ij.LanguageServerFactory
import com.redhat.devtools.lsp4ij.LanguageServerManager
import com.redhat.devtools.lsp4ij.client.LanguageClientImpl
import com.redhat.devtools.lsp4ij.server.OSProcessStreamConnectionProvider
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider
import org.eclipse.lsp4j.WorkspaceEdit
import org.eclipse.lsp4j.jsonrpc.services.JsonNotification
import org.eclipse.lsp4j.jsonrpc.services.JsonRequest
import org.eclipse.lsp4j.services.LanguageServer
import java.net.InetAddress
import java.util.concurrent.CompletableFuture

const val SERVER_ID = "hibou"

/** Highest hibou/* protocol version this plugin understands. `hibou lsp`
 * ships with each hibou release while the plugin updates from the
 * Marketplace, so it must cope with older and newer servers (PROTOCOL.md). */
const val SUPPORTED_PROTOCOL = 1

/** The hibou/* requests of `hibou lsp` (internal/lsp/server.go). */
interface HibouServerApi : LanguageServer {
    @JsonRequest("hibou/status") fun status(): CompletableFuture<JsonArray>
    @JsonRequest("hibou/findings") fun findings(params: JsonObject): CompletableFuture<JsonArray>
    @JsonRequest("hibou/refresh") fun refresh(): CompletableFuture<JsonArray>
    @JsonRequest("hibou/login/start") fun loginStart(): CompletableFuture<JsonObject>
    @JsonRequest("hibou/login/wait") fun loginWait(): CompletableFuture<JsonObject>
    @JsonRequest("hibou/login/cancel") fun loginCancel(): CompletableFuture<Any?>
    @JsonRequest("hibou/logout") fun logout(): CompletableFuture<Any?>
    @JsonRequest("hibou/setToken") fun setToken(params: JsonObject): CompletableFuture<Any?>
    @JsonRequest("hibou/suppressionEdit") fun suppressionEdit(params: JsonObject): CompletableFuture<WorkspaceEdit>
    @JsonRequest("hibou/triage") fun triage(params: JsonObject): CompletableFuture<JsonObject>
    @JsonRequest("hibou/coverage") fun coverage(params: JsonObject): CompletableFuture<JsonObject>
    @JsonRequest("hibou/secretCheck") fun secretCheck(params: JsonObject): CompletableFuture<JsonObject>
}

class HibouServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider = HibouConnectionProvider(project)

    override fun createLanguageClient(project: Project): LanguageClientImpl = HibouLanguageClient(project)

    override fun getServerInterface(): Class<out LanguageServer> = HibouServerApi::class.java
}

/** Starts `hibou lsp`. The binary is resolved (and maybe downloaded) on
 * start, which LSP4IJ runs off the UI thread. */
class HibouConnectionProvider(private val project: Project) : OSProcessStreamConnectionProvider() {
    private var server: String? = null

    override fun start() {
        val server = ServerUrl.resolve() ?: error("Set the hibou server URL in Settings › Tools › hibou.")
        check(!ServerUrl.isInsecureRemote(server)) { "Refusing plain http to $server: use https." }
        this.server = server
        val binary = HibouBinary.resolve(server)
        val cmd = GeneralCommandLine(binary.toString(), "lsp")
            .withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE)
            .withEnvironment("HIBOU_SERVER", server)
        // The token travels in the environment, never on the command line (ADR-042 §3).
        HibouCredentials.token(server)?.let { cmd.withEnvironment("HIBOU_TOKEN", it) }
        commandLine = cmd
        super.start()
    }

    override fun getInitializationOptions(rootUri: VirtualFile?): Any {
        val s = HibouSettings.get().state
        val p = HibouProjectSettings.get(project).state
        return mapOf(
            "server" to (server ?: ServerUrl.resolve().orEmpty()),
            "clientId" to "hibou-intellij",
            "clientName" to runCatching { InetAddress.getLocalHost().hostName }.getOrDefault("IntelliJ"),
            "org" to p.org.orEmpty(),
            "repo" to p.repo.orEmpty(),
            "pollSeconds" to s.pollSeconds,
            "showSuppressed" to s.showSuppressed,
            "secretCheck" to s.secretCheckEnabled,
        )
    }
}

class HibouLanguageClient(project: Project) : LanguageClientImpl(project) {
    @JsonNotification("hibou/statusChanged")
    fun statusChanged(status: JsonObject) {
        project.service<HibouProjectService>().onStatus(status)
    }
}

fun interface HibouStatusListener {
    fun statusChanged()

    companion object {
        val TOPIC = Topic.create("hibou status", HibouStatusListener::class.java)
    }
}

/** The project's view of the language server: latest statuses and access to
 * the hibou/* requests. */
@Service(Service.Level.PROJECT)
class HibouProjectService(private val project: Project) {
    @Volatile
    var statuses: List<JsonObject> = emptyList()
        private set

    fun onStatus(status: JsonObject) {
        val root = status.str("root")
        statuses = statuses.filter { it.str("root") != root && it.str("root").isNotEmpty() } + status
        project.messageBus.syncPublisher(HibouStatusListener.TOPIC).statusChanged()
    }

    fun setStatuses(list: JsonArray) {
        statuses = list.map { it.asJsonObject }
        project.messageBus.syncPublisher(HibouStatusListener.TOPIC).statusChanged()
    }

    /** The status of the workspace containing path, else the first one. */
    fun statusFor(path: String?): JsonObject? {
        if (path != null) {
            val norm = path.replace('\\', '/').lowercase()
            statuses.filter { s ->
                val root = s.str("root").replace('\\', '/').lowercase()
                root.isNotEmpty() && (norm == root || norm.startsWith("$root/"))
            }.maxByOrNull { it.str("root").length }?.let { return it }
        }
        return statuses.firstOrNull()
    }

    fun server(): CompletableFuture<HibouServerApi?> =
        LanguageServerManager.getInstance(project).getLanguageServer(SERVER_ID).thenApply { it?.server as? HibouServerApi }

    fun restart() {
        protocolChecked = false
        val manager = LanguageServerManager.getInstance(project)
        manager.stop(SERVER_ID)
        manager.start(SERVER_ID)
    }

    @Volatile
    private var protocolChecked = false

    /** Warns once per server start when the server is not a compatible hibou
     * LSP or speaks a newer protocol than this plugin. */
    private fun checkProtocol() {
        if (protocolChecked) return
        LanguageServerManager.getInstance(project).getLanguageServer(SERVER_ID).thenAccept { item ->
            if (item == null) return@thenAccept // not started yet: check on the next reload
            protocolChecked = true
            val experimental = item.serverCapabilities?.experimental
            val json = experimental as? JsonObject
                ?: experimental?.let { runCatching { com.google.gson.Gson().toJsonTree(it).asJsonObject }.getOrNull() }
            val protocol = json?.obj("hibou")?.get("protocol")?.takeIf { it.isJsonPrimitive }?.asInt
            when {
                protocol == null -> notify(project, "The hibou language server is not compatible with this plugin. Upgrade your hibou server, or fix the binary path.", com.intellij.notification.NotificationType.ERROR)
                protocol > SUPPORTED_PROTOCOL -> notify(project, "Your hibou server speaks a newer IDE protocol ($protocol) than this plugin ($SUPPORTED_PROTOCOL). Update the hibou plugin.", com.intellij.notification.NotificationType.WARNING)
            }
        }
    }

    /** Refreshes statuses once the server answers; used after (re)start. */
    fun reloadStatus() {
        checkProtocol()
        server().thenCompose { it?.status() ?: CompletableFuture.completedFuture(null) }
            .thenAccept { list -> list?.let(::setStatuses) }
            .exceptionally { logger<HibouProjectService>().info("hibou status unavailable: ${it.message}"); null }
    }

    companion object {
        fun get(project: Project): HibouProjectService = project.service()
    }
}

fun JsonObject.str(key: String): String = get(key)?.takeIf { it.isJsonPrimitive }?.asString.orEmpty()

fun JsonObject.obj(key: String): JsonObject? = get(key)?.takeIf { it.isJsonObject }?.asJsonObject
