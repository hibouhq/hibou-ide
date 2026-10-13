package com.hibouhq.hibou.ide

import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.Credentials
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.openapi.components.BaseState
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.SimplePersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project

/**
 * Application-level settings. The server URL and binary path are deliberately
 * not project settings: the plugin runs the binary the server serves, so a
 * project must not be able to choose either (ADR-042 §2).
 */
@Service(Service.Level.APP)
@State(name = "HibouSettings", storages = [Storage("hibou.xml")])
class HibouSettings : SimplePersistentStateComponent<HibouSettings.S>(S()) {
    class S : BaseState() {
        var server by string("")
        var binaryPath by string("")
        var pollSeconds by property(120)
        var showSuppressed by property(false)
        var coverageEnabled by property(false)
        // Consent to send staged diffs to the server's secret check (ADR-042 phase 3).
        var secretCheckEnabled by property(false)
    }

    companion object {
        fun get(): HibouSettings = service()
    }
}

/** Per-project overrides of git-remote detection. Harmless to share. */
@Service(Service.Level.PROJECT)
@State(name = "HibouProjectSettings", storages = [Storage("hibou.xml")])
class HibouProjectSettings : SimplePersistentStateComponent<HibouProjectSettings.S>(S()) {
    class S : BaseState() {
        var org by string("")
        var repo by string("")
    }

    companion object {
        fun get(project: Project): HibouProjectSettings = project.service()
    }
}

/** Tokens live in the IDE's password safe, one per server URL (ADR-042 §3). */
object HibouCredentials {
    private fun attributes(server: String) = CredentialAttributes(generateServiceName("hibou", server))

    fun token(server: String): String? = PasswordSafe.instance.getPassword(attributes(server))?.takeIf { it.isNotBlank() }

    fun store(server: String, token: String) = PasswordSafe.instance.set(attributes(server), Credentials("token", token))

    fun clear(server: String) = PasswordSafe.instance.set(attributes(server), null)
}

/** Server URL rules shared with the CLI (ADR-043): https by default, no trailing slash. */
object ServerUrl {
    fun normalize(raw: String?): String? {
        var s = raw?.trim().orEmpty()
        if (s.isEmpty()) return null
        if (!s.contains("://")) s = "https://$s"
        val uri = runCatching { java.net.URI(s) }.getOrNull() ?: return null
        if (uri.scheme != "https" && uri.scheme != "http") return null
        if (uri.host.isNullOrEmpty()) return null
        return s.trimEnd('/')
    }

    /** Plain http is only acceptable to a loopback server. */
    fun isInsecureRemote(server: String): Boolean {
        val uri = java.net.URI(server)
        if (uri.scheme != "http") return false
        val host = uri.host.trim('[', ']')
        return !(host == "localhost" || host == "::1" || host.startsWith("127."))
    }

    /** The configured server: settings, then HIBOU_SERVER, then `hibou login`'s config. */
    fun resolve(): String? =
        normalize(HibouSettings.get().state.server)
            ?: normalize(System.getenv("HIBOU_SERVER"))
            ?: normalize(cliConfigServer())

    private fun cliConfigServer(): String? {
        val os = System.getProperty("os.name").lowercase()
        val home = System.getProperty("user.home")
        val base = when {
            os.contains("win") -> System.getenv("APPDATA")
            os.contains("mac") -> "$home/Library/Application Support"
            else -> System.getenv("XDG_CONFIG_HOME")?.takeIf { it.isNotBlank() } ?: "$home/.config"
        } ?: return null
        val file = java.io.File(base, "hibou/config.yaml")
        if (!file.isFile) return null
        return Regex("""^server:\s*["']?([^"'\s#]+)""", RegexOption.MULTILINE).find(file.readText())?.groupValues?.get(1)
    }
}
