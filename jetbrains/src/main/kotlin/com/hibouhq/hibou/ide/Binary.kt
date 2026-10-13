package com.hibouhq.hibou.ide

import com.google.gson.JsonParser
import com.intellij.openapi.application.PathManager
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.time.Duration

/**
 * Fetches the language-server binary the configured hibou server serves,
 * verified against the sha256 from /api/v1/bin/version (ADR-042 §2). The
 * binary path setting overrides it.
 */
object HibouBinary {
    private const val MAX_BYTES = 200L * 1024 * 1024

    private val http: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    fun resolve(server: String): Path {
        HibouSettings.get().state.binaryPath?.trim()?.takeIf { it.isNotEmpty() }?.let { return Path.of(it) }

        val key = platformKey(System.getProperty("os.name"), System.getProperty("os.arch"))
            ?: error("hibou ships no binary for this platform; set the binary path in Settings › Tools › hibou.")

        val versionBody = get("$server/api/v1/bin/version", Duration.ofSeconds(15)).toString(Charsets.UTF_8)
        val (version, checksums) = parseBinVersion(versionBody)
        val expected = checksums[key]?.lowercase()
            ?: error("The hibou server serves no binary for $key; set the binary path in Settings › Tools › hibou.")

        val dir = Path.of(PathManager.getSystemPath(), "hibou", "bin", safeVersionDir(version))
        val target = dir.resolve(binaryName(System.getProperty("os.name")))
        if (Files.isRegularFile(target) && sha256Hex(Files.readAllBytes(target)) == expected) return target

        val (os, arch) = key.split("/")
        val data = get("$server/api/v1/bin/$os/$arch", Duration.ofMinutes(5))
        val actual = sha256Hex(data)
        check(actual == expected) { "Downloaded binary checksum $actual does not match the server's $expected; not running it." }

        Files.createDirectories(dir)
        val tmp = Files.createTempFile(dir, "hibou", ".tmp")
        Files.write(tmp, data)
        tmp.toFile().setExecutable(true, true)
        Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        pruneOtherVersions(dir)
        return target
    }

    private fun get(url: String, timeout: Duration): ByteArray {
        val req = HttpRequest.newBuilder(URI(url)).timeout(timeout).GET().build()
        val resp = http.send(req, HttpResponse.BodyHandlers.ofInputStream())
        check(resp.statusCode() in 200..299) { "$url returned HTTP ${resp.statusCode()}" }
        resp.body().use { input ->
            val bytes = input.readNBytes((MAX_BYTES + 1).toInt())
            check(bytes.size <= MAX_BYTES) { "$url is larger than expected" }
            return bytes
        }
    }

    private fun pruneOtherVersions(keep: Path) {
        runCatching {
            Files.list(keep.parent).use { entries ->
                entries.filter { it != keep }.forEach { it.toFile().deleteRecursively() }
            }
        }
    }

    // Pure helpers, unit-tested.

    fun platformKey(osName: String, osArch: String): String? {
        val os = osName.lowercase()
        val goos = when {
            os.contains("linux") -> "linux"
            os.contains("mac") || os.contains("darwin") -> "darwin"
            os.contains("win") -> "windows"
            else -> return null
        }
        val goarch = when (osArch.lowercase()) {
            "amd64", "x86_64" -> "amd64"
            "aarch64", "arm64" -> "arm64"
            else -> return null
        }
        return "$goos/$goarch"
    }

    fun binaryName(osName: String): String = if (osName.lowercase().contains("win")) "hibou.exe" else "hibou"

    fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    fun safeVersionDir(version: String): String =
        version.replace(Regex("[^A-Za-z0-9._-]"), "_").take(64).ifEmpty { "unknown" }

    fun parseBinVersion(body: String): Pair<String, Map<String, String>> {
        val data = JsonParser.parseString(body).asJsonObject.getAsJsonObject("data")
            ?: error("unexpected /api/v1/bin/version response")
        val version = data.get("version")?.asString ?: error("unexpected /api/v1/bin/version response")
        val sums = data.getAsJsonObject("sha256") ?: error("unexpected /api/v1/bin/version response")
        return version to sums.entrySet().associate { it.key to it.value.asString }
    }
}
