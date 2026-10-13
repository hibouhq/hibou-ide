package com.hibouhq.hibou.ide

import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PureTest {
    @Test
    fun platformKeys() {
        assertEquals("linux/amd64", HibouBinary.platformKey("Linux", "amd64"))
        assertEquals("darwin/arm64", HibouBinary.platformKey("Mac OS X", "aarch64"))
        assertEquals("windows/amd64", HibouBinary.platformKey("Windows 11", "x86_64"))
        assertNull(HibouBinary.platformKey("FreeBSD", "amd64"))
        assertNull(HibouBinary.platformKey("Linux", "x86"))
        assertEquals("hibou.exe", HibouBinary.binaryName("Windows 11"))
    }

    @Test
    fun checksumAndVersion() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", HibouBinary.sha256Hex("abc".toByteArray()))
        val (version, sums) = HibouBinary.parseBinVersion("""{"data":{"version":"v1.2.3","sha256":{"linux/amd64":"ab"}}}""")
        assertEquals("v1.2.3", version)
        assertEquals(mapOf("linux/amd64" to "ab"), sums)
        assertEquals(".._.._etc", HibouBinary.safeVersionDir("../../etc"))
    }

    @Test
    fun serverUrls() {
        assertEquals("https://hibou.example.com", ServerUrl.normalize("hibou.example.com"))
        assertEquals("https://h.example.com/sub", ServerUrl.normalize(" https://h.example.com/sub/ "))
        assertNull(ServerUrl.normalize("ftp://x"))
        assertFalse(ServerUrl.isInsecureRemote("http://localhost:8080"))
        assertFalse(ServerUrl.isInsecureRemote("http://127.0.0.1"))
        assertTrue(ServerUrl.isInsecureRemote("http://hibou.example.com"))
    }

    @Test
    fun statusTexts() {
        val st = JsonParser.parseString("""{"state":"ready","counts":{"high":2,"critical":1,"low":3},"gate":{"pr":"7","state":"failure","passed":false}}""").asJsonObject
        assertEquals("hibou: 1 critical · 2 high … · gate ✗", statusText(st))
        assertEquals("hibou: sign in", statusText(JsonParser.parseString("""{"state":"signedOut"}""").asJsonObject))
        assertEquals("no open findings", countsLabel(JsonParser.parseString("{}").asJsonObject))
    }
}
