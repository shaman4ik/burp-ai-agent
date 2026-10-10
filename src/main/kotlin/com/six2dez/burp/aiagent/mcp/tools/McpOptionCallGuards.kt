package com.six2dez.burp.aiagent.mcp.tools

import burp.api.montoya.MontoyaApi
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

/**
 * Guarded wrappers around the Montoya options export/import calls.
 *
 * Burp 2026.x can block these calls indefinitely when they are entered straight from a
 * Netty/Ktor worker thread. The guards add two safety nets:
 *  - a stdout log line before/after the call so a silent hang is visible in the extension console;
 *  - a hard timeout executed off the calling thread, so an MCP client receives an error
 *    instead of waiting forever.
 *
 * The call itself runs on a dedicated worker (not the EDT): Montoya does not document these
 * methods as requiring the Swing dispatch thread, and pinning them there would risk freezing
 * the UI if Burp internally blocks on something else.
 */
internal object McpOptionCallGuards {
    private const val TIMEOUT_SECONDS = 20L

    fun exportProjectOptions(api: MontoyaApi): String =
        guarded("project_options_get") { api.burpSuite().exportProjectOptionsAsJson() }

    fun exportUserOptions(api: MontoyaApi): String =
        guarded("user_options_get") { api.burpSuite().exportUserOptionsAsJson() }

    fun importProjectOptions(api: MontoyaApi, json: String) {
        guarded("project_options_set") { api.burpSuite().importProjectOptionsFromJson(json) }
    }

    fun importUserOptions(api: MontoyaApi, json: String) {
        guarded("user_options_set") { api.burpSuite().importUserOptionsFromJson(json) }
    }

    private fun <T> guarded(label: String, block: () -> T): T {
        println("[McpOptionCallGuards] $label: entering") // visible in the Burp process stdout
        val result = arrayOfNulls<Any?>(1)
        val error = arrayOfNulls<Throwable>(1)
        val latch = CountDownLatch(1)
        Thread({
            try {
                result[0] = block()
            } catch (t: Throwable) {
                error[0] = t
            } finally {
                latch.countDown()
            }
        }, "mcp-option-$label").start()
        if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            println("[McpOptionCallGuards] $label: TIMED OUT after ${TIMEOUT_SECONDS}s")
            throw IllegalStateException("$label timed out after ${TIMEOUT_SECONDS}s (Montoya call did not return)")
        }
        println("[McpOptionCallGuards] $label: completed")
        error[0]?.let { throw it }
        @Suppress("UNCHECKED_CAST")
        return result[0] as T
    }
}
