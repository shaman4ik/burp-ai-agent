package com.six2dez.burp.aiagent.compat

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

/**
 * CAPTAIN PATCH 2026-10-09 — Burp 2026.9+ compat.
 *
 * In newer Burp builds `Proxy.history()` returns `List<ProxyHttpRequestResponse>`,
 * which does NOT extend `HttpRequestResponse`. Code compiled against montoya-api
 * 2026.2 fails with ClassCastException / IncompatibleClassChangeError on every
 * history entry (ai_passive_scan, proxy_http_history, response_body_search, ...).
 *
 * Rehydrate each entry reflectively into a real HttpRequestResponse so the rest
 * of the extension sees the type it was compiled against.
 */
object Compat {
    fun convertList(history: List<*>?): List<HttpRequestResponse>? =
        history?.map { convertOne(it) }

    fun convertOne(entry: Any?): HttpRequestResponse? {
        if (entry == null) return null
        if (entry is HttpRequestResponse) return entry
        return runCatching {
            val request = entry.javaClass.getMethod("request").invoke(entry) as? HttpRequest
                ?: return null
            val response = entry.javaClass.getMethod("response").invoke(entry) as? HttpResponse
                ?: HttpResponse.httpResponse("")
            HttpRequestResponse.httpRequestResponse(request, response)
        }.getOrNull()
    }
}
