package com.six2dez.burp.aiagent

import burp.api.montoya.BurpExtension
import burp.api.montoya.EnhancedCapability
import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicLong

class BurpAiAgentExtension : BurpExtension {
    override fun enhancedCapabilities(): Set<EnhancedCapability> = setOf(EnhancedCapability.AI_FEATURES)

    override fun initialize(api: MontoyaApi) {
        App.initialize(api)
        api.extension().registerUnloadingHandler {
            App.shutdown()
        }
        ChlMuxBridge.install(api)
    }
}

/**
 * Watches proxy responses for Cloudflare managed challenges (Cf-Mitigated: challenge)
 * and pings the local chl-mux multiplexor so that e2zstore traffic flips to the
 * native TLS path for HOLD seconds — Firefox then solves the challenge with its
 * own TLS stack instead of Burp's MITM one.
 */
internal object ChlMuxBridge {
    private const val MUX_URL = "http://127.0.0.1:18082/challenge"
    private val lastPing = AtomicLong(0)

    fun install(api: MontoyaApi) {
        api.proxy().registerResponseHandler(object : ProxyResponseHandler {
            override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
                val mitigated = interceptedResponse.headers().firstOrNull {
                    it.name().equals("Cf-Mitigated", true) && it.value().equals("challenge", true)
                }
                if (mitigated != null && System.currentTimeMillis() - lastPing.get() > 5000) {
                    lastPing.set(System.currentTimeMillis())
                    Thread({
                        try {
                            val conn = URL(MUX_URL).openConnection() as HttpURLConnection
                            conn.connectTimeout = 2000
                            conn.readTimeout = 2000
                            conn.inputStream.use { it.read() }
                            api.logging().logToOutput("chl-mux: challenge detected, flipped traffic to native path")
                        } catch (e: Exception) {
                            api.logging().logToError("chl-mux ping failed: $e")
                        }
                    }, "chl-mux-ping").start()
                }
                return ProxyResponseReceivedAction.continueWith(interceptedResponse)
            }

            override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction =
                ProxyResponseToBeSentAction.continueWith(interceptedResponse)
        })
    }
}
