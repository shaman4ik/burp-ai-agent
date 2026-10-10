package com.six2dez.burp.aiagent.mcp

import burp.api.montoya.MontoyaApi
import com.six2dez.burp.aiagent.BuildFlags
import com.six2dez.burp.aiagent.audit.AiRequestLogger
import com.six2dez.burp.aiagent.backends.BackendRegistry
import com.six2dez.burp.aiagent.config.McpSettings
import com.six2dez.burp.aiagent.mcp.tools.ResponsePreprocessorSettings
import com.six2dez.burp.aiagent.mcp.tools.registerTools
import com.six2dez.burp.aiagent.redact.PrivacyMode
import com.six2dez.burp.aiagent.scanner.PassiveAiScanner
import com.six2dez.burp.aiagent.supervisor.AgentSupervisor
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.applicationEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import kotlin.time.Duration.Companion.seconds
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

class KtorMcpServerManager(
    private val api: MontoyaApi,
    private val contextFactory: McpRuntimeContextFactory = McpRuntimeContextFactory(api),
) : McpServerManager {
    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    private data class CorsAllowedHost(
        val hostAndPort: String,
        val scheme: String,
    )

    override fun setAiRequestLogger(logger: AiRequestLogger) {
        contextFactory.aiRequestLogger = logger
    }

    override fun setAiToolDependencies(
        supervisor: AgentSupervisor,
        passiveScanner: PassiveAiScanner,
        backendRegistry: BackendRegistry,
    ) {
        contextFactory.supervisor = supervisor
        contextFactory.passiveScanner = passiveScanner
        contextFactory.backendRegistry = backendRegistry
    }

    override fun start(
        settings: McpSettings,
        privacyMode: PrivacyMode,
        determinismMode: Boolean,
        preprocessSettings: ResponsePreprocessorSettings,
        callback: (McpServerState) -> Unit,
    ) {
        callback(McpServerState.Starting)
        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                if (settings.externalEnabled && !settings.tlsEnabled) {
                    error("External MCP access requires TLS. Enable TLS to continue.")
                }
                if (!settings.externalEnabled && !isLoopbackHost(settings.host)) {
                    error("MCP host must be loopback when external access is disabled.")
                }
                // SEC-05 5c / F19: LOG, do not throw. The gate already denies every non-health
                // request with 401 BlockReason.BLANK_TOKEN in this configuration, so failing closed
                // is guaranteed without refusing to bind. Letting the port bind keeps the
                // misconfiguration diagnosable — a start failure would only surface as a generic
                // "Failed" state in the UI.
                if (settings.externalEnabled && settings.token.isBlank()) {
                    api.logging().logToError(
                        "MCP external access is enabled with a blank bearer token — every request will be rejected " +
                            "with 401. Generate a token in Settings.",
                    )
                }

                val context = contextFactory.create(settings, privacyMode, determinismMode, preprocessSettings)
                val externalCorsHosts = parseExternalCorsHosts(settings.allowedOrigins)
                if (settings.externalEnabled && externalCorsHosts.isEmpty()) {
                    api.logging().logToOutput(
                        "MCP external mode has no allowed origins configured; using permissive CORS (any origin).",
                    )
                }

                val mcpServer =
                    Server(
                        // SEC-05 5a / F11: advertise the real build version. Only the version half
                        // changes — "burp-ai-agent" is a protocol identifier MCP clients may key on,
                        // so renaming it is a decision, not a defect fix (RESEARCH pitfall P12).
                        serverInfo = Implementation("burp-ai-agent", BuildFlags.VERSION),
                        options =
                            ServerOptions(
                                capabilities =
                                    ServerCapabilities(
                                        tools = ServerCapabilities.Tools(listChanged = false),
                                    ),
                            ),
                    )

                // D-06/D-07/D-09/D-10: exactly ONE reporter per start() invocation, never one per
                // request — the per-reason rate-limit windows live in instance state, so a
                // per-request instance would print every single block and suppress nothing.
                // Not the trailing-lambda form: the constructor's LAST parameter is `verboseAudit`,
                // so `McpBlockedRequestReporter { … }` would bind the lambda to the wrong parameter.
                val reporter = McpBlockedRequestReporter(logToOutput = { line -> api.logging().logToOutput(line) })
                // The gate reads an immutable snapshot. A local alias is needed because a function
                // parameter shadows an implicit-receiver member of the same name, so plain
                // `settings = settings` inside the install{} config lambda cannot compile.
                val settingsSnapshot = settings

                val environment = applicationEnvironment { }
                val serverInstance =
                    embeddedServer(Netty, environment, configure = {
                        if (settings.tlsEnabled) {
                            val tlsMaterial =
                                McpTls.resolve(settings)
                                    ?: error("TLS enabled but keystore not available.")
                            sslConnector(
                                keyStore = tlsMaterial.keyStore,
                                keyAlias = tlsMaterial.keyAlias,
                                keyStorePassword = { tlsMaterial.password },
                                privateKeyPassword = { tlsMaterial.password },
                            ) {
                                host = settings.host
                                port = settings.port
                            }
                        } else {
                            connector {
                                host = settings.host
                                port = settings.port
                            }
                        }
                    }) {
                        install(CORS) {
                            if (!settings.externalEnabled) {
                                allowHost("localhost:${settings.port}")
                                allowHost("127.0.0.1:${settings.port}")
                            } else {
                                if (externalCorsHosts.isEmpty()) {
                                    anyHost()
                                } else {
                                    externalCorsHosts.forEach { allowed ->
                                        allowHost(allowed.hostAndPort, schemes = listOf(allowed.scheme))
                                    }
                                }
                            }
                            allowMethod(HttpMethod.Get)
                            allowMethod(HttpMethod.Post)
                            allowHeader("Content-Type")
                            allowHeader("Accept")
                            allowHeader("Authorization")
                            allowHeader("Last-Event-ID")
                            allowCredentials = false
                            allowNonSimpleContentTypes = true
                            maxAgeInSeconds = 3600
                        }

                        // SEC-04 / F1: ORDER IS LOAD-BEARING — CORS FIRST, gate SECOND.
                        // Both live in the Plugins phase, where relative order is install order. It
                        // was measured that with the gate first a legitimate preflight gets 401 and
                        // browser CORS breaks; with CORS first plus the gate's isCommitted guard a
                        // legitimate preflight returns 200 with Access-Control-Allow-Origin, a
                        // foreign-origin preflight still gets CORS's own 403, and every real request
                        // is still gated. The gate's PHASE (not this line's position) is what makes it
                        // run before routing, so moving it below routing{} would still be correct —
                        // but moving it ABOVE install(CORS) would not.
                        install(McpAccessControl) {
                            // Explicit `this.` because the enclosing start() parameter named
                            // `settings` shadows the config property of the same name.
                            this.settings = settingsSnapshot
                            onBlocked = { deny ->
                                reporter.report(deny, settingsSnapshot.externalEnabled, System.currentTimeMillis())
                            }
                        }

                        routing {
                            get("/__mcp/health") {
                                // D-02: the identity header is a local-mode-only signal. In external
                                // mode an unauthenticated scan must not be able to confirm that a
                                // Burp AI Agent sits behind this port; the route itself stays
                                // reachable for liveness (D-01), just not for identification.
                                if (!settingsSnapshot.externalEnabled) {
                                    call.response.headers.append("X-Burp-AI-Agent", "mcp")
                                }
                                call.respondText("ok")
                            }
                            // SHUTDOWN_PATH, not a literal: the access-control gate now matches this
                            // same path to recognise the SEC-07 proof credential, and the two must not
                            // drift apart.
                            post(SHUTDOWN_PATH) {
                                // SEC-07: two accepted credential forms, and the order is not
                                // load-bearing. The bearer check is unchanged so an operator driving
                                // this endpoint by hand still works; the proof form is what the
                                // bind-conflict takeover client now presents, because the token must
                                // never reach a port holder whose identity cannot be established.
                                val authHeader = call.request.headers["Authorization"].orEmpty()
                                val proof = call.request.headers[McpTakeoverProof.HEADER].orEmpty()
                                if (!isAuthorized(authHeader, settings.token) &&
                                    !McpTakeoverProof.accepts(settings.token, settings.host, settings.port, System.currentTimeMillis(), proof)
                                ) {
                                    call.respond(HttpStatusCode.Unauthorized)
                                    return@post
                                }
                                call.respondText("shutting down")
                                executor.submit {
                                    try {
                                        server?.stop(1000, 5000)
                                    } catch (e: Exception) {
                                        api.logging().logToError("MCP shutdown failed: ${e.message}")
                                    }
                                }
                            }
                        }

                        // SEC-04 / F1: a Call-phase security interceptor USED TO SIT HERE. Do not
                        // restore it. RoutingRoot.Plugin.install registers its own interceptor in the
                        // very same Call phase at the moment of the first routing{} call,
                        // same-phase interceptors run in registration order, and RoutingRoot's
                        // interceptor never ends the pipeline — so every resolved route (including
                        // the SDK's /sse and /message) was served BEFORE these checks ran. The checks
                        // now live in McpAccessControlPlugin.kt, whose onCall attaches to the
                        // Plugins phase and therefore cannot be outrun by routing.

                        // Streamable HTTP (spec 2025-11-25): single /mcp endpoint for POST +
                        // optional GET stream. Replaces the legacy SSE pair (/sse + /message) whose
                        // idle sessions died silently after ~180s: the socket closed, the session
                        // stayed in the map, POSTs were accepted with 202 but the CallToolResult
                        // never reached a live stream and clients waited forever. Streamable
                        // transports clean up dead sessions, and the 30s heartbeat keeps the GET
                        // stream alive across quiet periods.
                        // DNS-rebinding protection is OFF here because McpAccessControl (Plugins
                        // phase) already gates every route by Host/Origin/token — the SDK's own
                        // route-local check would only duplicate it and reject proxied Hosts.
                        mcpStreamableHttp(
                            path = "/mcp",
                            enableDnsRebindingProtection = false,
                            sseHeartbeatConfig = {
                                period = 30.seconds
                            },
                        ) {
                            mcpServer
                        }

                        mcpServer.registerTools(api, context)
                    }

                server = serverInstance.apply { start(false) }
                api.logging().logToOutput("Started MCP server on ${settings.host}:${settings.port}")
                callback(McpServerState.Running)
            } catch (e: Exception) {
                api.logging().logToError(e)
                callback(McpServerState.Failed(e))
            }
        }
    }

    override fun stop(callback: (McpServerState) -> Unit) {
        callback(McpServerState.Stopping)
        // REL-02/SC5a: bound the submitted server-stop task so stop() never hangs.
        // RESTART-SAFE: we use future.get(BOUND) only — NOT executor.shutdown/awaitTermination/shutdownNow.
        // Terminating the executor here would cause start() to throw RejectedExecutionException on
        // the next restart attempt (the single-thread executor is shared across start/stop cycles).
        // awaitTermination+shutdownNow is correct ONLY in the terminal shutdown() method below.
        val future =
            executor.submit {
                try {
                    server?.stop(1000, 5000)
                    server = null
                    api.logging().logToOutput("Stopped MCP server")
                    callback(McpServerState.Stopped)
                } catch (e: Exception) {
                    api.logging().logToError(e)
                    callback(McpServerState.Failed(e))
                }
            }
        try {
            future.get(10, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            // Force-stop: the server task is taking too long. Cancel the future and force-stop
            // any remaining server reference so the port is released.
            future.cancel(true)
            try {
                server?.stop(0, 0)
            } catch (_: Exception) {
            }
            server = null
            // Always fire the callback so the UI never waits forever (DoS mitigation).
            callback(McpServerState.Stopped)
        } catch (e: Exception) {
            api.logging().logToError(e)
            callback(McpServerState.Failed(e))
        }
    }

    override fun shutdown() {
        server?.stop(1000, 5000)
        server = null
        executor.shutdown()
        if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
            executor.shutdownNow()
        }
    }

    /**
     * D-04: the `/__mcp/shutdown` handler keeps its own in-handler token check as defence in depth —
     * it is literally the one control that survived the F1 bypass. The body now delegates to the
     * decision core, so the handler inherits the SEC-05 5c blank-token guard for free.
     */
    private fun isAuthorized(
        authHeader: String,
        token: String,
    ): Boolean = isAuthorizedBearer(authHeader, token)

    /**
     * Bind-address guard used by [start]. Delegates to the shared D-11 authority predicate with a null
     * expected port, so `localhost`, `127.0.0.1` and `::1` all still pass.
     */
    private fun isLoopbackHost(host: String): Boolean = isLoopbackAuthority(host, null)

    // SEC-05 5b / D-11 / F12: constantTimeEquals, isValidOrigin, isBrowserRequest, isValidHost and
    // isValidReferer were DELETED here. Their logic lives in McpAccessControlDecision.kt behind one
    // shared loopback-authority predicate, which is what stops the Host / Origin / Referer checks
    // from drifting apart again — and what fixes the bracketed-IPv6 split(":") defect.

    private fun parseExternalCorsHosts(origins: List<String>): List<CorsAllowedHost> {
        if (origins.isEmpty()) return emptyList()
        val dedup = LinkedHashSet<CorsAllowedHost>()
        origins.forEach { raw ->
            val normalized = normalizeOrigin(raw)
            if (normalized == null) {
                return@forEach
            }
            dedup.add(normalized)
        }
        return dedup.toList()
    }

    private fun normalizeOrigin(raw: String): CorsAllowedHost? {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return null
        val candidate = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        return try {
            val uri = URI(candidate)
            val scheme = uri.scheme?.lowercase() ?: return null
            if (scheme != "http" && scheme != "https") return null
            val host = uri.host?.lowercase() ?: return null
            val hostAndPort = if (uri.port > 0) "$host:${uri.port}" else host
            CorsAllowedHost(hostAndPort = hostAndPort, scheme = scheme)
        } catch (_: Exception) {
            null
        }
    }
}
