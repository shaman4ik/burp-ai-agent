# Captain fork of six2dez/burp-ai-agent

Branch `captain/2026.9-compat`. Runs on Burp Pro 2026.9.1 (loader-activated),
backend = claude-cli through a local gateway.

## Why the fork (2026-10-09)

1. **AI gate.** Loader-activated Burp Pro reports `api.ai().isEnabled() == false`
   ("feature unavailable"), which hard-gates every AI tool. Our AI backend is the
   extension's own (claude-cli), not PortSwigger cloud.
   Patch: `AgentSupervisor.isAiEnabled()` → `true`.

2. **Proxy history type break.** On Burp 2026.9+ `Proxy.history()` returns
   `List<ProxyHttpRequestResponse>` which does NOT extend `HttpRequestResponse`.
   The `as List<HttpRequestResponse>` cast in the `ai_passive_scan` branch throws
   `ClassCastException` (`jdk.proxy2.$ProxyN cannot be cast to HttpRequestResponse`),
   swallowed by `McpToolKt.runTool`'s catch — passive scan silently dies.
   Diagnosed live via jdb (`-agentlib:jdwp` in the launcher).
   Patch: `compat/Compat.kt` rehydrates entries reflectively
   (`request()`/`response()` → `HttpRequestResponse.httpRequestResponse(...)`)
   before the cast. Only `ai_passive_scan` needs it; the other history tools
   already speak `ProxyHttpRequestResponse` (`listenerPort()` etc.).

## Known upstream issues seen on 2026.9.1 (not fixed here)

- claude 2.1.285 CLI does not know `--skip-git-repo-check` / `--output-last-message`
  → every one-shot spawn died silently. Workaround: `tools/claude-burp.sh` wrapper
  (strips the first flag, emulates the second, silences stderr in -p mode).
- MCP kotlin-sdk 0.5.0: long-running tool calls (ai_analyze) complete server-side
  but the response is not always delivered (completion latch misses; duplicate
  empty `_meta` responses on the wire). Fast tools deliver fine.

## Build & deploy

    JAVA_HOME=/opt/jdk-22.0.2+9 ./gradlew shadowJar -x test --no-daemon
    cp build/libs/Custom-AI-Agent-full-1.0.0.jar ~/burp/Custom-AI-Agent-full-1.0.0.jar

Restart Burp afterwards. The AI supervisor session is started by the passive
scanner pipeline under a Live audit task (Run continuously), or by an active
audit task.
