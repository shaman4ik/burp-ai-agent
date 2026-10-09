package com.six2dez.burp.aiagent.redact

import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

// ReDoS-safe regex utility.
//
// The JDK Matcher has no built-in timeout (JDK-8234713 "Won't fix"). This object bounds any
// single regex match to ~50 ms by wrapping the input in a DeadlineCharSequence whose get()
// throws RegexTimeoutException once System.nanoTime() exceeds the deadline. The Matcher reads
// input characters via CharSequence.get() during backtracking, so the deadline is observed
// promptly even under catastrophic backtracking.
//
// Reference: https://www.ocpsoft.org/regex/how-to-interrupt-a-long-running-infinite-java-regular-expression/
// [CITED — interruptible-CharSequence idiom, adapted to use a nanoTime deadline instead of
//  Thread.interrupted() so it works without requiring external thread management.]
//
// Design decisions mirrored from SecretCipher.kt:
//   - fail-soft: never throw into the redaction pipeline; return a safe fallback.
//   - no ExecutorService: avoids orphaned threads in Burp's long-lived JVM process.
//   - AWT-free: no java.awt / javax.swing imports so Phase 15's scanner-side tripwire can reuse
//     this file headless.

// Thrown by DeadlineCharSequence.get() when the match deadline is exceeded.
internal class RegexTimeoutException : RuntimeException()

// Wraps a CharSequence so that each get() call checks a nanoTime deadline before returning the
// character. The Matcher's inner backtracking loop calls CharSequence.get() (charAt) on every
// character access, so the deadline is observed promptly even under catastrophic backtracking.
private class DeadlineCharSequence(
    private val inner: CharSequence,
    private val deadlineNanos: Long,
) : CharSequence {
    override val length: Int get() = inner.length

    override fun get(index: Int): Char {
        if (System.nanoTime() > deadlineNanos) throw RegexTimeoutException()
        return inner[index]
    }

    override fun subSequence(
        startIndex: Int,
        endIndex: Int,
    ): CharSequence = DeadlineCharSequence(inner.subSequence(startIndex, endIndex), deadlineNanos)

    override fun toString(): String = inner.toString()
}

object SafeRegex {
    /**
     * Maximum wall-clock time (in milliseconds) allowed for a single regex match or probe.
     * Corresponds to the "50 ms per-pattern timeout" described in PRIV-02 / SC3.
     */
    const val DEFAULT_TIMEOUT_MS = 50L

    /**
     * Outcome of a bounded replacement (PRIV-06 / D-14).
     *
     * [timedOut] is the ONLY reliable signal that the pattern did not complete. [text] equals the
     * original input in BOTH the "the pattern matched nothing" case and the "the pattern never
     * finished" case, so a caller that inspects [text] alone cannot tell those two apart. A caller
     * that must fail closed — a body-redaction window whose unscanned bytes must never reach a
     * backend — has to branch on [timedOut], never on whether [text] changed.
     *
     * WR-03: THERE IS DELIBERATELY NO UN-REPORTING FAÇADE, and this note exists so the next person
     * who wants one finds the reason here instead of re-adding it.
     *
     * The DELETED function was `replaceAllSafe` — a `String`-returning one-line delegate that sat
     * beside [replaceAllSafeReporting] and returned exactly this [text] (the name is spelled out on
     * this line on purpose, so that grepping for it lands on its obituary). It ended Phase 21 with
     * ZERO production callers while its own KDoc named its hazard — "fail-open", "conflates
     * 'matched nothing' with 'timed out'" — i.e. a public fail-open replacement entry point inside
     * the redaction package, one autocomplete away from the next contributor who adds a rule. It was
     * removed (maintainer scope decision, 2026-08-12) rather than deprecated, because a `String`
     * return type structurally CANNOT carry [timedOut] and D-02 requires every body rule to fail
     * CLOSED on a timeout: a deprecated-but-callable fail-open helper is still a fail-open helper.
     * The shape that replaces it is explicit and one line longer:
     * `val r = replaceAllSafeReporting(...); if (r.timedOut) <fail closed> else r.text`.
     */
    data class SafeReplaceResult(
        val text: String,
        val timedOut: Boolean,
    )

    /**
     * Replaces all matches of [pattern] in [input] with [replacement], bounding the match to
     * [timeoutMs] milliseconds, and reports whether the match ran to completion (PRIV-06 / D-14).
     *
     * This is the ONLY replacement entry point in the redaction package (WR-03).
     *
     * On timeout [SafeReplaceResult.text] is the ORIGINAL [input] — fail-soft on the TEXT, so the
     * redaction pipeline never hangs and never corrupts content on account of a slow pattern — but
     * [SafeReplaceResult.timedOut] is true, which is what lets a caller drop unscanned content
     * instead of silently passing it through. See [SafeReplaceResult] for why the flag, not the
     * text, is the signal, and for why no `String`-returning convenience wrapper exists.
     */
    fun replaceAllSafeReporting(
        input: String,
        pattern: Pattern,
        replacement: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ): SafeReplaceResult =
        try {
            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            val matcher = pattern.matcher(DeadlineCharSequence(input, deadline))
            SafeReplaceResult(matcher.replaceAll(replacement), false)
        } catch (_: RegexTimeoutException) {
            // Fail-soft on the text as before, but report the timeout so the caller can fail closed.
            SafeReplaceResult(input, true)
        } catch (_: StackOverflowError) {
            // Java's regex engine recurses on lazy quantifiers. A fat body (CF challenge, OTP blob)
            // overflows the thread stack before DeadlineCharSequence can fire. Same outcome as a
            // timeout: caller drops the unscanned window instead of killing the MCP tool.
            SafeReplaceResult(input, true)
        }

    /**
     * Returns true if [regex] compiles successfully AND finishes matching EVERY probe in
     * [ADVERSARIAL_PROBES] within [timeoutMs] milliseconds each.
     *
     * Returns false if:
     *   - the regex fails to compile (PatternSyntaxException), or
     *   - the regex can match the empty string (WR-01 — its own distinct rejection, below), or
     *   - the match against ANY probe times out (RegexTimeoutException). The first timeout rejects;
     *     the remaining probes are not run.
     *
     * Used by the custom-pattern save-validation path (`SettingsPanel.validateAndCollectCustomPatterns`,
     * on the EDT) per SC3, and by `App.initialize`'s startup re-validation of the persisted list
     * (WR-07 / T-21-64).
     *
     * COST. Benign patterns complete in microseconds against every probe — a realistic ten-pattern
     * list measured 0.44 ms across the single old probe and 2.2 ms across the whole corpus. Only a
     * pathological pattern pays the deadline, and it pays it at most once per probe before the first
     * timeout ends the loop. See [ADVERSARIAL_PROBES] for the worst-case bound and the EDT note.
     */
    fun isPatternSafe(
        regex: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
    ): Boolean =
        try {
            val compiled = Pattern.compile(regex) // syntax check — throws PatternSyntaxException on bad regex
            // WR-01: reject patterns that can match the empty (zero-width) string, e.g. a*, \d*,
            // [0-9]*, \s*, x?, (foo)?, .*. Matcher.replaceAll advances past zero-width matches one
            // character at a time, inserting the replacement between EVERY character — corrupting
            // and bloating the outbound context (a 44-char body explodes to ~490 chars). Fail-safe
            // for secrecy, but a foreseeable footgun for non-expert regex users, so reject it up
            // front and surface a distinct rejection message in the save path.
            //
            // This check stays ABOVE the probe loop and keeps its own separate return, so a
            // zero-width pattern is still rejected for BEING zero-width rather than for timing out.
            // Guard: SafeRegexTest.zeroWidthPatternsAreRejectedWithoutRunningAnyProbe, which asserts
            // it by cost — nine empty-matchers must return in less than one probe deadline.
            if (compiled.matcher("").find()) {
                false
            } else {
                // WR-07: EVERY probe, and the first timeout rejects. Each probe gets its own fresh
                // deadline: a shared deadline across the corpus would let a pattern that is merely
                // slow on probe 1 exhaust the budget and be rejected on probe 2 for the wrong reason.
                for (probe in ADVERSARIAL_PROBES) {
                    val deadline = System.nanoTime() + timeoutMs * 1_000_000L
                    compiled.matcher(DeadlineCharSequence(probe, deadline)).find()
                }
                true
            }
        } catch (_: PatternSyntaxException) {
            false
        } catch (_: RegexTimeoutException) {
            false
        } catch (_: StackOverflowError) {
            false
        }

    // (PRIV-02) WR-07 / T-21-63: the catastrophic-backtracking probe corpus for isPatternSafe.
    //
    // WHY THIS IS A SECURITY CONTROL AND NOT A TIDY-UP. Before this phase, a custom pattern that
    // was accepted but slow degraded gracefully: custom patterns ran only inside the redactTokens
    // branch and an overrunning one was simply skipped. D-05 changed both halves of that. Custom
    // patterns now run in EVERY privacy mode INCLUDING OFF (they are a "never send this, ever" list,
    // independent of the mode — see Redaction.bodyRules), and bodyStage now fails CLOSED. So an
    // accepted-but-slow pattern no longer degrades: it spends Defaults.MAX_REDACTION_BUDGET_MS and
    // drops real content behind markers on EVERY call, including the calls a user in OFF mode
    // believes are unfiltered. The blast radius of a bad accept grew in both directions during this
    // phase without the gate being strengthened. This corpus is the strengthening.
    //
    // THE DESIGN PRINCIPLE IS (CHARACTER CLASS x TERMINATOR), and the terminator half is the part
    // WR-07 missed. Catastrophic backtracking in the (X+)+L family needs a long run of X that is
    // NOT followed by L, so the match fails and the engine explores the run's partitions. WR-07
    // proposed varying only the character class, all four probes still ending in '!'. Measured, that
    // does not reject WR-07's OWN second example: ([a-z]+)+! survives a lowercase probe ending in
    // '!' because the greedy match SUCCEEDS immediately and never backtracks, and survives the digit,
    // mixed-alphanumeric and space-separated-word probes because none of them contains a long
    // lowercase run. Only a lowercase run with a different terminator rejects it.
    //
    // Hence three classes x two terminators. Every realistic user-pattern class — hex [a-f0-9],
    // base64 [A-Za-z0-9+/=], \w, [a-z], [A-Z], \d, \S, '.' — contains 'a', '1' or 'A', so each is
    // reachable by at least one probe under at least one non-matching terminator.
    //
    // NO WHITESPACE PROBE, deliberately, and this is a measurement rather than an omission. WR-07
    // proposed ("x"*50 + " ")*40 + "!". Eleven whitespace-targeting candidates were screened against
    // it — (x+ ?)+$, (x+ )+$, ([a-z]+ )+$, (\w+ )+$, ([a-z]+ )+#, (x+ )+@, (x+\s)+!, (\w+\s)+$,
    // (\S+\s)+$, ([a-z ]+)+#, ([a-z]+\s?)+# — and NOT ONE is rejected by that probe alone: the ones
    // it catches are already caught by the lowercase probes, and the rest are not catastrophic at
    // all, because a MANDATORY separator inside the group removes the ambiguity that drives the
    // blow-up. Adding it would have cost a probe's worth of worst case for coverage that could not
    // be demonstrated — the "named guard pointing at nothing" defect this round exists to close. If
    // someone later finds a genuine whitespace-only fixture, add the probe WITH that fixture.
    //
    // SIZING. The first entry is the original single probe, kept BYTE-FOR-BYTE, so no pattern
    // rejected before this widening changes verdict for an unrelated reason. Its note still holds
    // and applies to all six: on JDK 21 the classic (a+)+$ shape needs ~2 000 characters before the
    // 50 ms deadline fires (JDK 21's NFA engine handles shorter inputs without blow-up), so every
    // probe carries a run of that length.
    //
    // WORST CASE, stated rather than assumed: ADVERSARIAL_PROBES.size * DEFAULT_TIMEOUT_MS = 6 * 50
    // = 300 ms for ONE pattern, and it is only reachable by a pattern that is slow-but-completing on
    // five probes and pathological on the sixth. Measured reality: a pattern rejected by the sixth
    // probe cost 50 ms end-to-end, because the five it survives complete in microseconds.
    //
    // EDT NOTE — REPORTED, NOT FIXED HERE (T-21-67, Phase 23 / REL-05). isPatternSafe runs ON THE
    // EDT at save time via SettingsPanel.validateAndCollectCustomPatterns, so this widening
    // multiplies that path's worst case by the probe count. Phase 23 owns EDT confinement; this is
    // measured and reported there rather than restructured here. The startup seeding path in
    // App.initialize is NOT on the EDT-critical path.
    private val ADVERSARIAL_PROBES: List<String> =
        listOf(
            "a".repeat(2_000) + "!", // original probe, verbatim — lowercase run, '!' terminator
            "a".repeat(2_000) + "-", // lowercase run, non-'!' terminator: rejects ([a-z]+)+!
            "1".repeat(2_000) + "!", // digit run: rejects (\d+)+@
            "1".repeat(2_000) + "-", // digit run, non-'!' terminator: rejects (\d+)+!
            "A".repeat(2_000) + "!", // uppercase run
            "A".repeat(2_000) + "-", // uppercase run, non-'!' terminator: rejects ([A-Z]+)+!
        )
}
