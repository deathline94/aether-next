package app.aethernext

/**
 * The supervised-restart budget for a full-device tunnel (T210).
 *
 * A dead data path used to be invisible forever: `markConnected()` was a one-shot
 * compare-and-set, so once a session had been up no later failure could take the
 * badge down, and nothing ever retried. The retry itself has to be bounded,
 * because the failure it is reacting to (a handoff that left the engine's sockets
 * bound to a vanished interface) can also be permanent: an unbounded restart loop
 * re-registers the VPN interface, re-runs `establish()`'s netd binder call and
 * keeps the radio awake forever.
 *
 * So: three attempts, 2 s / 8 s / 30 s apart, then a terminal state that only a
 * user action clears. This is that rule as a pure object — the coroutine that
 * waits is in [SessionController].
 */

/** The message of the terminal state. Deliberately names the action that works. */
const val RECONNECT_REQUIRED = "Network changed — reconnect required"

sealed interface RestartPlan {
    /** Wait [delayMs], then attempt restart number [attempt] (1-based). */
    data class RetryAfter(val delayMs: Long, val attempt: Int) : RestartPlan

    /** The budget is spent: publish [RECONNECT_REQUIRED] and stop trying. */
    data object GiveUp : RestartPlan
}

/**
 * A budget of restart attempts is held by [LivenessTracker], which owns the window
 * state the budget is counted against; a second counter alongside it was the kind of
 * duplicated rule that quietly disagrees with the first, so it is gone. What remains
 * here is the *shape* of a plan, which is all the service needs to act on.
 */
