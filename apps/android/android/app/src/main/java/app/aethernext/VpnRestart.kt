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
 * A budget of restart attempts.
 *
 * [next] is called *before* each attempt, so a caller that never attempts cannot
 * spend the budget, and [reset] is what a user-initiated `connect()` owes it —
 * without which a device that failed once could never recover until the app was
 * restarted.
 */
class VpnRestartBudget(
    private val maxAttempts: Int = MAX_ATTEMPTS,
) {
    @Volatile
    var attempts: Int = 0
        private set

    val spent: Boolean get() = attempts >= maxAttempts

    /** Number of attempts already performed; what the UI is told. */
    fun attemptsUsed(): Int = attempts

    /** Take the next attempt, or report that the budget is gone. */
    fun next(): RestartPlan {
        if (attempts >= maxAttempts) return RestartPlan.GiveUp
        val plan = RestartPlan.RetryAfter(backoffFor(attempts), attempts + 1)
        attempts += 1
        return plan
    }

    /** The budget a user-initiated session starts from. */
    fun reset() {
        attempts = 0
    }
}
