package app.aethernext

/**
 * Bounded teardown of the tun2socks service (T214).
 *
 * `stopTunnel()` used to call `TProxyStopService()` and then `Thread.sleep(150)`
 * before closing the descriptor: a fixed pause, chosen by feel, that the main
 * thread paid during `onRevoke`. Two things were wrong with that. A slow hev stop
 * (the 150 ms is a *guess* about when its threads are out of the fd) is not made
 * safe by a timer, and a fast one still cost 150 ms on the path Android runs
 * `onRevoke` on — which is how a Quick Settings tap gets an ANR dialog.
 *
 * So the stop runs on a thread of its own and the caller joins it with a budget:
 * the pause ends exactly when hev says it is done, and the wait can never exceed
 * the budget whatever hev does.
 */

internal sealed interface HevStopOutcome {
    /** The stop call returned inside the budget: the fd may be closed. */
    data object Acknowledged : HevStopOutcome

    /**
     * The stop call is still running after [waitedMs]. Closing the descriptor here
     * is the lesser evil — leaking it means the device stays behind a tunnel that
     * no one owns — but it is logged, and it is why the budget is generous.
     */
    data class TimedOut(val waitedMs: Long) : HevStopOutcome

    /** The stop call threw (or the native library is not loadable). */
    data class Failed(val reason: String) : HevStopOutcome
}

internal object HevStop {
    /** How long the caller waits for hev to release the TUN fd. */
    const val JOIN_BUDGET_MS = 2_000L

    /**
     * Run [stop] off the calling thread and wait for it, bounded by [budgetMs].
     *
     * [stop] is `TProxyStopService()` in production and a stub in a test; nothing
     * here touches Android, which is the point — the *bound* is the behaviour that
     * needs proving, and a device is not how to prove it.
     */
    fun stopAndAwait(
        stop: () -> Unit,
        budgetMs: Long = JOIN_BUDGET_MS,
        name: String = "hev-stop",
    ): HevStopOutcome {
        val failureRef = java.util.concurrent.atomic.AtomicReference<String?>(null)
        val signalled = java.util.concurrent.CountDownLatch(1)
        val worker = Thread({
            try {
                stop()
            } catch (e: Throwable) {
                failureRef.set(e.message ?: e.javaClass.simpleName)
            } finally {
                signalled.countDown()
            }
        }, name).apply { isDaemon = true }
        val startedAt = System.currentTimeMillis()
        worker.start()
        val acked = try {
            signalled.await(budgetMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            // The caller is being torn down; treat that as no acknowledgement
            // rather than as permission to close an fd hev may still hold.
            Thread.currentThread().interrupt()
            false
        }
        val failure = failureRef.get()
        return when {
            acked && failure != null -> HevStopOutcome.Failed(failure)
            acked -> HevStopOutcome.Acknowledged
            else -> HevStopOutcome.TimedOut(System.currentTimeMillis() - startedAt)
        }
    }
}
