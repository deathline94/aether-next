package app.aethernext

/**
 * Data-path liveness classification.
 *
 * Kept as a pure function over counter snapshots so the whole decision table is
 * testable on a JVM without a device, a VPN permission dialog, or a carrier
 * handoff. This exists because the tunnel used to report "connected" forever:
 * `TProxyGetStats()` was declared and never called, `onLost` only re-registered
 * the underlying network, and `markConnected()` was a one-shot compare-and-set
 * that no failure could ever revoke — so a QUIC socket left bound to a dead
 * interface produced a green badge over a total blackhole.
 *
 * Counter layout is libhev-socks5-tunnel's `TProxyGetStats()`:
 * `[tx_packets, tx_bytes, rx_packets, rx_bytes]`, where tx/rx are seen from the
 * tun side (rx = packets read out of the tunnel towards the network, tx =
 * packets written back into it) and the array is zeroed on every
 * `hev_socks5_tunnel_main()` entry. Because it resets per session, callers must
 * capture a baseline *after* starting the service, never before.
 */

/** Decision window cadence, in milliseconds. */
const val WINDOW_MS = 5_000L

/** Consecutive rx-only windows (15 s) before the path is declared dead. */
const val FROZEN_TX_WINDOWS = 3

/** Consecutive fully-silent windows (30 s) before death, probe-gated. */
const val SILENT_WINDOWS = 6

/** Maximum supervised restart attempts before a terminal state. */
const val MAX_ATTEMPTS = 3

sealed interface LivenessDecision {
    /** Traffic is moving both ways, or the tunnel is legitimately idle. */
    data object Alive : LivenessDecision

    /**
     * Packets are arriving from the network but nothing is going back out: the
     * signature of a tun that is up while the engine's sockets are bound to an
     * interface that no longer exists.
     */
    data object DeadRxOnly : LivenessDecision

    /**
     * No traffic either way *and* the foreground probe also failed. Kept
     * separate from [DeadRxOnly] because a genuinely idle device must not be
     * bounced every [SILENT_WINDOWS] windows.
     */
    data object DeadSilent : LivenessDecision

    /** The restart budget is spent; surface a terminal state to the user. */
    data object Exhausted : LivenessDecision
}

private fun LongArray.at(i: Int): Long = if (i in indices) get(i) else 0L

/**
 * Classify one window.
 *
 * @param prev previous `TProxyGetStats()` snapshot, or the post-start baseline
 * @param now current snapshot
 * @param elapsedMs wall time between the two snapshots
 * @param attempt number of supervised restarts already performed for this
 *                user-initiated session
 * @param frozenWindows consecutive windows already seen with rx advancing and
 *                      tx frozen
 * @param silentWindows consecutive fully-silent windows already seen
 * @param probeFailed whether an active foreground probe also failed this window
 */
fun decideLiveness(
    prev: LongArray,
    now: LongArray,
    elapsedMs: Long,
    attempt: Int,
    frozenWindows: Int = 0,
    silentWindows: Int = 0,
    probeFailed: Boolean = false,
): LivenessDecision {
    // The budget check comes first: once attempts are spent, nothing else may
    // schedule another restart, or a flapping network turns into a loop that
    // keeps re-registering the VPN interface.
    if (attempt >= MAX_ATTEMPTS) return LivenessDecision.Exhausted
    if (elapsedMs < WINDOW_MS) return LivenessDecision.Alive

    val txPackets = now.at(0) - prev.at(0)
    val txBytes = now.at(1) - prev.at(1)
    val rxPackets = now.at(2) - prev.at(2)
    val rxBytes = now.at(3) - prev.at(3)

    val rxDelta = rxPackets.coerceAtLeast(rxBytes)
    val txDelta = txPackets.coerceAtLeast(txBytes)

    return when {
        rxDelta > 0L && txDelta == 0L && frozenWindows + 1 >= FROZEN_TX_WINDOWS ->
            LivenessDecision.DeadRxOnly

        rxDelta == 0L && txDelta == 0L && silentWindows + 1 >= SILENT_WINDOWS && probeFailed ->
            LivenessDecision.DeadSilent

        else -> LivenessDecision.Alive
    }
}

/**
 * Counters for a [LivenessDecision.DeadRxOnly] verdict. Zeroed on any window
 * where traffic moved out, so a stall that self-heals does not accumulate.
 */
fun nextFrozenWindows(
    prev: LongArray,
    now: LongArray,
    frozenWindows: Int,
): Int {
    val txMoving = now.at(0) > prev.at(0) || now.at(1) > prev.at(1)
    val rxMoving = now.at(2) > prev.at(2) || now.at(3) > prev.at(3)
    return if (rxMoving && !txMoving) frozenWindows + 1 else 0
}

/** Same, for the fully-silent case. */
fun nextSilentWindows(prev: LongArray, now: LongArray, silentWindows: Int): Int {
    val quiet = now.at(0) == prev.at(0) && now.at(1) == prev.at(1) &&
        now.at(2) == prev.at(2) && now.at(3) == prev.at(3)
    return if (quiet) silentWindows + 1 else 0
}

/** Restart backoff schedule, in milliseconds, indexed by attempt number. */
fun backoffFor(attempt: Int): Long = when (attempt) {
    0 -> 2_000L
    1 -> 8_000L
    else -> 30_000L
}

/**
 * Whether a decision means "this tunnel cannot be trusted any more".
 *
 * [LivenessDecision.Exhausted] belongs here: a spent restart budget is the one
 * verdict that must reach the user, and excluding it meant `if (decision.isDead)`
 * callers — the only shape this shell writes — silently ignored a tunnel that had
 * already failed three supervised restarts and kept showing a green badge over it.
 */
val LivenessDecision.isDead: Boolean
    get() = this == LivenessDecision.DeadRxOnly ||
        this == LivenessDecision.DeadSilent ||
        this == LivenessDecision.Exhausted

/**
 * The window counter the service polls every [WINDOW_MS] from `TProxyGetStats()`.
 *
 * [decideLiveness] is a single window: it needs the previous snapshot, the elapsed
 * time and the two streak counters. This class is the only thing that may hold
 * those across windows, so it is kept free of Android types ([android.os.SystemClock]
 * included) and the whole watchdog — streaks, budget, baseline handling — is
 * assertable on a JVM (T203/T209).
 *
 * A tracker starts *unbaselined*: `TProxyGetStats()` is zeroed on every
 * `hev_socks5_tunnel_main()` entry, so a sample taken before the service is
 * running is not a baseline, and neither is one taken at the same instant as the
 * start. [baseline] must be called after `TProxyStartService()` returns, and a
 * tracker that never got one reports [LivenessDecision.Alive] forever rather than
 * inventing a delta out of a zeroed array.
 */
class LivenessTracker(
    private val maxAttempts: Int = MAX_ATTEMPTS,
) {
    /** Supervised restarts already spent for this user-initiated session. */
    var attempt: Int = 0
        private set

    @Volatile
    private var prev: LongArray? = null

    @Volatile
    private var prevAtMs: Long = 0L

    private var frozenWindows = 0
    private var silentWindows = 0

    fun baseline(sample: LongArray, atMs: Long) {
        prev = sample.clone()
        prevAtMs = atMs
        frozenWindows = 0
        silentWindows = 0
    }

    fun hasBaseline(): Boolean = prev != null

    /** A new session (a fresh tunnel, a user tap) starts a fresh budget and streaks. */
    fun reset(attempt: Int = 0) {
        prev = null
        prevAtMs = 0L
        frozenWindows = 0
        silentWindows = 0
        this.attempt = attempt
    }

    /**
     * Fold one poll into the window state.
     *
     * @param sample the raw `TProxyGetStats()` array
     * @param atMs monotonic time of this sample
     * @param probeFailed whether an active check of the underlying network failed
     * @return the decision for the window that just closed, or [LivenessDecision.Alive]
     *   while the window is still open (the sample is then kept, not discarded).
     */
    fun onSample(
        sample: LongArray,
        atMs: Long,
        probeFailed: Boolean = false,
    ): LivenessDecision {
        val before = prev ?: run {
            // No baseline yet: adopt this sample as one rather than diff against
            // an array that predates the tunnel.
            baseline(sample, atMs)
            return LivenessDecision.Alive
        }
        val elapsed = atMs - prevAtMs
        if (elapsed < WINDOW_MS) return LivenessDecision.Alive

        val decision = decideLiveness(
            prev = before,
            now = sample,
            elapsedMs = elapsed,
            attempt = attempt,
            frozenWindows = frozenWindows,
            silentWindows = silentWindows,
            probeFailed = probeFailed,
        )
        frozenWindows = nextFrozenWindows(before, sample, frozenWindows)
        silentWindows = nextSilentWindows(before, sample, silentWindows)
        prev = sample.clone()
        prevAtMs = atMs
        return decision
    }

    /** Consecutive frozen-tx windows, exposed for logs and tests. */
    fun frozenWindowCount(): Int = frozenWindows

    /** Consecutive fully-silent windows, exposed for logs and tests. */
    fun silentWindowCount(): Int = silentWindows

    /**
     * A verdict that costs one restart from the budget. Returns the plan the
     * caller must carry out — [RestartPlan.GiveUp] once [maxAttempts] is spent, so
     * a flapping radio cannot turn into an endless re-registration loop.
     */
    fun consumeRestart(): RestartPlan {
        val plan = if (attempt >= maxAttempts) RestartPlan.GiveUp else RestartPlan.RetryAfter(backoffFor(attempt), attempt + 1)
        if (plan is RestartPlan.RetryAfter) attempt = plan.attempt
        return plan
    }
}
