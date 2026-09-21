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
