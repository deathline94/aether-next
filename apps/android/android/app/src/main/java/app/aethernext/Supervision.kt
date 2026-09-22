package app.aethernext

import android.os.PowerManager

/**
 * Process-lifetime supervision (T217).
 *
 * Both services used to answer `START_NOT_STICKY` with no retry, so the Low Memory
 * Killer ending the process ended the tunnel silently, and doze could stall QUIC's
 * timers behind a parked CPU. Three levers, each with a rule that must not be
 * gotten wrong:
 *
 *  * **Restartability** — `START_STICKY` redelivers the start command, so a killed
 *    service comes back. That is only safe because [AetherVpnService.onStartCommand]
 *    re-establishes from the *stored* SOCKS port rather than trusting an intent it
 *    may not get again.
 *  * **Wake lock** — held *only* while the session is actually `connected`. A
 *    partial wake lock kept across an idle screen is the single most effective way
 *    to get the app uninstalled, and a lock held while disconnected protects
 *    nothing. [WakeLockGuard] makes holding it a state transition rather than a
 *    call site, so it cannot leak.
 *  * **Battery optimisation** — `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` is
 *    the only user-grantable escape from doze. It is an alarming dialog, so it is
 *    offered once, with the reason in the text, and never after the device already
 *    exempts us.
 */

/** What the platform restart delivery means for this service. */
internal sealed interface SupervisionAction {
    /** Stay alive and be restarted if the system kills us. */
    data object Sticky : SupervisionAction

    /** Do not recreate; the user asked for this to stop. */
    data object NotSticky : SupervisionAction
}

/**
 * The restart rule.
 *
 * `onStartCommand`'s [redelivery] argument is `intent == null`: that is Android
 * re-delivering a start after killing us, not a stop, and reading it as one is how
 * a service that says `START_STICKY` ends up never being sticky. The only thing
 * that may refuse a restart is a stop the user asked for.
 */
internal fun supervisionAction(redelivery: Boolean, stopRequested: Boolean): SupervisionAction =
    if (stopRequested) SupervisionAction.NotSticky else SupervisionAction.Sticky

/**
 * The wake-lock rule, as a function of the published session status.
 *
 * `connecting` deliberately does not hold the lock: a stalled connect must not
 * keep the CPU awake, which is the case that turns a broken tunnel into a dead
 * battery.
 */
internal fun wakeLockShouldHold(status: String): Boolean = status == "connected"

/** The two wake-lock calls, so the guard's transitions are testable without Android. */
internal interface WakeLockOps {
    fun acquire()

    fun release()

    fun isHeld(): Boolean
}

/**
 * Acquire/release exactly once each, driven by [onStatus].
 *
 * A `PowerManager.WakeLock` counts re-acquires as an error, and a lock that is
 * released by a state the user never sees is a leak the platform punishes; both
 * are avoided by making every transition idempotent.
 */
internal class WakeLockGuard(private val ops: WakeLockOps) {
    private var lastStatus: String? = null

    /** @return whether the lock is held after the transition. */
    fun onStatus(status: String): Boolean {
        lastStatus = status
        return if (wakeLockShouldHold(status)) {
            if (!ops.isHeld()) ops.acquire()
            true
        } else {
            if (ops.isHeld()) ops.release()
            false
        }
    }

    /** The teardown path: whatever the status said, let go. */
    fun release() {
        lastStatus = null
        if (ops.isHeld()) ops.release()
    }

    fun statusSeen(): String? = lastStatus
}

/** The platform adapter: a partial wake lock on this app's uid. */
internal fun powerWakeLock(power: PowerManager?, tag: String): WakeLockOps = object : WakeLockOps {
    private val lock = power?.let {
        it.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, tag).apply { setReferenceCounted(false) }
    }

    override fun acquire() {
        lock?.acquire(60 * 60 * 1000L) // self-clearing: a stuck holder cannot keep the CPU forever
    }

    override fun release() {
        lock?.release()
    }

    override fun isHeld(): Boolean = lock?.isHeld == true
}

/** Whether to take the user to the battery-optimisation dialog. */
internal sealed interface BatteryPlan {
    /** Ask, with the explanation shown in the same dialog. */
    data object Request : BatteryPlan

    /** The device already exempts us: saying anything would be noise. */
    data object AlreadyIgnoring : BatteryPlan

    /** We asked already and were refused; asking again is nagging. */
    data object AlreadyAsked : BatteryPlan
}

internal fun batteryPlan(isIgnoring: Boolean, askedBefore: Boolean): BatteryPlan = when {
    isIgnoring -> BatteryPlan.AlreadyIgnoring
    askedBefore -> BatteryPlan.AlreadyAsked
    else -> BatteryPlan.Request
}
