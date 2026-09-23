package app.aethernext

/**
 * The noise-profile vocabulary the shell may put on the engine's command line, and
 * the scan limits it may enforce (T2xx).
 *
 * Two homes for one fact was the bug, and this table was the second home. It claimed
 * the engine knew only `off|light|aggressive|heavy` and mapped the app's `high` and
 * `max` both onto `heavy` — which the engine's own `obfuscation::normalize` folds to
 * `max`. So the phone had one rung fewer than desktop, and choosing "High" sent the
 * loudest profile the user did not ask for. The engine's vocabulary is
 * `obfuscation::RECOGNIZED_PROFILES`, whose ladder is off < light < medium < high <
 * max (plus aliases and `custom`); every value below is one of those names, and the
 * app's four settings stay four distinct rungs. [forEngine] still returns null for
 * anything it does not know, and validation rejects a setting it cannot translate
 * rather than passing a guess downstream.
 *
 * The `custom` profile is the user's own junk sizes (`AETHER_NOIZE_JC/JMIN/JMAX`),
 * which the engine applies on top of a named profile: it is mapped to `aggressive`
 * because the explicit sizes are what decide the traffic, and the named profile only
 * has to switch injection on.
 */
internal object NoizeProfiles {

    /** The names the engine understands. Anything else is a shell-side invention. */
    val engineValues: Set<String> = setOf("off", "light", "medium", "high", "max", "custom")

    /** The names the app may send: its canonical set plus the legacy aliases it still reads back from a saved profile. */
    val appValues: Set<String> = setOf(
        "off", "light", "medium", "high", "max", "custom",
        "on", "random", "m1", "m2", "firewall", "balanced", "gfw", "aggressive", "heavy",
    )

    private val toEngine: Map<String, String> = mapOf(
        "off" to "off",
        "light" to "light",
        "on" to "light",
        "random" to "light",
        "m1" to "light",
        // The app's own ladder, kept distinct: folding high and max together onto
        // one engine name is what made "High" mean the loudest setting.
        "medium" to "medium",
        "balanced" to "medium",
        "firewall" to "medium",
        "high" to "high",
        "gfw" to "high",
        "max" to "max",
        "heavy" to "max",
        "aggressive" to "max",
        "m2" to "max",
        // The user's own junk sizes (AETHER_NOIZE_JC/JMIN/JMAX) decide the traffic;
        // the named profile only has to switch injection on, and the engine knows
        // `custom` by name.
        "custom" to "custom",
    )

    init {
        // Fail loudly in a debug build if the table ever drifts away from the
        // declared vocabulary: a mapping that lands on an unknown engine name is the
        // silent downgrade this table exists to prevent.
        val unmapped = appValues - toEngine.keys
        val invented = toEngine.values.toSet() - engineValues
        check(unmapped.isEmpty() && invented.isEmpty()) {
            "noize mapping drift: unmapped=$unmapped invented=$invented"
        }
    }

    /** The engine name for an app value, or null when this shell cannot translate it. */
    fun forEngine(value: String): String? = toEngine[value.lowercase().trim()]
}

/**
 * The single clamp for the standalone scan's per-probe timeout.
 *
 * The UI advertised 100-30000 ms while the bridge coerced the same number to
 * `>= 3000` (`>= 6000` for the MASQUE family, whose handshake does not fit in 3 s):
 * two implementations of one rule, disagreeing, and the input never told the user
 * which numbers were real. [clamp] is now the only place the bound exists on the
 * native side, and the web layer mirrors these four numbers in
 * `src/types.ts` so the field can disable what cannot be honoured.
 */
internal object ScanLimits {
    const val MIN_TIMEOUT_MS = 3_000
    const val MASQUE_MIN_TIMEOUT_MS = 6_000
    const val MAX_TIMEOUT_MS = 30_000
    const val MIN_CONCURRENCY = 1

    /**
     * 500, not the 2000 this used to carry. The desktop shell clamps the same
     * knob to 500 (`src-tauri/src/scan.rs`) and the engine's own absolute ceiling
     * is 1000 with 16 lanes for an H3 scan (`aether/src/prober.rs`), so a phone
     * offering 2000 promised a number nothing could deliver — and
     * `scripts/verify-invariants.mjs` (`numeric-limits-cross-layer`) now fails if
     * this, `SCAN_MAX_CONCURRENCY` in `packages/ui/src/index.ts` and the shell
     * clamp drift apart again.
     */
    const val MAX_CONCURRENCY = 500

    /**
     * Lanes a MASQUE/H3 scan may run, which is fewer than a cheap one can.
     *
     * The web layer already refuses to advertise more than this for H3; a shell that
     * clamped 1..500 for every protocol left the number able to reach the engine from
     * anywhere else — a stored value, another producer, a hand-written call — and ask
     * for lanes the handshake-safety rule exists to prevent. Mirrors
     * `SCAN_MAX_CONCURRENCY_H3` and the engine's `EXPENSIVE_MAX_CONCURRENCY`.
     */
    const val MAX_CONCURRENCY_H3 = 16

    /** The timeout actually sent to the engine, for the protocol the user picked. */
    fun clampTimeout(timeoutMs: Int, protocol: String): Int {
        val floor = if (isMasque(protocol)) MASQUE_MIN_TIMEOUT_MS else MIN_TIMEOUT_MS
        return timeoutMs.coerceIn(floor, MAX_TIMEOUT_MS)
    }

    /**
     * Lanes for the protocol actually being scanned.
     *
     * [protocol] defaults to empty — a caller with no protocol in hand keeps the
     * absolute ceiling rather than being silently narrowed. The scan path does have
     * one, and passes it.
     */
    fun clampConcurrency(concurrency: Int, protocol: String = ""): Int {
        val ceiling = if (isMasque(protocol)) MAX_CONCURRENCY_H3 else MAX_CONCURRENCY
        return concurrency.coerceIn(MIN_CONCURRENCY, ceiling)
    }

    fun isMasque(protocol: String): Boolean =
        protocol.contains("h3", ignoreCase = true) || protocol.equals("masque", ignoreCase = true)

    /**
     * `AETHER_SCAN` for a scan run. It used to be hardcoded to `balanced`, so the
     * scan mode the user chose in the settings was thrown away the moment they
     * pressed Scan — the standalone scan always ran the balanced profile.
     */
    fun scanProfile(settingsScanMode: String): String = settingsScanMode.lowercase().trim()
}
