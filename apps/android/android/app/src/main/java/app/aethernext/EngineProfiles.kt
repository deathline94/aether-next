package app.aethernext

/**
 * The noise-profile vocabulary the shell may put on the engine's command line, and
 * the scan limits it may enforce (T2xx).
 *
 * Two homes for one fact was the bug: the UI offered `medium`/`high`/`max` while the
 * engine maps only `off|light|aggressive|heavy`, so what the app sent for `high` was
 * whatever the engine's own fallback happened to be — a silent downgrade the user
 * could not see. The table below *is* the contract now: [forEngine] returns null for
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
    val engineValues: Set<String> = setOf("off", "light", "aggressive", "heavy")

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
        "medium" to "aggressive",
        "balanced" to "aggressive",
        "firewall" to "aggressive",
        "custom" to "aggressive",
        "aggressive" to "aggressive",
        "high" to "heavy",
        "max" to "heavy",
        "heavy" to "heavy",
        "gfw" to "heavy",
        "m2" to "heavy",
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

    /** The timeout actually sent to the engine, for the protocol the user picked. */
    fun clampTimeout(timeoutMs: Int, protocol: String): Int {
        val floor = if (isMasque(protocol)) MASQUE_MIN_TIMEOUT_MS else MIN_TIMEOUT_MS
        return timeoutMs.coerceIn(floor, MAX_TIMEOUT_MS)
    }

    fun clampConcurrency(concurrency: Int): Int =
        concurrency.coerceIn(MIN_CONCURRENCY, MAX_CONCURRENCY)

    fun isMasque(protocol: String): Boolean =
        protocol.contains("h3", ignoreCase = true) || protocol.equals("masque", ignoreCase = true)

    /**
     * `AETHER_SCAN` for a scan run. It used to be hardcoded to `balanced`, so the
     * scan mode the user chose in the settings was thrown away the moment they
     * pressed Scan — the standalone scan always ran the balanced profile.
     */
    fun scanProfile(settingsScanMode: String): String = settingsScanMode.lowercase().trim()
}
