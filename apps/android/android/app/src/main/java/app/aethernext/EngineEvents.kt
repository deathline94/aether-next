package app.aethernext

import org.json.JSONObject

/**
 * The shell's mirror of the engine's `SessionEvent`
 * (`aether/src/session_event.rs`, serialised as one JSON line
 * `AETHER_EVENT {"type":…}`).
 *
 * Before this existed the status path read *human log prose*: it looked for the
 * sentence "handshake successful", which no line of the Rust source ever prints,
 * so the happy path could never fire while a genuine `{"type":"connected"}` event
 * arriving on the same line was parsed, thrown away and left unreported. Prose is
 * a translation for a person, not a contract for a process; this sealed type is
 * the contract, and `Malformed` is the case the old code swallowed.
 *
 * Field names follow serde's `rename_all = "snake_case"` on the variants, so a
 * new engine variant shows up here as [Unrecognised] (visible, counted) instead
 * of silently meaning "not connected".
 */
internal sealed class EngineEvent {
    /** `IdentityReady` — the engine knows who it is; nothing routes on it yet. */
    data class IdentityReady(val deviceId: String, val ipv4: String) : EngineEvent()

    data class EndpointSelected(val addr: String, val protocol: String) : EngineEvent()

    /** Local SOCKS/HTTP listeners are accepting. */
    data class ProxyReady(val socks: String, val http: String) : EngineEvent()

    /** The QUIC/CONNECT tunnel carried a first round trip. */
    data class TunnelReady(val transport: String) : EngineEvent()

    data object TunReady : EngineEvent()

    /** The engine's own "the data path works" statement. */
    data class Connected(val detail: String) : EngineEvent()

    data class Failure(val message: String) : EngineEvent()

    /** `scan_start` / `scan_progress` / `scan_hit` / `scan_done`, forwarded verbatim. */
    data class Scan(val type: String, val payload: JSONObject) : EngineEvent()

    /** Informational stages the engine prints that are not lifecycle signals. */
    data class Stage(val type: String, val payload: JSONObject) : EngineEvent()

    /** A valid event whose `type` this shell does not model yet. */
    data class Unrecognised(val type: String) : EngineEvent()

    /**
     * An `AETHER_EVENT ` prefix whose body could not be read: truncated output,
     * a non-object, or a missing `type`. Distinct from "no event on this line"
     * precisely because it means the two sides disagree and must be reported.
     */
    data class Malformed(val reason: String, val raw: String) : EngineEvent()

    companion object {
        const val PREFIX = "AETHER_EVENT "

        /** Types that carry no lifecycle meaning; kept out of the warning path. */
        private val STAGE_TYPES = setOf("h3_stage")

        /**
         * @return the parsed event, or `null` when [line] holds no event at all
         *   (ordinary log chatter). A present-but-unreadable event is *not* null:
         *   it is [Malformed], so the caller can count and surface it.
         */
        fun parse(line: String): EngineEvent? {
            val idx = line.indexOf(PREFIX)
            if (idx < 0) return null
            val raw = line.substring(idx + PREFIX.length).trim()
            if (raw.isEmpty()) return Malformed("empty event body", raw)
            val json = try {
                JSONObject(raw)
            } catch (e: Exception) {
                return Malformed(e.message ?: "not valid JSON", raw)
            }
            val type = json.optString("type")
            if (type.isEmpty()) return Malformed("event has no \"type\"", raw)
            return when (type) {
                "identity_ready" -> IdentityReady(
                    deviceId = json.optString("device_id"),
                    ipv4 = json.optString("ipv4"),
                )
                "endpoint_selected" -> EndpointSelected(
                    addr = json.optString("addr"),
                    protocol = json.optString("protocol"),
                )
                "proxy_ready" -> ProxyReady(
                    socks = json.optString("socks"),
                    http = json.optString("http"),
                )
                "tunnel_ready" -> TunnelReady(transport = json.optString("transport"))
                "tun_ready" -> TunReady
                "connected" -> Connected(detail = json.optString("detail"))
                "error" -> Failure(json.optString("message", "Connection failed"))
                "scan_start", "scan_progress", "scan_hit", "scan_done" -> Scan(type, json)
                else -> if (type in STAGE_TYPES) Stage(type, json) else Unrecognised(type)
            }
        }
    }
}
