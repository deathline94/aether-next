package app.aethernext

import org.json.JSONObject

/**
 * The terminal scan event for a scan whose process ended without reporting one.
 *
 * `null` when the engine already said `scan_done`/`scan_failed`: a second terminal
 * event re-opens a run the UI had closed. Otherwise the answer must not be an empty
 * `scan_done` — the webview reads that as "finished, nothing found", so a scan
 * killed halfway through discarded the endpoints it had already surfaced and looked
 * like a search that found nothing rather than a run that stopped. The desktop shell
 * carried the same bug and reports a failure too.
 */
internal fun scanExitEvent(terminalSent: Boolean): JSONObject? {
    if (terminalSent) return null
    return JSONObject()
        .put("type", "scan_failed")
        .put(
            "message",
            "the scan process ended without reporting a result; the endpoints found so far are kept",
        )
}
