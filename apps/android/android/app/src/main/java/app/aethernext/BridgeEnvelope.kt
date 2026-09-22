package app.aethernext

import org.json.JSONObject

/**
 * A failure that knows what kind it is.
 *
 * The WebView envelope used to carry a bare message, so the UI could only branch
 * on prose — the same defect the desktop shell closed by making `CommandError`
 * serialise `{code, message, field}`. The codes are the shell's vocabulary
 * (`validation`, `not_found`, `permission_denied`, `encode`, `internal`, …) so one
 * frontend helper can read either side.
 */
class BridgeError(
    val code: String,
    val detail: String,
    val field: String? = null,
) : Exception(detail)

/**
 * A rejected setting. Subclasses `IllegalArgumentException` because that is what
 * this function has always thrown, and the message is still the human half — what
 * was missing is `field`, without which the form has nowhere to put the complaint
 * and the save indicator cannot stop saying "Auto-Saving".
 */
class SettingRejected(val field: String, detail: String) : IllegalArgumentException(detail)

internal fun bridgeOk(data: Any?): String {
    val o = JSONObject().put("ok", true)
    when (data) {
        null, JSONObject.NULL -> o.put("data", JSONObject.NULL)
        is JSONObject -> o.put("data", data)
        is Boolean -> o.put("data", data)
        is Number -> o.put("data", data)
        is String -> o.put("data", data)
        else -> o.put("data", data.toString())
    }
    return o.toString()
}

internal fun bridgeErr(code: String, message: String, field: String?): String {
    val error = JSONObject().put("code", code).put("message", message)
    if (field != null) error.put("field", field)
    return JSONObject().put("ok", false).put("error", error).toString()
}
