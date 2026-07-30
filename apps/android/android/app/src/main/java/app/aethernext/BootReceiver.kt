package app.aethernext

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val store = SettingsStore(context)
        val s = store.load()
        if (!s.launchAtLogin) return
        val launch = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        // Only opens the UI (never starts the VPN foreground service from boot,
        // which Android 12+ forbids). Background activity starts are restricted on
        // Android 10+ and may be dropped; guard so a throwing OEM can't crash boot.
        try {
            context.startActivity(launch)
        } catch (_: Exception) {
        }
    }
}
