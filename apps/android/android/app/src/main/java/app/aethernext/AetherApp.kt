package app.aethernext

import android.app.Application
import android.util.Log

/**
 * Process entry point, present for one reason: the crash forwarder.
 *
 * `MainActivity.onCreate` used to wrap `Thread.setDefaultUncaughtExceptionHandler`
 * every time an activity was created and keep the previous handler in a closure.
 * With `launchMode` `standard` that chain grew across activity restarts, and each
 * link captured a dead activity — so the last crash was reported through a
 * WebView that no longer existed, and the report was lost with it. Installing from
 * `Application.onCreate` behind an idempotency flag makes it exactly one link,
 * bound to no activity (T219).
 */
class AetherApp : Application() {
    override fun onCreate() {
        super.onCreate()
        installCrashForwarder()
    }

    companion object {
        private const val TAG = "AetherApp"

        @Volatile
        private var forwarderInstalled = false

        /** Public and guarded so a test, or a re-entered `onCreate`, is a no-op. */
        fun installCrashForwarder() {
            if (forwarderInstalled) return
            synchronized(this) {
                if (forwarderInstalled) return
                forwarderInstalled = true
                val previous = Thread.getDefaultUncaughtExceptionHandler()
                Thread.setDefaultUncaughtExceptionHandler { thread, exception ->
                    Log.e(TAG, "Uncaught exception on ${thread.name}", exception)
                    try {
                        SessionController.getOrNull()?.reportCrash(
                            "${exception.javaClass.simpleName}: ${exception.message ?: "no message"}",
                        )
                    } catch (e: Exception) {
                        Log.w(TAG, "could not publish the crash state: ${e.message}")
                    }
                    // The platform handler must still run, or the process hangs
                    // instead of dying and being restarted.
                    try {
                        previous?.uncaughtException(thread, exception)
                    } catch (e: Exception) {
                        Log.w(TAG, "previous uncaught handler failed: ${e.message}")
                    }
                }
            }
        }
    }
}
