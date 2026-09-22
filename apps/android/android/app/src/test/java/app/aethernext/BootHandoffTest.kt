package app.aethernext

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * "Launch at login" used to be a fire-and-forget `notify()` inside
 * `catch (_: Exception) {}`, which made a blocked notification indistinguishable
 * from a delivered one (T218). These assert the replacement: the blocked case is
 * decided up front and survives until the app can say it out loud, once.
 */
class BootHandoffTest {

    private class PrefsContext(private val baseDir: File) : ContextWrapper(null) {
        val prefs = FakeSharedPreferences()
        override fun getApplicationContext(): Context = this
        override fun getFilesDir(): File = baseDir
        override fun getSharedPreferences(name: String?, mode: Int): SharedPreferences = prefs
    }

    @Test
    fun aBlockedNotificationIsPlannedForBeforeAnythingIsPosted() {
        assertNotNull("blocked notifications must produce a message, not silence", BootHandoff.planFor(canNotify = false))
        assertNull("when notifications work there is nothing to replay", BootHandoff.planFor(canNotify = true))
        assertTrue(
            BootHandoff.planFor(canNotify = false)!!.contains("notifications are blocked"),
        )
    }

    @Test
    fun noNotificationManagerMeansNoNotification() {
        // ContextWrapper(null) makes getSystemService fail / return null, which is
        // the honest "cannot show anything" answer rather than an assumed yes.
        val tempDir = File(System.getProperty("java.io.tmpdir"), "boot_${System.nanoTime()}").apply { mkdirs() }
        assertFalse(BootHandoff.canNotify(PrefsContext(tempDir)))
        tempDir.deleteRecursively()
    }

    @Test
    fun thePendingNoticeIsReplayedExactlyOnce() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "boot_${System.nanoTime()}").apply { mkdirs() }
        val context = PrefsContext(tempDir)

        assertNull(BootHandoff.consumePendingStart(context))

        BootHandoff.markStartPending(context, BootHandoff.BLOCKED_MESSAGE)
        assertEquals(BootHandoff.BLOCKED_MESSAGE, BootHandoff.consumePendingStart(context))
        assertNull("a second open must not repeat it", BootHandoff.consumePendingStart(context))

        tempDir.deleteRecursively()
    }

    @Test
    fun aBootWithLaunchAtLoginOffRecordsNoHandoff() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "boot_${System.nanoTime()}").apply { mkdirs() }
        val context = PrefsContext(tempDir)

        // Fresh install: `launchAtLogin` defaults to off, so the receiver must
        // return before it touches the notification path at all.
        BootReceiver().handleBoot(context)
        assertNull(BootHandoff.consumePendingStart(context))

        tempDir.deleteRecursively()
    }

    @Test
    fun aBlockedBootNotificationIsRecordedForTheNextLaunch() {
        val tempDir = File(System.getProperty("java.io.tmpdir"), "boot_${System.nanoTime()}").apply { mkdirs() }
        val context = PrefsContext(tempDir)
        context.prefs.edit()
            .putString("json", Settings(launchAtLogin = true).toJson().toString())
            .apply()

        BootReceiver().handleBoot(context)

        val replayed = BootHandoff.consumePendingStart(context)
        assertNotNull("the blocked boot must come back as a visible in-app state", replayed)
        assertTrue("got: $replayed", replayed!!.contains("tap Connect"))
        assertNull("and only once", BootHandoff.consumePendingStart(context))

        tempDir.deleteRecursively()
    }
}
