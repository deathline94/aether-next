package app.aethernext

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

enum class ProcessExitBehavior {
    GRACEFUL,
    FORCED_ON_DESTROY,
    FORCED_ON_DESTROY_FORCIBLY,
    UNKILLABLE
}

/**
 * A live process does not hand its readers EOF: an empty stream let the engine
 * io thread finish the instant it started, so `start()` raced the very next
 * assertion and hid the "EOF is not death" bug. Bounded at ~200 ms so no test
 * leaks a parked thread.
 */
private class BlockingInputStream : InputStream() {
    @Volatile private var released = false

    override fun read(): Int {
        var waited = 0L
        while (!released && waited < 200) {
            Thread.sleep(10)
            waited += 10
        }
        return -1
    }

    fun release() {
        released = true
    }
}

class FakeProcess(
    private val behavior: ProcessExitBehavior = ProcessExitBehavior.GRACEFUL
) : Process() {
    private val stdout = BlockingInputStream()
    val destroyCalled = AtomicBoolean(false)
    val destroyForciblyCalled = AtomicBoolean(false)
    val waitCount = AtomicInteger(0)

    override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
    override fun getInputStream(): InputStream = stdout
    override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))

    val isTerminated: Boolean
        get() = when (behavior) {
            ProcessExitBehavior.GRACEFUL -> true
            ProcessExitBehavior.FORCED_ON_DESTROY -> destroyCalled.get()
            ProcessExitBehavior.FORCED_ON_DESTROY_FORCIBLY -> destroyForciblyCalled.get()
            ProcessExitBehavior.UNKILLABLE -> false
        }

    override fun isAlive(): Boolean {
        if (isTerminated) stdout.release()
        return !isTerminated
    }

    override fun exitValue(): Int = if (isTerminated) 0 else throw IllegalThreadStateException("Process still alive")

    override fun waitFor(): Int {
        if (!isTerminated && behavior == ProcessExitBehavior.UNKILLABLE) {
            throw InterruptedException("Unkillable")
        }
        return 0
    }

    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
        waitCount.incrementAndGet()
        return isTerminated
    }

    override fun destroy() {
        destroyCalled.set(true)
        stdout.release()
    }

    override fun destroyForcibly(): Process {
        destroyForciblyCalled.set(true)
        stdout.release()
        return this
    }
}

class FakeProcessLauncher(
    var nextProcess: Process = FakeProcess(ProcessExitBehavior.GRACEFUL)
) : ProcessLauncher {
    var lastCommand: List<String>? = null
    var lastEnv: Map<String, String>? = null
    var launchCount = 0

    override fun launch(command: List<String>, env: Map<String, String>): Process {
        launchCount++
        lastCommand = command
        lastEnv = env
        return nextProcess
    }
}
