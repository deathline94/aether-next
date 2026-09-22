package app.aethernext

import android.net.VpnService
import android.os.ParcelFileDescriptor

/**
 * Loop avoidance for the TUN, and the ordering rule around it (audit T202/T208).
 *
 * ## Why `protect()` cannot be used here
 *
 * `VpnService.protect(int fd)` clears the VPN mark on **one descriptor in the
 * calling process's** file-descriptor table. The engine is not in this process:
 * `EngineRunner` starts it with `ProcessBuilder`, so it is a child with its own
 * pid and its own descriptor table, and its QUIC socket is created inside that
 * child, after the fork, in address space this service cannot reach. There is no
 * int we could pass to `protect()` that refers to the engine's socket, and the
 * hev-socks5-tunnel threads live in *this* process but talk to 127.0.0.1 — which
 * a `0.0.0.0/0` route with the TUN excluded still resolves locally.
 *
 * That leaves `VpnService.Builder.addDisallowedApplication(packageName)` — a
 * per-uid routing exclusion applied by the network stack, which is the only
 * mechanism that can cover a child process, because the child inherits this
 * package's uid.
 *
 * ## Why its failure is fatal
 *
 * With no application excluded, the tunnel installs a default route that also
 * captures the engine's own outbound connections to Cloudflare, which are then
 * forwarded by tun2socks back into the engine's SOCKS server, whose outbound
 * traffic re-enters the TUN: a self-carrying loop. The visible symptom is not an
 * error — it is MTU collapse and then total no-connectivity behind a green
 * "connected" badge. A tunnel that cannot exclude itself is therefore not a
 * degraded tunnel; it is a blackhole, and `establish()` must not be reached.
 */

/** The one builder call this file cares about, so it can be tested on a JVM. */
internal fun interface DisallowApplication {
    /** Mirrors `VpnService.Builder.addDisallowedApplication`; throws if netd refuses. */
    @Throws(Exception::class)
    fun addDisallowedApplication(packageName: String)
}

internal object LoopAvoidance {
    /** Raised when a package could not be kept off the tunnel. Callers must not establish. */
    class Failure(
        val rejectedPackages: List<String>,
        val reasons: List<String>,
    ) : IllegalStateException(
        "loop avoidance could not exclude ${rejectedPackages.joinToString()} from the VPN " +
            "tunnel (${reasons.joinToString()}); refusing to start a tunnel that would " +
            "capture Aether's own traffic",
    )

    /**
     * Applies the exclusion for every package in [packages].
     *
     * Every package is attempted before throwing so the message names all of them,
     * but a single failure is fatal: partial loop avoidance is the same blackhole.
     */
    fun enforce(exempt: DisallowApplication, packages: List<String>) {
        if (packages.isEmpty()) {
            throw Failure(listOf("<none configured>"), listOf("no package was eligible for exclusion"))
        }
        val rejected = mutableListOf<String>()
        val reasons = mutableListOf<String>()
        for (pkg in packages) {
            try {
                exempt.addDisallowedApplication(pkg)
            } catch (e: Throwable) {
                rejected += pkg
                reasons += "${pkg}: ${e.message ?: e.javaClass.simpleName}"
            }
        }
        if (rejected.isNotEmpty()) throw Failure(rejected, reasons)
    }
}

internal object TunEstablishment {
    /**
     * The exact sequence the service runs: loop avoidance first, then `establish()`.
     *
     * Extracted as a function over two lambdas so a test can prove that a failing
     * `addDisallowedApplication` short-circuits before the tunnel exists — the
     * defect was a `catch (_: Exception) { }` between the two calls.
     */
    fun establish(
        exempt: DisallowApplication,
        packages: List<String>,
        openTun: () -> ParcelFileDescriptor?,
    ): ParcelFileDescriptor {
        LoopAvoidance.enforce(exempt, packages)
        return openTun() ?: throw IllegalStateException(
            "VpnService.Builder.establish() returned null: the system refused the tunnel " +
                "(another VPN may hold the only slot)",
        )
    }

    /** Adapter from the real Android builder to the testable seam. */
    fun builderFor(builder: VpnService.Builder): DisallowApplication =
        object : DisallowApplication {
            override fun addDisallowedApplication(packageName: String) {
                // The builder's return value is the chaining handle; the routing
                // rule is what matters here, and any rejection propagates as-is.
                builder.addDisallowedApplication(packageName)
            }
        }
}
