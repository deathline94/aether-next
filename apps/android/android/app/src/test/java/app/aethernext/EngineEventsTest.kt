package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The `AETHER_EVENT` contract (T129). Each case names the engine line it mirrors:
 * the emitter's own source is in `aether/src/session_event.rs`, `aether/src/quic.rs`
 * and `aether/src/masque_h2.rs`.
 */
class EngineEventsTest {

    @Test
    fun aPlainLogLineIsNotAnEvent() {
        assertNull(EngineEvent.parse("[+] socks5 server listening on 127.0.0.1:1819"))
        assertNull(EngineEvent.parse("[+] handshake successful"))
    }

    @Test
    fun anEventPrefixedByTheLoggerFormatStillParses() {
        // `log::info!("AETHER_EVENT {...}")` puts the level and target in front.
        val ev = EngineEvent.parse("2026-09-22T08:00:00.000Z  INFO aether::masque_h2: AETHER_EVENT {\"type\":\"tunnel_ready\",\"transport\":\"h2\"}")
        assertEquals(EngineEvent.TunnelReady("h2"), ev)
    }

    @Test
    fun everyLifecycleVariantOfTheEngineHasACase() {
        val cases = mapOf(
            """AETHER_EVENT {"type":"identity_ready","device_id":"abc","ipv4":"172.16.0.2"}""" to
                EngineEvent.IdentityReady("abc", "172.16.0.2"),
            """AETHER_EVENT {"type":"endpoint_selected","addr":"162.159.198.1:443","protocol":"MASQUE H3"}""" to
                EngineEvent.EndpointSelected("162.159.198.1:443", "MASQUE H3"),
            """AETHER_EVENT {"type":"proxy_ready","socks":"127.0.0.1:1819","http":"127.0.0.1:1820"}""" to
                EngineEvent.ProxyReady("127.0.0.1:1819", "127.0.0.1:1820"),
            """AETHER_EVENT {"type":"tun_ready"}""" to EngineEvent.TunReady,
            """AETHER_EVENT {"type":"connected","detail":"proxy ready"}""" to EngineEvent.Connected("proxy ready"),
            """AETHER_EVENT {"type":"error","message":"no reachable gateway"}""" to
                EngineEvent.Failure("no reachable gateway"),
        )
        for ((line, expected) in cases) {
            val actual = EngineEvent.parse(line)
            assertNotNull("expected $expected for: $line", actual)
            assertEquals(expected, actual)
        }
    }

    @Test
    fun scanVariantsKeepTheirPayloadForTheWebview() {
        val ev = EngineEvent.parse(
            """AETHER_EVENT {"type":"scan_hit","addr":"1.1.1.1:443","rtt":"24ms","rtt_ms":24.5,"protocol":"MASQUE H3"}"""
        )
        assertTrue(ev is EngineEvent.Scan)
        assertEquals("scan_hit", (ev as EngineEvent.Scan).type)
        assertEquals(24.5, ev.payload.getDouble("rtt_ms"), 0.001)
    }

    @Test
    fun truncatedJsonIsReportedAsMalformedRatherThanAbsent() {
        val ev = EngineEvent.parse("AETHER_EVENT {\"type\": \"conn")
        assertTrue("got: $ev", ev is EngineEvent.Malformed)
        assertTrue((ev as EngineEvent.Malformed).raw.startsWith("{\"type\""))
    }

    @Test
    fun anEventWithoutATypeIsMalformed() {
        val ev = EngineEvent.parse("""AETHER_EVENT {"detail":"what is this"}""")
        assertTrue("got: $ev", ev is EngineEvent.Malformed)
        assertEquals("event has no \"type\"", (ev as EngineEvent.Malformed).reason)
    }

    @Test
    fun anEmptyBodyIsMalformed() {
        assertTrue(EngineEvent.parse("AETHER_EVENT ") is EngineEvent.Malformed)
    }

    @Test
    fun aNonObjectBodyIsMalformed() {
        assertTrue(EngineEvent.parse("AETHER_EVENT [1,2,3]") is EngineEvent.Malformed)
        assertTrue(EngineEvent.parse("AETHER_EVENT \"connected\"") is EngineEvent.Malformed)
    }

    @Test
    fun anUnknownButWellFormedTypeIsNotAnError() {
        // A newer engine may add a variant; the shell must see it, count it, and keep
        // the state machine fail-closed instead of treating it as malformed output.
        val ev = EngineEvent.parse("""AETHER_EVENT {"type":"handoff_scheduled","attempt":2}""")
        assertEquals(EngineEvent.Unrecognised("handoff_scheduled"), ev)
    }

    @Test
    fun engineProgressStagesAreNeitherStateNorErrors() {
        // `aether/src/quic.rs` emits `h3_stage` for diagnostics.
        val ev = EngineEvent.parse("""AETHER_EVENT {"type":"h3_stage","stage":"connect" }""")
        assertTrue("got: $ev", ev is EngineEvent.Stage)
    }
}
