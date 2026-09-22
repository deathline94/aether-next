package app.aethernext

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The TUN plan, asserted as data (T207).
 *
 * `VpnService.Builder` arguments used to exist only inside the builder chain, so
 * the single decision that decides whether the device leaks — "exactly one DNS
 * server, and it is the mapdns fake resolver" — could only be checked on
 * hardware. `TunConfig` made it a plan; this is the net under it. The rules below
 * each encode a device-level failure named in `TunConfig`'s own comment, so they
 * are asserted, not merely described.
 */
class TunConfigTest {

    @Test
    fun advertisesExactlyOneDnsServerAndItIsTheFakeResolver() {
        assertEquals(listOf(TunConfig.MAPPED_DNS), TunConfig.dnsPlan())
        // Advertising a public resolver alongside mapdns lets netd answer queries
        // outside the tunnel — and on mobile data, with real IPv6 records.
        for (leaky in listOf("1.1.1.1", "8.8.8.8", "2606:4700:4700::1111")) {
            assertFalse("no public resolver may be advertised: $leaky", TunConfig.dnsPlan().contains(leaky))
        }
    }

    @Test
    fun theDnsAddressStaysInsideTheTunnelSubnet() {
        val (addr, prefix) = TunConfig.addressPlan().first()
        assertEquals(TunConfig.TUN_ADDR, addr)
        // /32 would put 198.18.0.2 off-link and Android's DnsManager would then
        // refuse to route queries to it at all.
        assertEquals(24, prefix)
        assertTrue(
            "mapdns must be reachable inside the advertised subnet",
            covers19818("198.18.0.0", prefix, TunConfig.MAPPED_DNS),
        )
    }

    @Test
    fun oneSlashFifteenRouteCoversBothTunAndMappedRanges() {
        val routes = TunConfig.routePlan()
        assertTrue("a default v4 route is what makes this full-device", routes.contains("0.0.0.0" to 0))
        assertTrue(routes.contains("198.18.0.0" to 15))
        val (v6Addr, v6Prefix) = TunConfig.addressPlan()[1]
        assertEquals(TunConfig.TUN_ADDR_V6, v6Addr)
        assertEquals("IPv6 is point-to-point on a /128", 128, v6Prefix)
        assertTrue("v6 needs its own default route or a carrier bypasses the tunnel", routes.contains("::" to 0))

        // The /15 must span 198.18.0.0/16 (interface + DNS) and 198.19.0.0/16
        // (fake-IP space) — anything narrower leaks the fake-IP block.
        assertTrue(covers19818("198.18.0.0", 15, "198.19.255.254"))
        assertFalse("a /16 would stop short of the mapped range", covers19818("198.18.0.0", 16, "198.19.0.1"))
    }

    @Test
    fun theMtuIsTheIpv6FloorAndThePlanIsAppliedInOrder() {
        assertEquals(1280, TunConfig.MTU)
        assertEquals("v4 before v6: the builder applies them in list order", 2, TunConfig.addressPlan().size)
    }

    @Test
    fun theHevConfigCarriesTheSameNumbersTheTunDoes() {
        val yaml = TunConfig.hevYaml(socksPort = 1819)
        // A drift here means the userspace tunnel is told a different address than
        // the kernel interface carries, which presents as "connected, nothing works".
        assertTrue(yaml.contains("mtu: ${TunConfig.MTU}"))
        assertTrue(yaml.contains("ipv4: ${TunConfig.TUN_ADDR}"))
        assertTrue(yaml.contains("ipv6: '${TunConfig.TUN_ADDR_V6}'"))
        assertTrue(yaml.contains("port: 1819"))
        assertTrue(yaml.contains("address: ${TunConfig.MAPPED_DNS}"))
        assertTrue(yaml.contains("network: ${TunConfig.MAPPED_NETWORK}"))
        assertTrue(yaml.contains("netmask: ${TunConfig.MAPPED_NETMASK}"))
        // SOCKS5 UDP ASSOCIATE is implemented; UDP-in-TCP is not.
        assertTrue(yaml.contains("udp: 'udp'"))
        // ICMP must be rejected, not dropped, or Happy Eyeballs waits out a timeout.
        assertTrue(yaml.contains("icmp: 'reject'"))
    }

    @Test
    fun aChangedSocksPortReachesTheTunnelConfig() {
        assertTrue(TunConfig.hevYaml(1821).contains("port: 1821"))
    }

    @Test
    fun theTunnelNeverAdoptsItsOwnNetworkAsTheUnderlyingOne() {
        // Handing the VPN's own tun to `setUnderlyingNetworks` tells the tunnel to
        // carry itself: every packet re-encapsulates into the interface already
        // carrying it.
        val cellular = "cellular"
        val vpn = "vpn-tun"
        val picked = UnderlyingNetworks.pick(listOf(cellular, vpn)) { it == vpn }
        assertEquals(listOf(cellular), picked)

        val onlyVpn = UnderlyingNetworks.pick(listOf(vpn, "another-vpn")) { it == vpn || it == "another-vpn" }
        assertTrue("every VPN network must be dropped", onlyVpn.isEmpty())
        assertNull(
            "an empty pick publishes nothing, which is `null` — not an empty array",
            UnderlyingNetworks.toUnderlyingArg(onlyVpn) { it.toTypedArray() },
        )
        assertEquals(
            1,
            UnderlyingNetworks.toUnderlyingArg(listOf(cellular)) { it.toTypedArray() }?.size,
        )
    }

    /** True when [ip] lies inside [base]/[prefix] — both dotted-quad, v4 only. */
    private fun covers19818(base: String, prefix: Int, ip: String): Boolean {
        val b = base.split(".").map { it.toInt() }.fold(0L) { acc, part -> (acc shl 8) or part.toLong() }
        val t = ip.split(".").map { it.toInt() }.fold(0L) { acc, part -> (acc shl 8) or part.toLong() }
        val mask = if (prefix == 0) 0L else (-1L shl (32 - prefix)) and 0xFFFFFFFFL
        return (b and mask) == (t and mask)
    }
}
