package app.aethernext

/**
 * The TUN interface and the hev-socks5-tunnel config, expressed as *data* rather
 * than as a chain of `VpnService.Builder` calls.
 *
 * The builder chain used to be the only home for the DNS/route/exclusion surface,
 * which meant the one thing that decides whether the device leaks traffic —
 * "exactly one DNS server, and it is the mapdns fake resolver" — could only be
 * verified on hardware. It is now a plan this object owns and a JVM test can
 * assert; [AetherVpnService.configureTunBuilder] applies the plan and nothing
 * else.
 *
 * The values themselves are unchanged from the previous inline chain, comments
 * included, because each one encodes a device-level failure:
 *  - `/24` on the tunnel address keeps 198.18.0.2 inside the local subnet, or
 *    Android's DnsManager will not route queries to it at all.
 *  - advertising any public resolver (1.1.1.1, the IPv6 ones) lets netd leak
 *    queries and return real IPv6 answers that bypass the tunnel on mobile data.
 *  - the `/15` covers both 198.18.0.0/16 (interface + DNS) and 198.19.0.0/16
 *    (mapdns fake-IP space) in one route.
 *  - IPv6 is a point-to-point /128 address with a default route, which is what
 *    traps it inside the TUN instead of letting a carrier bypass it.
 */
internal object TunConfig {
    const val MTU = 1280
    const val SESSION_NAME = "Aether Next"
    const val TUN_ADDR = "198.18.0.1"
    /** Unique local address for the dual-stack IPv6 tunnel. */
    const val TUN_ADDR_V6 = "fd00:ae::1"
    const val MAPPED_DNS = "198.18.0.2"
    /** RFC 2544 benchmark range, isolated from [TUN_ADDR] and [MAPPED_DNS]. */
    const val MAPPED_NETWORK = "198.19.0.0"
    const val MAPPED_NETMASK = "255.255.0.0"
    const val MAPPED_PORT = 53
    const val CONNECT_TIMEOUT_MS = 5000
    const val TASK_STACK_SIZE = 81920
    const val DNS_CACHE_SIZE = 10000

    /** `address to prefixLength`, in the order the builder must apply them. */
    fun addressPlan(): List<Pair<String, Int>> = listOf(
        TUN_ADDR to 24,
        TUN_ADDR_V6 to 128,
    )

    /** DNS servers advertised to the device. Exactly one, and it is mapdns. */
    fun dnsPlan(): List<String> = listOf(MAPPED_DNS)

    fun routePlan(): List<Pair<String, Int>> = listOf(
        "0.0.0.0" to 0,
        "198.18.0.0" to 15,
        "::" to 0,
    )

    /**
     * hev-socks5-tunnel YAML.
     *
     * `udp: udp` — aether implements standard SOCKS5 UDP ASSOCIATE, not
     * UDP-in-TCP. `mapdns` resolves names through the SOCKS path so apps never
     * depend on raw UDP DNS. `icmp: reject` answers the flows that cannot be
     * routed (unrouteable / IPv6) with ECONNREFUSED or RST, so Happy Eyeballs
     * fails forward to IPv4 immediately instead of waiting out a timeout.
     */
    fun hevYaml(socksPort: Int): String = """
        |tunnel:
        |  mtu: $MTU
        |  ipv4: $TUN_ADDR
        |  ipv6: '$TUN_ADDR_V6'
        |  icmp: 'reject'
        |socks5:
        |  port: $socksPort
        |  address: 127.0.0.1
        |  udp: 'udp'
        |mapdns:
        |  address: $MAPPED_DNS
        |  port: $MAPPED_PORT
        |  network: $MAPPED_NETWORK
        |  netmask: $MAPPED_NETMASK
        |  cache-size: $DNS_CACHE_SIZE
        |misc:
        |  task-stack-size: $TASK_STACK_SIZE
        |  connect-timeout: $CONNECT_TIMEOUT_MS
        |  log-level: warn
        |""".trimMargin()
}

/**
 * Which networks a VPN service may adopt as its *underlying* network (T2xx).
 *
 * `registerDefaultNetworkCallback` reports the VPN's own tun once the tun has
 * become the default network, and handing that network to
 * `setUnderlyingNetworks` tells the tunnel to carry itself: every packet is
 * re-encapsulated into the interface that is already carrying it. The rule is
 * therefore a filter on the capability bit, and the filter is a pure function so
 * a test can prove the VPN network never survives it.
 */
internal object UnderlyingNetworks {

    /**
     * Drop every candidate [hasVpnCapability] reports as a VPN network.
     *
     * @return the networks safe to publish, possibly empty — an empty result means
     *   "publish nothing", which callers express as `null`.
     */
    fun <T> pick(candidates: List<T>, hasVpnCapability: (T) -> Boolean): List<T> =
        candidates.filterNot(hasVpnCapability)

    /** The value `setUnderlyingNetworks` takes: an array, or `null` for "none". */
    fun <T> toUnderlyingArg(networks: List<T>, arrayOf: (List<T>) -> Array<T>): Array<T>? =
        if (networks.isEmpty()) null else arrayOf(networks)
}
