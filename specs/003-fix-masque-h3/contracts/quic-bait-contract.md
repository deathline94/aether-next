# Interface Contract: QUIC v2 Version Negotiation Bait

**Protocol**: UDP Datagram Exchange
**Target**: Cloudflare Edge Anycast / MASQUE Gateways

---

## 1. Request Datagram Structure (`build_version_bait`)

Total Datagram Length: `1200` octets (padded).

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|1| 0 0 |R R R|                Version (32)                   |
|  (0xc3)       |            0x6b3343cf (QUIC v2)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCID Len (0x08)|             Destination Connection ID (64)    |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|SCID Len (0x08)|                Source Connection ID (64)      |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Token Len(0x00)|   Payload Length (Varint, 2 bytes: 0x44 0x8b) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Padding (0x00...)                      |
|                  (remaining bytes to 1200 total)              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 2. Expected Edge Response: Version Negotiation (RFC 9000 §17.2.1)

A conforming QUIC edge receiving an unsupported version (QUIC v2 `0x6b3343cf`) replies with a Version Negotiation packet:

```text
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|  Unused (7) |                    0x00000000                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCID Len (0x08)|             Destination Connection ID (64)    |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|SCID Len (0x08)|                Source Connection ID (64)      |
+-+-+-+-+-+-+-+-+                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Supported Version 1 (32)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
```

**Verification Rule**:
- First byte has `0x80` set (Long Header).
- Version field equals `0x00000000`.
- Destination Connection ID matches the SCID sent in the bait packet.
- When this packet is received, the client confirms edge UDP reachability and proceeds immediately with the QUIC v1 connection.
