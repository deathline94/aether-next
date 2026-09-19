# Contract: SOCKS DNS Configuration Parser

## Overview
Specifies the parsing rules for `AETHER_DNS` resolver entries in `aether/src/socks.rs`.

## Grammar & Conversion Rules

| Input Format | Example | Parsed SocketAddr |
|---|---|---|
| Bare IPv4 | `1.1.1.1` | `1.1.1.1:53` |
| IPv4 with custom port | `1.1.1.1:5353` | `1.1.1.1:5353` |
| Bare IPv6 | `2606:4700:4700::1111` | `[2606:4700:4700::1111]:53` |
| Bracketed IPv6 without port | `[2606:4700:4700::1111]` | `[2606:4700:4700::1111]:53` |
| Bracketed IPv6 with custom port | `[2606:4700:4700::1111]:5353` | `[2606:4700:4700::1111]:5353` |

## Parser Logic
```rust
fn parse_dns_entry(entry: &str) -> Option<SocketAddr> {
    let p = entry.trim();
    if p.is_empty() {
        return None;
    }
    // 1. If it's a bare IP (IPv4 or unbracketed IPv6), pair with default port 53.
    if let Ok(ip) = p.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    // 2. If it's bracketed without port e.g. "[2606::1]", strip brackets and pair with 53.
    if p.starts_with('[') && p.ends_with(']') {
        if let Ok(ip) = p[1..p.len()-1].parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
    }
    // 3. Otherwise parse as full SocketAddr (e.g. "1.1.1.1:5353" or "[2606::1]:5353").
    p.parse::<SocketAddr>().ok()
}
```
