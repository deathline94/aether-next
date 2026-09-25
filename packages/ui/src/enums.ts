/*
 * The wire enums, in one place, for both frontends.
 *
 * Before this file the same three vocabularies were restated independently in
 * `apps/desktop/src/types.ts`, `hooks/useScanner.ts`, `components/ScannerTab.tsx`
 * and `components/SettingsTab.tsx` (and again in the four Android copies). That is
 * how the Settings option and the Scanner option for the same setting ended up with
 * different legal values: one carried `"thorogh"` and the other `"both"`, the Rust
 * validator accepted one spelling and rejected the other, and the user could pick a
 * combination in the Scanner that the Settings panel then refused to save, which
 * failed Connect with no visible cause.
 *
 * These are the values the shell's `wire_enum!` definitions serialise to
 * (`apps/desktop/src-tauri/src/lib.rs`), and every one of them is accepted on the
 * wire. `both` is the canonical spelling of `IpVersion::Dual`; it is not the
 * stringly leftover the audit flagged — the defect there was *four private copies*
 * of the list, one of which had drifted. Aliases the shell still reads for old
 * configs (`dual`, `fast`, `deep`, …) deliberately do not appear here: the UI has
 * one spelling per value, and accepting the others is a compatibility concern for
 * the reader, not a menu of near-identical options.
 */

/** Address families to probe. `IpVersion` in the shell. */
export const IP_FAMILIES = ["v4", "v6", "both"] as const;
export type IpFamily = (typeof IP_FAMILIES)[number];
export const IP_FAMILY_OPTIONS: readonly { value: IpFamily; label: string }[] = [
  { value: "v4", label: "IPv4 Only" },
  { value: "v6", label: "IPv6 Only" },
  { value: "both", label: "Dual-Stack" },
];

/**
 * The family as a telemetry tile names it, which is not the menu's wording.
 *
 * "IPv4 Only" is a choice being made; the status line is answering a question, and
 * `settings.ipVersion.toUpperCase()` — which one surface printed — answers it with
 * a stored token. Both apps kept their own spelling of the three answers.
 */
const IP_FAMILY_DISPLAY: Record<IpFamily, string> = {
  v4: "IPv4",
  v6: "IPv6",
  both: "IPv4 + IPv6",
};

export function ipFamilyLabel(ipVersion: IpFamily): string {
  return IP_FAMILY_DISPLAY[ipVersion];
}

/** Probe velocity profile. `ScanMode` in the shell. */
export const SCAN_MODES = ["turbo", "balanced", "thorough", "stealth", "ironclad"] as const;
export type ScanMode = (typeof SCAN_MODES)[number];
export const SCAN_MODE_OPTIONS: readonly { value: ScanMode; label: string }[] = [
  { value: "turbo", label: "Turbo (Highest concurrency, fastest startup)" },
  { value: "balanced", label: "Balanced (Optimal speed and route fidelity)" },
  { value: "thorough", label: "Thorough (Deep probe across extensive pools)" },
  { value: "stealth", label: "Stealth (Low rate to minimize traffic anomaly)" },
  { value: "ironclad", label: "Ironclad (Verify every candidate endpoint)" },
];

/** Tunnel the engine dials. `Protocol` in the shell. */
export const TUNNEL_PROTOCOLS = ["masque", "wireguard", "gool", "mim"] as const;
export type TunnelProtocol = (typeof TUNNEL_PROTOCOLS)[number];
export const TUNNEL_PROTOCOL_OPTIONS: readonly { value: TunnelProtocol; label: string }[] = [
  { value: "masque", label: "MASQUE" },
  { value: "wireguard", label: "WireGuard" },
  { value: "gool", label: "Gool" },
  { value: "mim", label: "MASQUE-in-MASQUE" },
];

/** MASQUE inner transport. `TransportKind` in the shell; `auto` is legacy. */
export const TRANSPORTS = ["h3", "h2"] as const;
export type Transport = (typeof TRANSPORTS)[number];
export const TRANSPORT_OPTIONS: readonly { value: Transport; label: string }[] = [
  { value: "h3", label: "HTTP/3 (QUIC)" },
  { value: "h2", label: "HTTP/2 (TCP)" },
];

/** How the OS is pointed at the engine. `RoutingMode` in the shell. */
export const ROUTING_MODES = ["system-proxy", "proxy-only", "tun"] as const;
export type RoutingMode = (typeof ROUTING_MODES)[number];
export const ROUTING_MODE_OPTIONS: readonly { value: RoutingMode; label: string }[] = [
  { value: "system-proxy", label: "System Proxy" },
  { value: "proxy-only", label: "Proxy Only" },
  { value: "tun", label: "TUN (Full System)" },
];

/**
 * What the standalone scanner probes: the carrier and the transport as one choice,
 * because the Scanner's UI offers the pair together while `Settings` keeps them as
 * two fields. The `masque-*` spellings are the scan command's own vocabulary, not
 * `Settings.protocol`.
 */
export const SCAN_PROTOCOLS = ["masque-h3", "masque-h2", "wireguard"] as const;
export type ScanProtocol = (typeof SCAN_PROTOCOLS)[number];
export const SCAN_PROTOCOL_OPTIONS: readonly { value: ScanProtocol; label: string }[] = [
  { value: "masque-h3", label: "MASQUE H3" },
  { value: "masque-h2", label: "MASQUE H2" },
  { value: "wireguard", label: "WireGuard" },
];

/**
 * Which protocol a results filter is showing. `all` is a view, not a wire value,
 * so it lives beside the protocol list rather than inside it.
 */
export type ScanProtocolFilter = "all" | ScanProtocol;

/** Handshake noise profile. `Settings.noize` / the scan command's `noize`. */
export const NOIZE_PROFILES = ["off", "light", "medium", "high", "max", "custom"] as const;
export type NoizeProfile = (typeof NOIZE_PROFILES)[number];
export const NOIZE_OPTIONS: readonly { value: NoizeProfile; label: string }[] = [
  { value: "off", label: "Off — no noise" },
  { value: "light", label: "Light — low noise" },
  { value: "medium", label: "Medium — default" },
  { value: "high", label: "High — stronger" },
  { value: "max", label: "Max — highest noise" },
  { value: "custom", label: "Custom — manual values" },
];

/** A value from a wire enum, or the default when something else arrived. */
export function oneOf<T extends string>(
  value: unknown,
  allowed: readonly T[],
  fallback: T,
): T {
  return typeof value === "string" && (allowed as readonly string[]).includes(value)
    ? (value as T)
    : fallback;
}

/**
 * Severities the engine's lines and the console's badges speak with. Both apps
 * spelled this union inline, which is how a fourth level added on one surface
 * would be `undefined` on the other.
 */
export const LOG_LEVELS = ["info", "warn", "error"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/**
 * The four one-tap speed presets, as far as they are the same on both surfaces.
 *
 * Each app used to keep its own copy of this table, and they had already begun to
 * disagree: the same four ids in the same order, but "balanced scan" against
 * "balanced" in the hint, and `transport` written out per row where a missing key
 * would silently leave the previous profile's transport in place. What genuinely
 * differs is where the traffic leaves the device - the desktop patches
 * `routingMode: "system-proxy"`, the phone `"tun"` with no pinned peer - so that
 * is the one input, and the ids, labels and protocol/transport pairing are shared.
 */
export const SPEED_PROFILES = [
  {
    id: "masque-h3",
    label: "MASQUE H3",
    hintSubject: "MASQUE H3",
    protocol: "masque",
    transport: "h3",
  },
  {
    id: "masque-h2",
    label: "MASQUE H2 (Default)",
    hintSubject: "MASQUE H2",
    protocol: "masque",
    transport: "h2",
  },
  {
    id: "mim",
    label: "MASQUE-in-MASQUE",
    hintSubject: "MASQUE-in-MASQUE (dual hop)",
    protocol: "mim",
    transport: "h3",
  },
  {
    id: "wireguard",
    label: "WireGuard",
    hintSubject: "WireGuard",
    protocol: "wireguard",
    transport: "h2",
  },
  {
    id: "gool",
    label: "Gool",
    hintSubject: "Gool (WARP-in-WARP)",
    protocol: "gool",
    transport: "h2",
  },
] as const;

export type SpeedProfile = (typeof SPEED_PROFILES)[number];

/** The row's own words for the hint: `MASQUE H3`, `Gool (WARP-in-WARP)`. */
export function speedProfileName(profile: SpeedProfile): string {
  return profile.hintSubject;
}

/**
 * The line under the preset's name: what it sets, in the order the settings
 * screen shows them, ending in where the traffic goes.
 */
export function speedProfileHint(profile: SpeedProfile, routingLabel: string): string {
  return `${speedProfileName(profile)} · noise off · balanced scan · ${routingLabel}`;
}
