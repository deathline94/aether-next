/*
 * What either frontend is allowed to *state* about a session, in one place.
 *
 * This is the copy half of the fork. Both apps describe the same observable
 * facts - which routing mode is on, what state the runtime reports, whether a
 * listener is merely bound or actually wired into the operating system, what the
 * console is doing - and until now each kept its own wording for them. That is
 * not two designs, it is two claims, and the history is the defect list: a hero
 * that read "VPN ACTIVE / Traffic Routed" in a mode that routes nothing, a
 * listener tile that shouted "HTTP proxy configured" in every mode, a console
 * that said "STREAM: LIVE" with no producer, and a Gool session advertising a
 * WIREGUARD carrier on the card whose own headline named the protocol. Each was
 * fixed on one surface and stayed wrong on the other, which is what
 * `frontend-fork-parity` exists to catch and what this file removes.
 *
 * What is deliberately *not* here: layout, class names, which card a sentence
 * sits in, the order a phone scrolls through, and each surface's own section
 * headings. Those are two designs and are meant to differ.
 *
 * What genuinely differs between the platforms arrives as data
 * (`PlatformCapabilities`), not as a second set of strings. The case that
 * started it: Android exposes no API by which an app may set the system proxy,
 * so a stored `system-proxy` profile *degrades* to the local listeners there and
 * is honoured on Windows. Same routing mode, same wire token, two different
 * facts - a branch on the mode alone cannot tell them apart, so the mode comes
 * in with the capability it was honoured under.
 */

import { isRuntimeStatus, noiseIsInert } from "./index";
import type { RuntimeStatus } from "./index";
import type { RoutingMode, Transport, TunnelProtocol } from "./enums";

/**
 * The two things about a platform its copy has to be told, plus the noun the OS
 * level route goes by. `routeName` fills the object slot ("going through the
 * Android VPN") and `routeSubject` the subject slot ("Android's VPN route
 * carries…") because the two sentences need the same route in two grammatical
 * forms, and paraphrasing one of them to fit a single slot is how a claim gets
 * blurred into "the tunnel".
 */
export interface PlatformCapabilities {
  /** May an app on this platform point the OS at a system-wide proxy at all? */
  canSetSystemProxy: boolean;
  /** What the route this app installs goes by, in the object slot. */
  routeName: string;
  /** The same route, phrased to open a sentence. */
  routeSubject: string;
  /** The verb the primary control is used with: a phone is tapped, a desktop clicked. */
  actionVerb: "Tap" | "Click";
}

/** The hero's three lines for a reported status. */
export type HeroLines = { eyebrow: string; title: string; badge: string };

/**
 * The state, named once per state.
 *
 * `connected` is mode-neutral on purpose: which of the two kinds of connected it
 * is belongs to `connectedCopy`, and a hero that out-claims the badge beside it
 * was the original pairing bug. "VPN ACTIVE" and "Route Open" used to sit here
 * for every state including the failed one.
 */
const HERO_COPY: Record<RuntimeStatus, HeroLines> = {
  disconnected: { eyebrow: "NOT CONNECTED", title: "Ready to connect", badge: "NOT CONNECTED" },
  connecting: { eyebrow: "CONNECTING", title: "Connecting…", badge: "CONNECTING" },
  connected: { eyebrow: "CONNECTED", title: "Connected", badge: "CONNECTED" },
  error: { eyebrow: "CONNECTION FAILED", title: "Connection failed", badge: "CONNECTION FAILED" },
};

/** A status the frame guard let through but this table has no line for. */
const UNKNOWN_HERO: HeroLines = {
  eyebrow: "STATE UNKNOWN",
  title: "Status unavailable",
  badge: "STATE UNKNOWN",
};

/**
 * The hero's lines, never `undefined`.
 *
 * Both apps index a table by a status that arrives from the shell, and a miss
 * threw inside a background event and took the window down (T186) - so the
 * lookup is a function here and the fallback says the least, not the most.
 */
export function heroCopy(status: string): HeroLines {
  return isRuntimeStatus(status) ? HERO_COPY[status] : UNKNOWN_HERO;
}

/** The connected-state claim: the badge and the sentence under it. */
export type ConnectedCopy = { badge: string; body: string };

/**
 * What "connected" covers, which is a property of the routing mode - and of
 * whether the platform can honour that mode at all.
 *
 * The `system-proxy` arm is the capability speaking: where an app may set the
 * system proxy it is true that applications following it are covered, and where
 * it may not (Android) the stored mode is the local one and only an application
 * the user re-pointed is carried. Both say "local proxy" in their badge, because
 * in both the coverage really is the local listeners.
 */
export function connectedCopy(mode: RoutingMode, platform: PlatformCapabilities): ConnectedCopy {
  if (mode === "tun") {
    return {
      badge: "CONNECTED · WHOLE DEVICE VPN",
      body: `Every app on this device is going through ${platform.routeName}.`,
    };
  }
  if (mode === "system-proxy" && platform.canSetSystemProxy) {
    return {
      badge: "CONNECTED · SYSTEM PROXY",
      body: "The system proxy is set to Aether's own ports, so applications that follow it are covered.",
    };
  }
  if (mode === "system-proxy") {
    return {
      badge: "CONNECTED · LOCAL PROXY",
      body:
        "This platform does not let an app set the system proxy, so the saved mode acts as the local one: " +
        "only apps you point at Aether's own ports go through it.",
    };
  }
  return {
    badge: "CONNECTED · LOCAL PROXY",
    body:
      "Aether's local proxy ports are open. Only apps you point at them go through it — every other app on this device is untouched.",
  };
}

/** The two listener tiles: what each port is doing right now. */
export type ListenerState = { http: string; socks: string };

/**
 * A bound port is a bound port; only a mode that reaches the operating system may
 * be called configured.
 *
 * Both tiles used to be keyed on `status === "connected"` and printed the widest
 * claim available, so a `tun` session on Windows - where the route is the tunnel
 * device and nothing was written to the proxy settings - read "HTTP proxy
 * configured". Where the platform cannot set a system proxy at all, the
 * `system-proxy` arm says what it actually is: another open listener.
 */
export function portStateCopy(
  connected: boolean,
  mode: RoutingMode,
  platform: PlatformCapabilities,
): ListenerState {
  if (!connected) return { http: "idle", socks: "idle" };
  if (mode === "tun") {
    return {
      http: "HTTP listener available (TUN routes)",
      socks: "SOCKS5 listener available (TUN routes)",
    };
  }
  if (mode === "system-proxy" && platform.canSetSystemProxy) {
    return { http: "HTTP proxy configured", socks: "SOCKS5 configured" };
  }
  return { http: "HTTP listener open", socks: "SOCKS5 listener open" };
}

/**
 * The "what it covers" answer: the short form and the sentence under it.
 *
 * The field is called `answer`, not `value`, on purpose: `wire-tokens-cross-layer`
 * reads a `value:` literal in this package as a token a Settings menu can send to
 * the engine, and these are sentences about a session, not wire values.
 */
export type CoverageClaim = { answer: string; detail: string };

/**
 * Coverage reduced to what this app can observe: the route it installed, or the
 * ports it opened. The port numbers are in the sentence because the sentence is
 * the instruction - it is what the user carries to another application.
 */
export function coverageClaim(
  mode: RoutingMode,
  platform: PlatformCapabilities,
  httpPort: number,
  socksPort: number,
): CoverageClaim {
  if (mode === "tun") {
    return {
      answer: "Whole device",
      detail: `${platform.routeSubject} carries every app on this device.`,
    };
  }
  if (mode === "system-proxy" && platform.canSetSystemProxy) {
    return {
      answer: "Apps that follow the system proxy",
      detail: `The system proxy points at 127.0.0.1:${httpPort} (HTTP) and :${socksPort} (SOCKS5), so applications that read it are covered.`,
    };
  }
  if (mode === "system-proxy") {
    return {
      answer: "Apps you set up",
      detail: `This platform has no API for an app to set the system proxy, so point each app at 127.0.0.1:${httpPort} (HTTP) or :${socksPort} (SOCKS5) yourself.`,
    };
  }
  return {
    answer: "Apps you set up",
    detail: `Give an app the proxy 127.0.0.1:${httpPort} (HTTP) or :${socksPort} (SOCKS5). Other apps keep going directly.`,
  };
}

/**
 * The state as a one-word answer, and the line under it.
 *
 * The answer is what the status row prints; the detail is the native layer's own
 * sentence, which wins when it says something so a frame that reported a reason
 * is never overwritten by the generic one.
 */
const STATE_ANSWER: Record<RuntimeStatus, string> = {
  disconnected: "Not connected",
  connecting: "Connecting",
  connected: "Connected",
  error: "Failed",
};

const STATE_DETAIL: Record<RuntimeStatus, string> = {
  disconnected: "Nothing is running yet.",
  connecting: "Starting the engine…",
  connected: "Session is up.",
  error: "Last attempt failed.",
};

export function stateAnswer(status: string): string {
  return isRuntimeStatus(status) ? STATE_ANSWER[status] : "Unknown";
}

export function stateDetail(status: string, reported: string): string {
  const said = reported.trim();
  if (said) return said;
  return isRuntimeStatus(status) ? STATE_DETAIL[status] : "No detail reported.";
}

/** The server a session is carrying traffic to - or the honest absence of one. */
export type EndpointClaim = { answer: string; detail: string };

/**
 * "Not connected" until the engine reports an address, because the address is the
 * one piece of evidence a user can take to the scanner and the console and check.
 * Both surfaces used to print a different invention for the same empty field - a
 * scan that was not running, a "Dynamic Edge Discovery" that advertised work
 * nobody had asked for.
 */
export function endpointClaim(endpoint: string | null, running: boolean): EndpointClaim {
  return {
    answer: endpoint || (running ? "Finding one…" : "Not connected"),
    detail: endpoint
      ? "The address this session is carrying traffic to."
      : "The address appears here once the session has one.",
  };
}

/**
 * The line the hero shows before anything has run: what the control does, in the
 * verb the control is used with. A phone's is tapped, a desktop's is clicked, and
 * an accessibility label that disagrees with the visible text is a second claim.
 */
export function startHint(platform: PlatformCapabilities): string {
  return `${platform.actionVerb} the power button to connect. Aether opens a private path to Cloudflare's edge; connection status shows what that covers on this device.`;
}

/** The same verb, in the one place the switch tells the user what it will do. */
export function powerHint(running: boolean, platform: PlatformCapabilities): string {
  return `${platform.actionVerb.toUpperCase()} TO ${running ? "DISCONNECT" : "CONNECT"}`;
}

/**
 * The carrier a tunnel runs on, per protocol - exhaustive by construction.
 *
 * Both apps keyed this on two ternary arms, so anything that was not `masque`
 * fell through to "WIREGUARD": a Gool session whose own headline said
 * WARP-in-WARP advertised a carrier it is not, on the same card. A table keyed on
 * the protocol union makes a new protocol a compile error rather than a wrong
 * label, and the two surfaces' spellings ("WIREGUARD" / "WIREGUARD/UDP",
 * "QUIC/UDP x2" / "WARP-IN-WARP") were the same fact said twice.
 */
const CARRIER_COPY: Record<
  TunnelProtocol,
  { chip: (t: Transport) => string; transport: (t: Transport) => string; headline: string }
> = {
  masque: {
    chip: (t) => (t === "h3" ? "QUIC/UDP" : "H2/TLS"),
    transport: (t) => (t === "h3" ? "HTTP/3" : "HTTP/2"),
    headline: "MASQUE",
  },
  gool: {
    chip: () => "QUIC/UDP x2",
    transport: () => "WireGuard in WireGuard",
    headline: "Gool (double WireGuard)",
  },
  wireguard: {
    chip: () => "WIREGUARD",
    transport: () => "UDP WireGuard",
    headline: "WireGuard",
  },
};

export function carrierChip(settings: { protocol: TunnelProtocol; transport: Transport }): string {
  return CARRIER_COPY[settings.protocol].chip(settings.transport);
}

export function transportName(settings: { protocol: TunnelProtocol; transport: Transport }): string {
  return CARRIER_COPY[settings.protocol].transport(settings.transport);
}

/**
 * The protocol card's headline: the name of the protocol, nothing more.
 *
 * It used to print `${protocol} ${transport}` uppercased - "MASQUE H3", "GOOL H3"
 * - two identifiers glued together, and "WARP-in-WARP", a nickname from the
 * protocol's own documentation. The carrier belongs to the chip and the line
 * under it, which is where the shorthand reads as shorthand.
 */
export function protocolHeadline(settings: { protocol: TunnelProtocol; transport: Transport }): string {
  return CARRIER_COPY[settings.protocol].headline;
}

/**
 * The three lines that restate a *setting* as a state, on both surfaces.
 *
 * Each app had its own spelling and each spelling was a claim: "NOISE: AGGRESSIVE"
 * on a transport where the profile is inert, "NEGOTIATED (not observed)" /
 * "Chosen with the server" for a TLS suite nobody measured, "SPLIT (96B)" for a
 * fragmentation the engine may never reach. The wording here is the plain one, and
 * the inertness predicate is the shared `noiseIsInert` rather than a second copy of
 * the reasoning.
 */
export function noiseSettingCopy(settings: {
  protocol: TunnelProtocol;
  transport: Transport;
  noize: string;
}): string {
  if (noiseIsInert(settings.protocol, settings.transport)) return "Off (no QUIC handshake here)";
  return settings.noize === "off" ? "Off" : `On — ${settings.noize} padding`;
}

export function fragSettingCopy(settings: {
  quicInitialFrag: boolean;
  quicInitialFragSize: number;
}): string {
  return settings.quicInitialFrag ? `On — at ${settings.quicInitialFragSize} bytes` : "Off";
}

/**
 * WireGuard's suite is fixed by the protocol, so naming it is a statement about the
 * transport. MASQUE negotiates a TLS 1.3 suite with the peer - frequently an
 * AES-GCM one - and nothing here observes which, so it cannot be asserted.
 */
export function cipherSettingCopy(protocol: TunnelProtocol): string {
  return protocol === "masque" ? "Chosen with the server" : "ChaCha20-Poly1305";
}

/**
 * The server card's chip: what this session is doing with the address above it.
 *
 * "ROUTE ARMED" was printed in `proxy-only`, where no route exists to arm; the
 * honest pair is the one the phone already used, and it is mode-aware.
 */
export function trafficChip(connected: boolean, running: boolean, mode: RoutingMode): string {
  if (connected) return mode === "tun" ? "VPN ROUTING" : "PROXY PORTS OPEN";
  return running ? "STARTING" : "OFF";
}

/** The engine line: up and carrying, coming up, or not running. */
export function engineStateCopy(connected: boolean, running: boolean): string {
  if (connected) return "Engine is up and carrying connections";
  return running ? "Engine is starting" : "Engine stopped — connect to start it";
}

/**
 * The background process, from the one field the runtime reports.
 *
 * A process id is the only evidence either surface has that an engine is running,
 * so both say the same thing about it; "DORMANT" and "Standby Engine" were the same
 * fact in the voice of a subsystem nobody polled.
 */
export function processStateCopy(pid: number | null): { headline: string; chip: string } {
  return pid
    ? { headline: `Running (PID ${pid})`, chip: "RUNNING" }
    : { headline: "Stopped", chip: "STOPPED" };
}

/**
 * The measured round trip, or the honest absence of one.
 *
 * This replaced `testResult.match(/(\d+)\s*ms/i)` — prose scraped for a number. The
 * test command answers with sentences that contain no `ms` at all, so the tile was
 * permanently "not measured" while the shell sent a real round trip on every state
 * frame that nothing read; and on a *failed* test the same regex could catch a
 * timeout figure and print it as a latency. Zero is not a round trip either: a
 * reading of 0 ms would advertise a link better than the wire can deliver, so it
 * counts as nothing having been measured.
 */
export function roundTripLabel(ms: number | null | undefined): string {
  return typeof ms === "number" && Number.isFinite(ms) && ms > 0 ? `${Math.round(ms)} ms` : "not measured";
}

/**
 * The name the connect control gives itself.
 *
 * The accessible name has to agree with what the control visibly does, and it is
 * the one sentence about the button that is not on screen - "Engage tunnel
 * connection" described neither the label nor the effect.
 */
export function powerControlLabel(running: boolean): string {
  return running ? "Disconnect Aether" : "Connect Aether";
}

/** The verification row: what the button will do, and what it says while doing it. */
export function connectionTestCopy(
  connected: boolean,
  testBusy: boolean,
): { prompt: string; button: string } {
  return {
    prompt: connected
      ? "Send one request through Aether to measure the round trip."
      : "Connect first — then run this to check the path works.",
    button: testBusy ? "Testing…" : "Test connection",
  };
}

/** The pinned-peer bar: one carrier is forced, and the button stops it. */
export const PINNED_PEER_LABEL = "Pinned to one server:";
export const PINNED_PEER_CLEAR_LABEL = "Clear (pick a server automatically)";

/**
 * The console's mode tag, in the one tense the app can actually observe.
 *
 * It used to read "STREAM: LIVE" in every state, including the idle disconnected
 * one - a claim about a stream that had no producer, on the panel that is the only
 * place a user goes to find out whether the engine is saying anything. It now
 * names the state it is in, and `status` is the same value the Connection tab's
 * hero reads, so the two surfaces cannot tell two different stories.
 *
 * The fallback covers a status this app does not know: `status` arrives from the
 * runtime, and the console is subscribed to it whatever it says.
 */
export function streamLabel(status: string): string {
  switch (status) {
    case "connected":
      return "Live session logs";
    case "connecting":
      return "Waiting for the engine to start";
    case "error":
      return "Stopped after an error";
    default:
      return "No session running";
  }
}

/** The four console filters, as `useLogs` names them in both apps. */
export type LogFilterId = "milestones" | "hits" | "errors" | "raw";

/**
 * What the four filter chips are actually selected for.
 *
 * The ids come from `useLogs` and cannot change without breaking the store, but
 * "Milestones / Hits / Errors / Raw" is two operator nouns and one enum
 * identifier doing the work of labels: "Hits" is the list of servers the scan
 * answered, and "Raw" is every line. The chip says which, so the count beside it
 * means something - and both consoles list the same four, so they say it once.
 */
export const LOG_FILTER_LABELS: { id: LogFilterId; label: string }[] = [
  { id: "milestones", label: "Key events" },
  { id: "hits", label: "Servers found" },
  { id: "errors", label: "Errors" },
  { id: "raw", label: "All lines" },
];

/** The line under an empty console, which names the chip to press by its label. */
export const LOG_FILTER_HINT =
  '"Key events" keeps only the lines that say something changed. Pick "All lines" to read every line the engine sent.';

/**
 * What the terminal's title strip says.
 *
 * The desktop's spelled itself `session-log · aether@daemon`: a shell prompt
 * promises a shell, and nothing here takes input - a screen reader would have read
 * the typed command as content. Both surfaces now say what the region is.
 */
export const TERMINAL_TITLE = "aether session log · read only";

/**
 * The scan card, in the words a scan is: what is being counted, and what the
 * numbers on it are.
 *
 * The phone had "Checked 40 of 100 addresses / 7 answered / 25 at once / fastest
 * 48 ms" and the desktop "Probed 40 / 100 candidates / 7 working / 25 workers /
 * best 48 ms" over the very same `scan_progress` frame. "Working" is the field
 * name, not a sentence; a user reads it as "is it going well".
 */
export function scanProgressCopy(counts: {
  mode: string;
  scanned: number;
  total: number;
  concurrency: number;
  working: number;
  bestRtt: string | null;
}): {
  headline: string;
  progressLabel: string;
  concurrency: string;
  working: string;
  /** Null when nothing has answered yet: the chip is absent, not empty. */
  fastest: string | null;
} {
  return {
    headline: `Scanning for servers (${counts.mode.toUpperCase()})`,
    progressLabel: `Checked ${counts.scanned.toLocaleString()} of ${counts.total.toLocaleString()} addresses`,
    concurrency: `${counts.concurrency} at once`,
    working: `${counts.working} answered`,
    fastest: counts.bestRtt ? `fastest ${counts.bestRtt}` : null,
  };
}
