import { describe, expect, it } from "vitest";
import {
  defaults,
  parseRuntimeState,
  parseSettings,
} from "./types";
import { isRuntimeStatus } from "../../../packages/ui/src";

/** Every field the shell's `RuntimeState` serialises, camelCase. */
const shellPayload = {
  status: "connected",
  detail: "Session active",
  pid: 4242,
  endpoint: "104.16.0.1:443",
  handshakeRttMs: 17,
};

describe("parseRuntimeState", () => {
  it("accepts the payload the shell actually sends", () => {
    expect(parseRuntimeState(shellPayload)).toEqual({
      status: "connected",
      detail: "Session active",
      pid: 4242,
      endpoint: "104.16.0.1:443",
      handshakeRttMs: 17,
    });
  });

  it("keeps the measured round-trip instead of dropping it", () => {
    // The latency tile was regex-scraped out of `test_connection` prose while the
    // real `handshakeRttMs` arrived on every state event and nothing read it.
    expect(parseRuntimeState(shellPayload)?.handshakeRttMs).toBe(17);
    expect(parseRuntimeState({ ...shellPayload, handshakeRttMs: null })?.handshakeRttMs).toBeNull();
    expect(parseRuntimeState({ ...shellPayload, handshakeRttMs: "17" })?.handshakeRttMs).toBeNull();
  });

  it("rejects a status the UI has no copy for rather than rendering it", () => {
    // `heroCopy[status]` missing throws at render and white-screens the window.
    expect(parseRuntimeState({ ...shellPayload, status: "reconnecting" })).toBeNull();
    expect(parseRuntimeState({ ...shellPayload, status: null })).toBeNull();
    expect(parseRuntimeState("connected")).toBeNull();
    expect(parseRuntimeState(null)).toBeNull();
    expect(isRuntimeStatus("bogus")).toBe(false);
  });

  it("falls back to the harmless shape for absent optional fields", () => {
    expect(parseRuntimeState({ status: "disconnected" })).toEqual({
      status: "disconnected",
      detail: "",
      pid: null,
      endpoint: null,
      handshakeRttMs: null,
    });
  });
});

describe("parseSettings", () => {
  it("returns a full Settings object for the shell's own payload", () => {
    const { settings, corrected } = parseSettings(shellSettings());
    expect(corrected).toEqual([]);
    expect(Object.keys(settings).sort()).toEqual(Object.keys(defaults).sort());
  });

  it("merges over the defaults instead of replacing them", () => {
    // A shell build that drops `ipVersion` used to hand the UI `undefined`, and
    // `settings.ipVersion.toUpperCase()` threw on the next render.
    const dropped = { ...shellSettings(), ipVersion: undefined };
    delete (dropped as Record<string, unknown>).ipVersion;
    const { settings, corrected } = parseSettings(dropped);
    expect(settings.ipVersion).toBe(defaults.ipVersion);
    expect(corrected).toContain("ipVersion");
    expect(settings.protocol).toBe("gool");
  });

  it("corrects a value outside the wire enum rather than trusting it", () => {
    const { settings, corrected } = parseSettings({
      ...shellSettings(),
      routingMode: "system",
      noize: "turbo-udp",
      socksPort: "1080",
      launchAtLogin: "yes",
    });
    expect(settings.routingMode).toBe(defaults.routingMode);
    expect(settings.noize).toBe(defaults.noize);
    expect(settings.socksPort).toBe(defaults.socksPort);
    expect(settings.launchAtLogin).toBe(defaults.launchAtLogin);
    expect(corrected.sort()).toEqual(["launchAtLogin", "noize", "routingMode", "socksPort"]);
  });

  it("keeps the legal zero and the legal 'off' rather than treating them as missing", () => {
    const { settings, corrected } = parseSettings(
      shellSettings({ noize: "off", noizeIntervalMs: 0, peer: "" }),
    );
    expect(settings.noize).toBe("off");
    expect(settings.noizeIntervalMs).toBe(0);
    expect(corrected).toEqual([]);
  });

  it("tolerates garbage input entirely", () => {
    for (const junk of [null, undefined, "settings", 7, []]) {
      const { settings, corrected } = parseSettings(junk);
      expect(settings).toEqual(defaults);
      expect(corrected.length).toBeGreaterThan(0);
    }
  });
});

/** What `get_settings` returns today: every field of the Rust `Settings`. */
export function shellSettings(over: Record<string, unknown> = {}) {
  return {
    protocol: "gool",
    transport: "h2",
    scanMode: "ironclad",
    ipVersion: "both",
    noize: "medium",
    noizeJc: 5,
    noizeJmin: 50,
    noizeJmax: 128,
    noizeIntervalMs: 0,
    routingMode: "tun",
    socksPort: 1080,
    httpPort: 8080,
    startMinimized: false,
    launchAtLogin: true,
    enginePath: "C:\\aether.exe",
    peer: "104.16.0.1:443",
    quicInitialFrag: true,
    quicInitialFragSize: 96,
    ...over,
  };
}
