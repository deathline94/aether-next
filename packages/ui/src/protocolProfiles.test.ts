import { beforeEach, describe, expect, it } from "vitest";
import {
  applyProtocolScopedPatch,
  clearProtocolProfiles,
  protocolProfileKey,
  syncProtocolProfile,
} from "./protocolProfiles";

const mem = new Map<string, string>();
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    localStorage: {
      getItem: (k: string) => mem.get(k) ?? null,
      setItem: (k: string, v: string) => { mem.set(k, String(v)); },
      removeItem: (k: string) => { mem.delete(k); },
      clear: () => { mem.clear(); },
    },
  },
});

const base = {
  protocol: "masque" as const,
  transport: "h3" as const,
  noize: "medium" as const,
  noizeJc: 5,
  noizeJmin: 50,
  noizeJmax: 128,
  noizeIntervalMs: 0,
  quicInitialFrag: false,
  quicInitialFragSize: 96,
};

describe("protocolProfiles", () => {
  beforeEach(() => {
    mem.clear();
    clearProtocolProfiles();
  });

  it("isolates obfuscation and QUIC fragmentation settings per protocol and transport", () => {
    syncProtocolProfile(base);

    let current = applyProtocolScopedPatch(base, {
      quicInitialFrag: true,
      quicInitialFragSize: 128,
      noize: "off",
    });
    expect(current.noize).toBe("off");
    expect(current.quicInitialFrag).toBe(true);

    current = applyProtocolScopedPatch(current, { protocol: "wireguard" });
    expect(current.protocol).toBe("wireguard");
    expect(current.noize).toBe("off");
    expect(current.quicInitialFrag).toBe(false);

    current = applyProtocolScopedPatch(current, { noize: "light", noizeJc: 7 });
    expect(current.noize).toBe("light");

    current = applyProtocolScopedPatch(current, { protocol: "masque", transport: "h3" });
    expect(current.noize).toBe("off");
    expect(current.quicInitialFrag).toBe(true);
    expect(current.quicInitialFragSize).toBe(128);

    current = applyProtocolScopedPatch(current, { protocol: "wireguard" });
    expect(current.noize).toBe("light");
    expect(current.noizeJc).toBe(7);
  });

  it("keys masque and mim by transport while keying non-masque protocols by protocol", () => {
    expect(protocolProfileKey("masque", "h3")).toBe("masque:h3");
    expect(protocolProfileKey("masque", "h2")).toBe("masque:h2");
    expect(protocolProfileKey("mim", "h3")).toBe("mim:h3");
    expect(protocolProfileKey("wireguard", "h2")).toBe("wireguard");
    expect(protocolProfileKey("gool", "h3")).toBe("gool");
  });
});
