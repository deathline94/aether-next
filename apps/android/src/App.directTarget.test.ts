// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { directTarget } from "./App";

/*
 * A direct connect reads the protocol out of whatever label the engine put on the
 * endpoint. The phone accepts `wg` as well as `wireguard`, which the desktop does
 * not, so the rule is pinned here before it moves into the shared package.
 */
describe("direct connect target", () => {
  it("reads WireGuard from the engine's spellings, including the `wg` shorthand", () => {
    expect(directTarget("WG")).toEqual({ protocol: "wireguard", transport: "h2" });
    expect(directTarget("wg")).toEqual({ protocol: "wireguard", transport: "h2" });
    expect(directTarget("wireguard")).toEqual({ protocol: "wireguard", transport: "h2" });
  });

  it("reads MASQUE, and the transport from the same label", () => {
    expect(directTarget("masque-h3")).toEqual({ protocol: "masque", transport: "h3" });
    expect(directTarget("MASQUE H3")).toEqual({ protocol: "masque", transport: "h3" });
    expect(directTarget("MASQUE H2")).toEqual({ protocol: "masque", transport: "h2" });
  });
});
