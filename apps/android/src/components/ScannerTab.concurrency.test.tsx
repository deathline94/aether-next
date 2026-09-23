// @vitest-environment jsdom
/*
 * The phone's half of the same promise as `apps/desktop/src/components/ScannerTab.concurrency.test.tsx`:
 * the lane *control*, the hint beside it, the log line and the number in the request
 * are one value, or the panel is describing a run that is not happening.
 *
 * The two front-ends are forks of this hook, and this is the defect that fork
 * produced: the field opened at 250 lanes on a protocol whose ceiling is 16, so the
 * first screen of a fresh scanner advertised fifteen times the lanes the engine will
 * put through a QUIC handshake — and then, when Scan was pressed, ran 16 without
 * saying so. Nothing here reads the hook's private state; it reads the spinbutton,
 * the hint text, the announced line and the arguments that reached the bridge.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import {
  SCAN_DEFAULT_CONCURRENCY,
  SCAN_MAX_CONCURRENCY,
  SCAN_MAX_CONCURRENCY_H3,
  SCAN_MIN_CONCURRENCY,
} from "@aether/ui";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(async (_cmd: string, _args?: Record<string, unknown>) => null),
  listen: vi.fn(async () => () => {}),
}));

vi.mock("../bridge", () => ({ invoke: mocks.invoke, listen: mocks.listen }));

import { useScanner } from "../hooks/useScanner";
import { ScannerTab } from "./ScannerTab";
import type { LogInput } from "../types";

const logs: LogInput[] = [];
const appendLog = (entry: LogInput) => {
  logs.push(entry);
};

/** The panel as the app mounts it: the hook's output, verbatim, into the control. */
function ScannerScreen() {
  const scanner = useScanner(appendLog, false);
  return <ScannerTab {...scanner} connectDirect={() => {}} connectBusy={false} />;
}

/** Every range the field prints is the minimum, an en dash, the ceiling: `1–`. */
const rangePrefix = `${SCAN_MIN_CONCURRENCY}\u2013`;

function lanesField(): HTMLInputElement {
  return screen.getByRole("spinbutton", {
    name: /concurrency \(workers\)/i,
  }) as HTMLInputElement;
}

/** The range the field prints under its own label, e.g. `1–16 lanes`. */
function lanesRange(): string {
  const text = screen.getByText(new RegExp(`${rangePrefix}\\d+ lanes`)).textContent ?? "";
  return text.trim();
}

function chooseProtocol(label: "MASQUE H3" | "MASQUE H2" | "WireGuard") {
  const group = screen.getByRole("radiogroup", { name: /target protocol/i });
  fireEvent.click(within(group).getByRole("radio", { name: label }));
}

/** Type a lane count and leave the field, the way committing an edit works. */
function typeLanes(value: string) {
  const field = lanesField();
  fireEvent.change(field, { target: { value } });
  fireEvent.blur(field);
}

function startScan() {
  fireEvent.click(screen.getByRole("button", { name: /start standalone edge scan/i }));
}

function lastScanArgs(): Record<string, unknown> {
  const call = mocks.invoke.mock.calls.filter(([command]) => command === "scan").at(-1);
  if (!call) throw new Error("no scan was ever dispatched");
  return call[1] as Record<string, unknown>;
}

function lastScanAnnouncement(): string {
  const entry = logs.filter((l) => l.message.startsWith("Starting standalone scan")).at(-1);
  if (!entry) throw new Error("the scan announced no parameters");
  return entry.message;
}

beforeEach(() => {
  logs.length = 0;
  vi.clearAllMocks();
  mocks.invoke.mockResolvedValue(null);
  mocks.listen.mockResolvedValue(() => {});
});

afterEach(() => cleanup());

describe("scanner lane control agrees with the run it starts", () => {
  it("opens on a lane count the protocol it opens on can actually run", () => {
    render(<ScannerScreen />);

    // The control, its ceiling and its hint, all read together: a field showing a
    // number above its own `max` is a field showing a number that will not run.
    const shown = lanesField().value;
    expect(shown).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    expect(lanesField().getAttribute("max")).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    expect(lanesRange()).toBe(`${rangePrefix}${SCAN_MAX_CONCURRENCY_H3} lanes`);

    startScan();
    expect(Number(lastScanArgs().concurrency)).toBe(Number(shown));
    expect(lastScanAnnouncement()).toContain(`concurrency=${shown}`);
  });

  it("drops back to the H3 ceiling when a wide protocol is left behind", () => {
    render(<ScannerScreen />);

    // A protocol that can carry the lanes: fill the field with 250 and check the
    // panel really shows 250, so the assertion below cannot pass by never setting it.
    chooseProtocol("MASQUE H2");
    typeLanes("250");
    expect(lanesField().value).toBe("250");
    expect(lanesRange()).toBe(`${rangePrefix}${SCAN_MAX_CONCURRENCY} lanes`);

    // Back to QUIC, where more concurrent BoringSSL handshakes abort the engine.
    chooseProtocol("MASQUE H3");
    expect(lanesField().value).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    expect(lanesField().getAttribute("max")).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    expect(lanesRange()).toBe(`${rangePrefix}${SCAN_MAX_CONCURRENCY_H3} lanes`);

    startScan();
    // Payload, log line and the number on screen: the H3 ceiling, in all three.
    expect(Number(lastScanArgs().concurrency)).toBe(SCAN_MAX_CONCURRENCY_H3);
    expect(lastScanAnnouncement()).toContain(`concurrency=${SCAN_MAX_CONCURRENCY_H3}`);
    expect(lanesField().value).toBe(String(SCAN_MAX_CONCURRENCY_H3));
  });

  it("keeps the lane count the user chose for a transport that can carry it", () => {
    // The clamp is on what a protocol can run, not on what was asked for: erasing
    // 250 the moment H3 is selected would quietly reset a deliberate choice, which
    // is the behaviour `scanNoizeFor` already set for the noise profile.
    render(<ScannerScreen />);
    chooseProtocol("MASQUE H2");
    typeLanes("250");
    chooseProtocol("MASQUE H3");
    expect(lanesField().value).toBe(String(SCAN_MAX_CONCURRENCY_H3));
    chooseProtocol("MASQUE H2");
    expect(lanesField().value).toBe("250");
  });

  /*
   * The phone's copy of desktop's fourth case, and the reason it is not covered by
   * the three above: `concurrency` on screen is `clampConcurrency(requested,
   * protocol)`, so a wrong *stored* default is invisible on the protocol the panel
   * opens on — the field showed 16 while the state underneath it was still 250, and
   * the first click on a wide protocol put that 250 on the wire. Every assertion in
   * the first case would have passed on the buggy build; only leaving the clamp
   * behind, and coming back, watches the initial value `useScanner` is seeded with.
   */
  it("opens on one default for every protocol, not on a width only a cheap scan can take", () => {
    render(<ScannerScreen />);
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));

    // The two protocols whose ceiling is 500 lanes: the clamp has nothing to hide
    // behind there, so the number on screen is the number that was seeded.
    chooseProtocol("MASQUE H2");
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));
    chooseProtocol("WireGuard");
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));

    // Back to QUIC, where the display clamp would have hidden a wider default.
    chooseProtocol("MASQUE H3");
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));

    startScan();
    expect(Number(lastScanArgs().concurrency)).toBe(SCAN_DEFAULT_CONCURRENCY);
  });
});
