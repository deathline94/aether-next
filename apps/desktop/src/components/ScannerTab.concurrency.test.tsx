// @vitest-environment jsdom
/*
 * The scanner's lane *control*, the hint beside it, the line it logs and the number
 * it sends are one value — or the panel is describing a run that is not happening.
 *
 * This file renders the real `useScanner` wired to the real `ScannerTab`, because
 * the defect was never in one of those two on its own: the hook clamped on send and
 * displayed the raw number, and the field read its ceiling from the protocol. Each
 * half was defensible; together they showed `250` in a box whose own label said
 * `1–16 lanes` while the engine ran sixteen lanes, on the very first screen of a
 * fresh window — the one a user reads before pressing anything.
 *
 * So nothing here asserts on the hook's private state: it asserts on what the
 * spinbutton *displays*, what the hint says, what the log announced and what
 * reached `invoke("scan")`, all from one render. Those four are the whole promise.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import {
  SCAN_DEFAULT_CONCURRENCY,
  SCAN_MAX_CONCURRENCY,
  SCAN_MAX_CONCURRENCY_H3,
  SCAN_MIN_CONCURRENCY,
} from "@aether/ui";
import { useScanner } from "../hooks/useScanner";
import { ScannerTab } from "./ScannerTab";
import type { LogInput } from "../types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

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
  const call = vi
    .mocked(invoke)
    .mock.calls.filter(([command]) => command === "scan")
    .at(-1);
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
  vi.mocked(invoke).mockResolvedValue(null);
  // A no-op subscription is enough here: the point is what leaves the panel, and
  // an unhandled `listen` rejection would only add a log line this file ignores.
  vi.mocked(listen).mockResolvedValue(() => {});
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

  it("opens on one default for every protocol, not on a width only a cheap scan can take", () => {
    // The 250 this field used to carry was legal for H2 and impossible for the H3
    // the panel opens on, and the clamp alone hid that: the stored number was still
    // 250, so the first click on a wide protocol produced a 250-lane run nobody had
    // asked for. A default has to be chosen for the protocol the scanner actually
    // starts on, which is why it is `SCAN_DEFAULT_CONCURRENCY` and not a literal.
    render(<ScannerScreen />);
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));

    chooseProtocol("MASQUE H2");
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));
    chooseProtocol("WireGuard");
    expect(lanesField().value).toBe(String(SCAN_DEFAULT_CONCURRENCY));

    startScan();
    expect(Number(lastScanArgs().concurrency)).toBe(SCAN_DEFAULT_CONCURRENCY);
  });
});
