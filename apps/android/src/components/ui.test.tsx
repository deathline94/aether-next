// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NumberField, Segmented, draftNumber } from "./ui";

// vitest runs without `globals: true`, which disables testing-library's automatic
// cleanup — without this every render in the file stays in the same document and
// the second query finds two of everything.
afterEach(() => cleanup());

describe("draftNumber", () => {
  it("keeps a legitimate zero", () => {
    expect(draftNumber("0", 5)).toBe(0);
  });

  it("falls back only when there is no number at all", () => {
    expect(draftNumber("", 5)).toBe(5);
    expect(draftNumber("abc", 7)).toBe(7);
    expect(draftNumber("12", 5)).toBe(12);
  });
});

describe("NumberField", () => {
  it("steps from a typed zero instead of the previous value", () => {
    // The defect: `parseInt(draft) || value` made "0" indistinguishable from an
    // empty box, so stepping up from 0 committed the number the user had just
    // replaced — and "Burst Interval"'s real minimum is 0.
    const onCommit = vi.fn();
    render(<NumberField label="burst" value={5} min={0} max={10} step={1} onCommit={onCommit} />);
    fireEvent.change(spinbutton(), { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: "Increase burst" }));
    expect(onCommit).toHaveBeenCalledWith(1);
  });

  it("disables the minus button at the real minimum of zero", () => {
    render(<NumberField label="burst" value={5} min={0} max={10} step={1} onCommit={() => {}} />);
    fireEvent.change(spinbutton(), { target: { value: "0" } });
    expect(screen.getByRole("button", { name: "Decrease burst" }).hasAttribute("disabled")).toBe(true);
  });
});

function spinbutton(): HTMLElement {
  return screen.getByRole("spinbutton", { name: "burst" });
}

const PICKS = [
  { value: "masque", label: "MASQUE" },
  { value: "wireguard", label: "WireGuard" },
  { value: "gool", label: "Gool" },
];

describe("Segmented", () => {
  it("is one tab stop, not a column of them", () => {
    // The Android copy rendered every option as its own stop with no key
    // handling — desktop had the roving tabindex. With a keyboard attached,
    // "Carrier Protocol" was three tab stops whose selected member was
    // indistinguishable, and the arrows did nothing.
    render(<Segmented label="Carrier protocol" value="wireguard" options={PICKS} onChange={() => {}} />);
    expect(screen.getAllByRole("radio").map((r) => r.getAttribute("tabindex"))).toEqual([
      "-1",
      "0",
      "-1",
    ]);
  });

  it("moves the selection with the arrow keys", () => {
    const onChange = vi.fn();
    render(<Segmented label="Carrier protocol" value="masque" options={PICKS} onChange={onChange} />);
    fireEvent.keyDown(screen.getAllByRole("radio")[0]!, { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith("wireguard");
    fireEvent.keyDown(screen.getAllByRole("radio")[0]!, { key: "End" });
    expect(onChange).toHaveBeenCalledWith("gool");
  });

  it("stays put while the group is disabled", () => {
    // `settingsLocked` means a live tunnel: the keys must not be able to change
    // the carrier under a running session.
    const onChange = vi.fn();
    render(
      <Segmented
        label="Carrier protocol"
        value="masque"
        options={PICKS}
        disabled
        onChange={onChange}
      />,
    );
    fireEvent.keyDown(screen.getAllByRole("radio")[0]!, { key: "ArrowRight" });
    expect(onChange).not.toHaveBeenCalled();
  });
});
