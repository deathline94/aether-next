// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { NumberField, draftNumber } from "./ui";

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
