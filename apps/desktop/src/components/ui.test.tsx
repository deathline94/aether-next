// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { nextOptionIndex } from "@aether/ui";
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

describe("nextOptionIndex", () => {
  it("walks a radio group the way the ARIA pattern says", () => {
    expect(nextOptionIndex(0, "ArrowRight", 3)).toBe(1);
    expect(nextOptionIndex(0, "ArrowDown", 3)).toBe(1);
    expect(nextOptionIndex(1, "ArrowLeft", 3)).toBe(0);
    expect(nextOptionIndex(1, "ArrowUp", 3)).toBe(0);
    expect(nextOptionIndex(2, "ArrowRight", 3)).toBe(0);
    expect(nextOptionIndex(0, "ArrowLeft", 3)).toBe(2);
    expect(nextOptionIndex(1, "Home", 3)).toBe(0);
    expect(nextOptionIndex(1, "End", 3)).toBe(2);
  });

  it("leaves every other key to the browser", () => {
    expect(nextOptionIndex(0, "Tab", 3)).toBeNull();
    expect(nextOptionIndex(0, "a", 3)).toBeNull();
    expect(nextOptionIndex(0, "Enter", 3)).toBeNull();
    expect(nextOptionIndex(0, "ArrowRight", 0)).toBeNull();
  });
});

describe("Segmented", () => {
  const options = [
    { value: "a", label: "Alpha" },
    { value: "b", label: "Beta" },
    { value: "c", label: "Gamma" },
  ];

  it("keeps exactly one radio in the tab order", () => {
    render(<Segmented label="pick" value="b" options={options} onChange={() => {}} />);
    const radios = screen.getAllByRole("radio");
    expect(radios.map((r) => r.getAttribute("tabindex"))).toEqual(["-1", "0", "-1"]);
  });

  it("moves the selection and the focus with the arrow keys", () => {
    const onChange = vi.fn();
    render(<Segmented label="pick" value="a" options={options} onChange={onChange} />);
    const radios = screen.getAllByRole("radio");
    const firstRadio = radios[0];
    const secondRadio = radios[1];
    if (!firstRadio || !secondRadio) throw new Error("the group rendered too few radios");
    fireEvent.keyDown(firstRadio, { key: "ArrowRight" });
    expect(onChange).toHaveBeenCalledWith("b");
    // The button that just took the selection has to be the one under the caret,
    // or the next keystroke moves the wrong thing.
    expect(secondRadio.getAttribute("aria-checked")).toBe("false");
    const focusedAgain = screen.getAllByRole("radio")[0];
    if (!focusedAgain) throw new Error("the group lost its radios");
    fireEvent.keyDown(focusedAgain, { key: "End" });
    expect(onChange).toHaveBeenCalledWith("c");
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

  it("leaves the steppers reachable by keyboard", () => {
    // The native spin buttons are suppressed in CSS, so a `tabIndex={-1}` on the
    // replacements made port, timeout and concurrency inoperable without a mouse.
    render(<NumberField label="burst" value={5} min={0} max={10} step={1} onCommit={() => {}} />);
    for (const name of ["Decrease burst", "Increase burst"]) {
      const btn = screen.getByRole("button", { name });
      expect(btn.hasAttribute("tabindex")).toBe(false);
      expect(btn.tabIndex).toBeGreaterThanOrEqual(0);
    }
  });
});

function spinbutton(): HTMLElement {
  return screen.getByRole("spinbutton", { name: "burst" });
}
