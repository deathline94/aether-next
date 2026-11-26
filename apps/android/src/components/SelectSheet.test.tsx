// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { SelectSheet } from "./SelectSheet";

afterEach(() => cleanup());

const OPTIONS = [
  { value: "off", label: "Off — no noise" },
  { value: "light", label: "Light — low noise" },
  { value: "custom", label: "Custom — manual", disabled: true },
];

describe("SelectSheet", () => {
  it("opens a themed listbox sheet, selects an option, and closes on Escape", () => {
    const onChange = vi.fn();
    render(
      <SelectSheet
        label="Obfuscation noise profile"
        title="Handshake Obfuscation"
        value="off"
        options={OPTIONS}
        onChange={onChange}
      />,
    );

    const trigger = screen.getByRole("button", { name: "Obfuscation noise profile" });
    expect(trigger.textContent).toContain("Off — no noise");
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "Handshake Obfuscation" })).toBeTruthy();

    // Disabled option is ignored.
    const disabledOpt = screen.getByRole("option", { name: "Custom — manual" });
    expect((disabledOpt as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(disabledOpt);
    expect(onChange).not.toHaveBeenCalled();

    // Escape closes without calling onChange.
    fireEvent.keyDown(window, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(onChange).not.toHaveBeenCalled();

    // Choosing an enabled option fires onChange and closes the sheet.
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("option", { name: "Light — low noise" }));
    expect(onChange).toHaveBeenCalledWith("light");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("has no axe accessibility violations closed or open", async () => {
    const { container } = render(
      <SelectSheet
        label="Scan mode"
        title="Scan Thoroughness"
        value="off"
        options={OPTIONS}
        onChange={() => {}}
      />,
    );

    const closedResults = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(closedResults.violations).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: "Scan mode" }));
    const openResults = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(openResults.violations).toEqual([]);
  });
});
