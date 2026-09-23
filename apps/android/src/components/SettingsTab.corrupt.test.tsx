// @vitest-environment jsdom
/*
 * ITEM 10's last visible piece: the Settings panel has to agree with the banner the
 * workspace shows.
 *
 * The corrupt case is the one where the screen lies hardest — what is on it are the
 * built-in defaults, not the user's profile, and every write the shell refuses from
 * here on is refused *because* of that. `App.tsx` says so above the tabs, because the
 * same refusal stops `connect()` on whatever tab the user happens to be on; the panel
 * they navigate to in order to fix it used to say nothing, which left the diagnosis and
 * its remedy two screens apart.
 *
 * The class names are asserted literally rather than looked up in the sheet: this app's
 * `css-class-resolution` gate reddens on a class the sheets do not define, so the
 * banner may reuse `error-banner` / `error-banner-content` / `banner-action` and
 * nothing else — `@types/node` is not installed here, and a test that reads CSS off disk
 * would be a second, weaker copy of that gate.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ComponentProps } from "react";
import { SettingsTab } from "./SettingsTab";
import { defaults } from "../types";

afterEach(() => cleanup());

const NOTICE =
  "Your saved settings could not be read at 22/09/2026 09:15:00: expected a value at protocol. " +
  "They were kept on the device, not overwritten.";

type Corrupt = NonNullable<ComponentProps<typeof SettingsTab>["corrupt"]>;

function corruptProp(overrides: Partial<Corrupt> = {}): Corrupt {
  return { notice: NOTICE, busy: false, onReset: vi.fn(), ...overrides };
}

function renderTab(corrupt?: Corrupt) {
  render(
    <SettingsTab
      settings={{ ...defaults }}
      settingsLocked={false}
      settingsLoaded={true}
      saved="idle"
      admin={false}
      patchSettings={vi.fn()}
      corrupt={corrupt}
    />,
  );
}

const resetButton = () => screen.getByRole("button", { name: /reset settings/i });

/** The corrupt banner itself, not any of the others the panel can raise. */
function corruptBanner(): HTMLElement {
  const found = screen
    .getAllByRole("alert")
    .find((el) => el.textContent?.includes("SAVED SETTINGS CORRUPT"));
  if (!found) throw new Error("the panel rendered no corrupt-settings banner");
  return found;
}

describe("the corrupt-settings notice inside the panel", () => {
  it("names the refused profile and offers the reset that clears it", () => {
    const onReset = vi.fn();
    renderTab(corruptProp({ onReset }));

    const banner = corruptBanner();
    expect(banner.textContent).toContain(NOTICE);
    // The facts the sentence has to carry, in the panel and not only in the log: the
    // bytes survived, and there is a way out on this screen.
    expect(banner.textContent).toContain("not overwritten");
    expect(resetButton().textContent).toBe("Reset settings");
    expect(onReset).not.toHaveBeenCalled();
  });

  it("reuses the banner vocabulary the sheets already define, and nothing new", () => {
    renderTab(corruptProp());
    const banner = corruptBanner();
    expect(banner.className).toBe("error-banner");
    expect(banner.querySelector(".error-banner-content")).not.toBeNull();
    expect(resetButton().className).toBe("banner-action");
    // A banner with no classes would satisfy the two checks above by accident.
    expect(banner.querySelectorAll("[class]").length).toBeGreaterThan(1);
  });

  it("dispatches the reset the shell needs, and only the reset", () => {
    const onReset = vi.fn();
    const retrySettings = vi.fn();
    render(
      <SettingsTab
        settings={{ ...defaults }}
        settingsLocked={false}
        settingsLoaded={false}
        settingsLoadError={true}
        retrySettings={retrySettings}
        saved="idle"
        admin={false}
        patchSettings={vi.fn()}
        corrupt={corruptProp({ onReset })}
      />,
    );

    fireEvent.click(resetButton());
    expect(onReset).toHaveBeenCalledTimes(1);
    // A corrupt read answers with defaults, so "Retry" is not the remedy: the panel
    // keeps both actions, and pressing one must not press the other.
    expect(retrySettings).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /retry/i })).toBeTruthy();
  });

  it("says it is working while the shell decides, and cannot be pressed twice", () => {
    const onReset = vi.fn();
    renderTab(corruptProp({ busy: true, onReset }));

    // Read by class, not by name: the accessible name *is* the thing under test here.
    const button = corruptBanner().querySelector<HTMLButtonElement>(".banner-action");
    expect(button, "the banner lost its action").not.toBeNull();
    expect(button?.hasAttribute("disabled")).toBe(true);
    expect(button?.textContent).toBe("Resetting…");
    fireEvent.click(button!);
    expect(onReset).not.toHaveBeenCalled();
  });

  it("keeps the corruption visible while the form is locked and unread", () => {
    render(
      <SettingsTab
        settings={{ ...defaults }}
        settingsLocked={true}
        settingsLoaded={false}
        saved="idle"
        admin={false}
        patchSettings={vi.fn()}
        corrupt={corruptProp()}
      />,
    );
    expect(screen.getByText("TUNNEL OPERATIONAL — CONFIGURATION LOCKED")).toBeTruthy();
    expect(corruptBanner()).toBeTruthy();
    // The dock still cannot claim a synchronisation it never started. Read off the dock
    // itself: the lock banner is a live region too, and it says something else.
    const dock = document.querySelector(".save-bar-status");
    expect(dock?.textContent).toContain("Reading configuration profile");
    expect(dock?.textContent).not.toMatch(/synchronizing/i);
  });

  it("shows nothing about corruption on a healthy profile", () => {
    // The control the cases above need: without it, a banner that always rendered would
    // pass every one of them.
    renderTab(undefined);
    expect(screen.queryByText("SAVED SETTINGS CORRUPT")).toBeNull();
    expect(screen.queryByRole("button", { name: /reset settings/i })).toBeNull();
    expect(screen.queryAllByRole("alert")).toHaveLength(0);
  });
});
