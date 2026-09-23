import { describe, expect, it } from "vitest";
import { scrollConsoleToBottom } from "./ActivityTab";
// The console's mode tag is the shared table's, not this app's: the two surfaces
// have to name the same state with the same words.
import { streamLabel } from "@aether/ui/statusCopy";

describe("streamLabel", () => {
  it("names the state the log is actually in", () => {
    expect(streamLabel("connected")).toBe("Live session logs");
    expect(streamLabel("connecting")).toBe("Waiting for the engine to start");
    expect(streamLabel("error")).toBe("Stopped after an error");
    expect(streamLabel("disconnected")).toBe("No session running");
    expect(streamLabel("")).toBe("No session running");
  });

  it("never claims a live stream for a state that has no producer", () => {
    for (const status of ["disconnected", "", "unknown-status"]) {
      expect(streamLabel(status)).not.toMatch(/LIVE/i);
    }
    // Only a session that is actually running may say so.
    expect(streamLabel("connecting")).not.toMatch(/Live/i);
  });
});

describe("scrollConsoleToBottom", () => {
  it("holds the programmatic latch only for the duration of the scroll", () => {
    const latchDuringScroll: boolean[] = [];
    const latch = { current: false };
    const panel = {
      top: 0,
      get scrollTop() {
        return this.top;
      },
      set scrollTop(value: number) {
        latchDuringScroll.push(latch.current);
        this.top = value;
      },
      scrollHeight: 4200,
    };
    let markerArg: unknown = null;

    scrollConsoleToBottom(panel, { scrollIntoView: (arg?: ScrollIntoViewOptions | boolean) => { markerArg = arg; } }, latch);

    // The scroll has to be marked as ours, or the resulting scroll event reads as
    // the user dragging away from the bottom and the follow switches itself off.
    expect(latchDuringScroll).toEqual([true]);
    // ...and unmarked again before returning: the previous version left the reset
    // to requestAnimationFrame, which never runs in a window hidden to the tray,
    // so the latch stuck and genuine user scrolling could no longer pause it.
    expect(latch.current).toBe(false);
    expect(markerArg).toEqual({ behavior: "auto" });
  });

  it("clears the latch even when the marker throws", () => {
    const latch = { current: false };
    expect(() =>
      scrollConsoleToBottom({ scrollTop: 0, scrollHeight: 1 }, {
        scrollIntoView: () => {
          throw new Error("detached node");
        },
      }, latch),
    ).toThrow();
    expect(latch.current).toBe(false);
  });
});
