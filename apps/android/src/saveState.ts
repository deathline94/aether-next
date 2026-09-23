/**
 * The save lifecycle of the settings form, in one vocabulary.
 *
 * Its own module because both ends of the claim need it and neither should restate
 * it: `hooks/useRuntime.ts` is what knows whether a write is queued, in flight or
 * landed, and `components/SettingsTab.tsx` is what has to say so. It is also the
 * reason this file exists in the Android app only: `App.tsx` forwards the hook's
 * `saved` key straight to the dock, so the lifecycle travels through a prop that a
 * call site may still be filling with a boolean, and the translation belongs in one
 * place rather than in the ternary that renders the sentence.
 */
export type SaveState = "idle" | "dirty" | "saving" | "saved";

/**
 * Read the dock's input as the lifecycle it describes.
 *
 * A boolean is accepted because that is all a call site can pass while the runtime
 * hook's `saved` key is forwarded unchanged, and it is read for the only things it
 * can honestly mean: `true` is a write that just landed, `false` is nothing pending.
 * What it cannot mean is "saving" — that is a claim only an in-flight write may make,
 * and this is the single place that keeps it to the claim.
 */
export function saveStateOf(saved: SaveState | boolean): SaveState {
  if (typeof saved !== "boolean") return saved;
  return saved ? "saved" : "idle";
}

/**
 * What the Settings dock may say, per state the runtime can be in.
 *
 * A pure function rather than markup, because markup is the part of this claim this
 * surface cannot test: under React 19 + jsdom a render that throws is rethrown out of
 * `act()` and the tree unmounts, so a broken status line is invisible here (T186).
 * The wording rule — never "synchronizing" unless a write the app started is
 * outstanding — is checkable, and `SettingsTab` renders exactly what this returns.
 *
 * A refused save is deliberately not a fifth state: it is `dirty` (the value is still
 * not on disk) plus the `IpcError` that names the field the shell rejected, which the
 * dock checks before this table.
 */
export function saveDockCopy(state: SaveState): { text: string; icon: "check" | "pulse" | "pending" | "idle" } {
  switch (state) {
    case "saving":
      return { text: "Synchronizing changes…", icon: "pulse" };
    case "dirty":
      return { text: "Changes are on screen, not on disk yet", icon: "pending" };
    case "saved":
      return { text: "All parameters synchronized with runtime daemon", icon: "check" };
    case "idle":
      return {
        text: "No changes pending — the form matches the profile on disk",
        icon: "idle",
      };
  }
}
