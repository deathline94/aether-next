/**
 * A native/bridge rejection, as it arrives in the UI.
 *
 * `code` is the half a caller is meant to branch on — `disconnect_incomplete`,
 * `anchor_not_published`, `validation` — and `field` names the setting a
 * `validation` error is about. Before the shell (and, for Android, the envelope
 * in `bridge.ts`) carried both, the only thing to branch on was prose, so a
 * rejected value had nowhere to be shown and the save spinner kept spinning.
 *
 * `unwrapEnvelope` still receives prose from the Kotlin side for everything
 * except a structured `error` object, and `ipcError` accepts a bare string, an
 * `Error`, and the object shape alike — the caller should not have to know which
 * layer failed.
 */
export type IpcError = { code: string; message: string; field?: string };

export function ipcError(error: unknown): IpcError {
  if (typeof error === "string") return { code: "unknown", message: error };
  if (error instanceof Error) {
    const detail = (error as Error & { ipc?: IpcError }).ipc;
    if (detail) return detail;
    return { code: "unknown", message: error.message };
  }
  if (error && typeof error === "object") {
    const o = error as Record<string, unknown>;
    return {
      code: typeof o.code === "string" ? o.code : "unknown",
      message: typeof o.message === "string" ? o.message : JSON.stringify(error),
      field: typeof o.field === "string" ? o.field : undefined,
    };
  }
  return { code: "unknown", message: String(error) };
}

export const errorMessage = (error: unknown): string => ipcError(error).message;
export const errorCode = (error: unknown): string => ipcError(error).code;
export const errorField = (error: unknown): string | undefined => ipcError(error).field;

/** An `Error` that keeps the structured rejection the bridge reported. */
export class IpcRejection extends Error {
  readonly ipc: IpcError;
  constructor(detail: IpcError) {
    super(detail.message);
    this.ipc = detail;
  }
}
