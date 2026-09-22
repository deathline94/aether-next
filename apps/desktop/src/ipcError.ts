/**
 * A shell rejection, as it arrives over IPC.
 *
 * `code` is the half the frontend is meant to branch on — `disconnect_incomplete`,
 * `anchor_not_published`, `key_service_unavailable`, `validation` — and `field`
 * names the setting a `validation` error is about. Until the shell serialised
 * both (contract C-IPC-2 in `specs/015-full-audit-remediation/contracts/ipc-contract.md`)
 * the only thing to branch on was prose, so every caller stringified and every
 * field-specific error had nowhere to be shown.
 *
 * The Android bridge still rejects with a plain string, so that shape is handled
 * here rather than at each call site.
 */
export type IpcError = { code: string; message: string; field?: string };

export function ipcError(error: unknown): IpcError {
  if (typeof error === "string") return { code: "unknown", message: error };
  if (error instanceof Error) return { code: "unknown", message: error.message };
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
