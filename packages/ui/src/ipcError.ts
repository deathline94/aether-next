/**
 * A shell or bridge rejection, as it arrives in either frontend.
 *
 * `code` is the half a caller is meant to branch on — `disconnect_incomplete`,
 * `anchor_not_published`, `key_service_unavailable`, `validation` — and `field`
 * names the setting a `validation` error is about. Before the shell (and, on
 * Android, the envelope in `bridge.ts`) serialised both, the only thing to branch
 * on was prose: every caller stringified, a rejected value had nowhere to be
 * shown, and the save spinner kept spinning (contract C-IPC-2,
 * `specs/015-full-audit-remediation/contracts/ipc-contract.md`).
 *
 * This is the two frontends' mapping merged into one copy, and the merge is a
 * behaviour fix rather than tidying: they had drifted in the one place that
 * matters. Android attached a structured rejection to an `Error` (`IpcRejection`)
 * and read it back out of the `instanceof Error` branch; the desktop's same
 * branch threw the detail away and reported `unknown`. One failure, one wrapper,
 * a code lost on one platform only.
 */
export type IpcError = { code: string; message: string; field?: string };

/** An `Error` that keeps the structured rejection the bridge reported. */
export class IpcRejection extends Error {
  readonly ipc: IpcError;

  constructor(detail: IpcError) {
    super(detail.message);
    this.name = "IpcRejection";
    this.ipc = detail;
  }
}

/**
 * Reduce anything a rejection handler can receive to `{code, message, field}`:
 * the shell's object shape, a bare string, an `Error`, and an `Error` carrying
 * the structured detail. A caller should not have to know which layer failed.
 */
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
