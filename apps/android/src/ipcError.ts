/**
 * The mapping lives in `packages/ui`, in one copy shared by both frontends; this
 * file is only each frontend's import path for it. That module's own comment says
 * why there is one: the two copies had drifted in the `Error` branch, and a
 * structured rejection kept its code on one platform and lost it on the other.
 */
export {
  ipcError,
  errorMessage,
  errorCode,
  errorField,
  IpcRejection,
} from "../../../packages/ui/src/ipcError";
export type { IpcError } from "../../../packages/ui/src/ipcError";
