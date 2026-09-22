import { describe, expect, it } from "vitest";
import { errorMessage, ipcError, IpcRejection } from "./ipcError";

describe("ipcError (android)", () => {
  it("reads a structured rejection the envelope carried", () => {
    const e = ipcError({ code: "validation", message: "scanMode must be one of: …", field: "scanMode" });
    expect(e.code).toBe("validation");
    expect(e.field).toBe("scanMode");
  });

  it("keeps the code through an Error wrapper", () => {
    const thrown = new IpcRejection({ code: "disconnect_incomplete", message: "proxy still set" });
    expect(ipcError(thrown).code).toBe("disconnect_incomplete");
    expect(errorMessage(thrown)).toBe("proxy still set");
  });

  it("still works while the native side reports prose", () => {
    expect(ipcError(new Error("engine spawn failed")).code).toBe("unknown");
    expect(errorMessage(new Error("engine spawn failed"))).toBe("engine spawn failed");
    expect(errorMessage("bridge call connect failed: boom")).toBe("bridge call connect failed: boom");
  });
});
