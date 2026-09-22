import { describe, expect, it } from "vitest";
import { errorCode, errorMessage, ipcError } from "./ipcError";

describe("ipcError", () => {
  it("reads the code the shell sends", () => {
    const e = ipcError({ code: "disconnect_incomplete", message: "proxy still set" });
    expect(e.code).toBe("disconnect_incomplete");
    expect(e.message).toBe("proxy still set");
    expect(e.field).toBeUndefined();
  });

  it("keeps the field a validation error names", () => {
    const e = ipcError({ code: "validation", message: "HTTP port must be 1024–65535", field: "httpPort" });
    expect(e.field).toBe("httpPort");
  });

  it("survives a bridge that rejects with prose", () => {
    expect(errorMessage("engine spawn failed")).toBe("engine spawn failed");
    expect(errorCode("engine spawn failed")).toBe("unknown");
    expect(errorCode(new Error("boom"))).toBe("unknown");
    expect(errorMessage(new Error("boom"))).toBe("boom");
  });

  it("never hands the UI [object Object]", () => {
    const shellError = { code: "not_found", message: "wintun.dll is missing" };
    expect(errorMessage(shellError)).toBe("wintun.dll is missing");
    expect(errorMessage(null)).toBe("null");
  });
});
