export type ProtocolTuning = {
  noize: string;
  noizeJc: number;
  noizeJmin: number;
  noizeJmax: number;
  noizeIntervalMs: number;
  quicInitialFrag: boolean;
  quicInitialFragSize: number;
};

export type ProtocolScopedSettings = ProtocolTuning & {
  protocol: string;
  transport: string;
};

const STORAGE_KEY = "aether-protocol-profiles-v1";

const DEFAULT_PROTOCOL_TUNING: ProtocolTuning = {
  noize: "off",
  noizeJc: 5,
  noizeJmin: 50,
  noizeJmax: 128,
  noizeIntervalMs: 0,
  quicInitialFrag: false,
  quicInitialFragSize: 96,
};

const TUNING_KEYS: readonly (keyof ProtocolTuning)[] = [
  "noize",
  "noizeJc",
  "noizeJmin",
  "noizeJmax",
  "noizeIntervalMs",
  "quicInitialFrag",
  "quicInitialFragSize",
];

function supportsTransportSplit(protocol: string): boolean {
  return protocol === "masque" || protocol === "mim";
}

export function protocolProfileKey(protocol: string, transport: string): string {
  return supportsTransportSplit(protocol) ? `${protocol}:${transport}` : protocol;
}

function extractTuning(settings: ProtocolScopedSettings): ProtocolTuning {
  return {
    noize: settings.noize,
    noizeJc: settings.noizeJc,
    noizeJmin: settings.noizeJmin,
    noizeJmax: settings.noizeJmax,
    noizeIntervalMs: settings.noizeIntervalMs,
    quicInitialFrag: settings.quicInitialFrag,
    quicInitialFragSize: settings.quicInitialFragSize,
  };
}

function readProfileStore(): Record<string, Partial<ProtocolTuning>> {
  try {
    if (typeof window === "undefined") return {};
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, Partial<ProtocolTuning>>) : {};
  } catch {
    return {};
  }
}

function writeProfileStore(store: Record<string, Partial<ProtocolTuning>>): void {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // Ignore persistence failures when storage is restricted.
  }
}

function normalizeTuning(partial?: Partial<ProtocolTuning>): ProtocolTuning {
  return {
    ...DEFAULT_PROTOCOL_TUNING,
    ...(partial ?? {}),
  };
}

/** Records the currently active protocol/transport tuning under its profile key. */
export function syncProtocolProfile(settings: ProtocolScopedSettings): void {
  const key = protocolProfileKey(settings.protocol, settings.transport);
  const store = readProfileStore();
  store[key] = extractTuning(settings);
  writeProfileStore(store);
}

/** Clears saved per-protocol obfuscation/framing profiles on explicit settings reset. */
export function clearProtocolProfiles(): void {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore storage removal failures.
  }
}

/**
 * Applies a settings patch while keeping each protocol/transport's obfuscation
 * and fragmentation settings isolated. Switching protocols saves the outgoing
 * profile and restores the target profile (or factory defaults) instead of
 * carrying settings across protocols.
 */
export function applyProtocolScopedPatch<T extends ProtocolScopedSettings>(
  prev: T,
  patch: Partial<T>,
): T {
  const prevKey = protocolProfileKey(prev.protocol, prev.transport);
  const nextProtocol = patch.protocol ?? prev.protocol;
  const nextTransport = patch.transport ?? prev.transport;
  const nextKey = protocolProfileKey(nextProtocol, nextTransport);

  const store = readProfileStore();
  store[prevKey] = extractTuning(prev);

  if (nextKey === prevKey) {
    const merged: T = { ...prev, ...patch };
    store[nextKey] = extractTuning(merged);
    writeProfileStore(store);
    return merged;
  }

  const baseTarget = normalizeTuning(store[nextKey]);
  const patchTuning: Partial<ProtocolTuning> = {};
  for (const k of TUNING_KEYS) {
    if (k in patch && patch[k] !== undefined) {
      (patchTuning as Record<string, unknown>)[k] = patch[k];
    }
  }
  const resolvedTuning = { ...baseTarget, ...patchTuning };
  const merged: T = {
    ...prev,
    ...patch,
    ...resolvedTuning,
    protocol: nextProtocol,
    transport: nextTransport,
  };
  store[nextKey] = resolvedTuning;
  writeProfileStore(store);
  return merged;
}
