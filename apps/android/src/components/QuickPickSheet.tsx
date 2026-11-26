import { Check } from "lucide-react";
import { noiseSettingCopy, NORDIC_PROTOCOL_CHOICES, type NordicProtocolChoice } from "@aether/ui/statusCopy";
import { NOIZE_OPTIONS } from "@aether/ui/enums";
import type { Settings } from "../types";

export type SheetKind = null | "protocol" | "routing" | "obfuscation";

interface QuickPickSheetProps {
  sheet: SheetKind;
  settings: Settings;
  activeChoice: NordicProtocolChoice;
  onClose: () => void;
  onPatch: (patch: Partial<Settings>) => void;
}

export function QuickPickSheet({
  sheet,
  settings,
  activeChoice,
  onClose,
  onPatch,
}: QuickPickSheetProps) {
  if (!sheet) return null;
  return (
    <div className="sheet-backdrop" role="presentation" onClick={onClose}>
      <div
        className="bottom-sheet"
        role="dialog"
        aria-modal="true"
        aria-label={`Choose ${sheet}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="sheet-handle" aria-hidden="true" />
        <div className="sheet-header">
          <strong>
            {sheet === "protocol"
              ? "Protocol & Transport"
              : sheet === "routing"
                ? "Routing Mode"
                : "Handshake Obfuscation"}
          </strong>
          <button type="button" className="banner-action" onClick={onClose}>
            Done
          </button>
        </div>

        {sheet === "protocol" && (
          <div className="sheet-options">
            {NORDIC_PROTOCOL_CHOICES.map((choice) => {
              const selected = activeChoice.id === choice.id;
              return (
                <button
                  key={choice.id}
                  type="button"
                  className={`sheet-option-btn ${selected ? "active" : ""}`}
                  onClick={() => {
                    onPatch({ protocol: choice.protocol, transport: choice.transport, peer: "" });
                    onClose();
                  }}
                >
                  <div>
                    <strong>{choice.title}</strong>
                    <span>{choice.subtitle}</span>
                  </div>
                  {selected && (
                    <span className="protocol-check" aria-hidden="true">
                      <Check size={13} strokeWidth={2.6} />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {sheet === "routing" && (
          <div className="sheet-options">
            {[
              {
                mode: "tun" as const,
                title: "Full Device VPN",
                subtitle: "Routes all apps system-wide via Android VpnService",
              },
              {
                mode: "proxy-only" as const,
                title: "Proxy Only",
                subtitle: `Local listeners on 127.0.0.1:${settings.socksPort} & :${settings.httpPort}`,
              },
            ].map((opt) => {
              const selected = settings.routingMode === opt.mode;
              return (
                <button
                  key={opt.mode}
                  type="button"
                  className={`sheet-option-btn ${selected ? "active" : ""}`}
                  onClick={() => {
                    onPatch({ routingMode: opt.mode });
                    onClose();
                  }}
                >
                  <div>
                    <strong>{opt.title}</strong>
                    <span>{opt.subtitle}</span>
                  </div>
                  {selected && (
                    <span className="protocol-check" aria-hidden="true">
                      <Check size={13} strokeWidth={2.6} />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}

        {sheet === "obfuscation" && (
          <div className="sheet-options">
            {NOIZE_OPTIONS.map((opt) => {
              const selected = settings.noize === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  className={`sheet-option-btn ${selected ? "active" : ""}`}
                  onClick={() => {
                    onPatch({ noize: opt.value });
                    onClose();
                  }}
                >
                  <div>
                    <strong>{opt.label}</strong>
                    <span>{noiseSettingCopy({ ...settings, noize: opt.value })}</span>
                  </div>
                  {selected && (
                    <span className="protocol-check" aria-hidden="true">
                      <Check size={13} strokeWidth={2.6} />
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
