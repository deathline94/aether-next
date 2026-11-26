import { Check, ChevronDown } from "lucide-react";
import { useEffect, useState } from "react";
import { ROUTING_MODE_OPTIONS } from "@aether/ui/enums";

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

const ANDROID_ROUTING_LABELS: Record<string, string> = {
  tun: "Full VPN (Android VpnService)",
  "proxy-only": "Proxy Only (Local Listeners)",
};

export function androidRoutingOptions(currentRoutingMode: string): SelectOption[] {
  return ROUTING_MODE_OPTIONS.flatMap((option): SelectOption[] => {
    if (option.value === "system-proxy") {
      return currentRoutingMode === "system-proxy"
        ? [{ value: option.value, label: "System Proxy — stored, not available on Android", disabled: true }]
        : [];
    }
    return [{ value: option.value, label: ANDROID_ROUTING_LABELS[option.value] ?? option.label }];
  });
}

interface SelectSheetProps {
  label: string;
  title: string;
  value: string;
  disabled?: boolean;
  options: readonly SelectOption[];
  onChange: (value: string) => void;
}

/**
 * Theme-aware bottom sheet picker replacing native `<select>` on Android,
 * whose Chromium popup menu ignores dark-mode CSS tokens and renders white.
 */
export function SelectSheet({
  label,
  title,
  value,
  disabled = false,
  options,
  onChange,
}: SelectSheetProps) {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (disabled && open) setOpen(false);
  }, [disabled, open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  const current = options.find((opt) => opt.value === value) ?? options[0];

  return (
    <>
      <button
        type="button"
        className="tactical-select select-sheet-trigger"
        aria-label={label}
        aria-haspopup="listbox"
        aria-expanded={open}
        disabled={disabled}
        onClick={() => setOpen(true)}
      >
        <span>{current?.label ?? value}</span>
        <ChevronDown size={15} aria-hidden="true" />
      </button>

      {open && !disabled && (
        <div className="sheet-backdrop" role="presentation" onClick={() => setOpen(false)}>
          <div
            className="bottom-sheet"
            role="dialog"
            aria-modal="true"
            aria-label={title}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sheet-handle" aria-hidden="true" />
            <div className="sheet-header">
              <strong>{title}</strong>
              <button type="button" className="banner-action" onClick={() => setOpen(false)}>
                Done
              </button>
            </div>
            <div className="sheet-options" role="listbox" aria-label={title}>
              {options.map((opt) => {
                const selected = opt.value === value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    role="option"
                    aria-selected={selected}
                    disabled={opt.disabled}
                    className={`sheet-option-btn ${selected ? "active" : ""}`}
                    onClick={() => {
                      if (opt.disabled) return;
                      onChange(opt.value);
                      setOpen(false);
                    }}
                  >
                    <div>
                      <strong>{opt.label}</strong>
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
          </div>
        </div>
      )}
    </>
  );
}
