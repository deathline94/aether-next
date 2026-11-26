import { useEffect, useRef, useState } from "react";
import { nextOptionIndex } from "@aether/ui";

/**
 * Same radiogroup contract as the desktop control: one stop in the tab order,
 * arrows walk the choice. Without it every option of "Carrier Protocol", "MASQUE
 * Transport" and "IP Pool Family" was its own tab stop, and the keyboard could
 * not tell which one was selected.
 */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
  label,
}: {
  value: T;
  /** Readonly: callers hand over the shared option lists from `@aether/ui/enums`,
      which are declared `as const`-adjacent readonly, without copying. */
  options: readonly { value: T; label: string }[];
  onChange: (value: T) => void;
  disabled?: boolean;
  /** Accessible name for the group. */
  label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const selected = Math.max(0, options.findIndex((option) => option.value === value));

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (disabled) return;
    const next = nextOptionIndex(selected, event.key, options.length);
    if (next === null) return;
    event.preventDefault();
    const option = options[next];
    if (!option) return;
    onChange(option.value);
    refs.current[next]?.focus();
  };

  return (
    <div
      className={`segmented ${disabled ? "disabled" : ""}`}
      role="radiogroup"
      aria-label={label}
      onKeyDown={onKeyDown}
    >
      {options.map((option, index) => (
        <button
          ref={(node) => {
            refs.current[index] = node;
          }}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          // Roving tabindex: the group is one stop, and the arrows move the choice.
          tabIndex={index === selected ? 0 : -1}
          key={option.value}
          disabled={disabled}
          className={value === option.value ? "active" : ""}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

/** Lucide's copy icon, inlined: `packages/ui` has no node_modules of its own, so
    a `lucide-react` import here would not resolve for either app. */
function CopyIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
      <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 6 9 17l-5-5" />
    </svg>
  );
}

export function AetherMark({ size = 24, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={className}
      aria-hidden="true"
    >
      <path
        d="M3.5 18.5 C6.2 7.5 13.5 3.5 20.5 7.5"
        stroke="var(--emerald)"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M5.5 19.5 C8.2 11.2 14.2 8.2 20 11.5"
        stroke="var(--fg)"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 20 C10.6 15 14.5 13.2 18.5 15.2"
        stroke="var(--emerald)"
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/**
 * Copy button that confirms in place — feedback where the user is looking. One
 * implementation for both frontends: the two copies were verbatim twins whose
 * only future difference would have been a fix applied to one of them.
 */
export function CopyButton({ value, label, text, onCopyFailed }: {
  value: string;
  label: string;
  /** Optional visible text label (e.g. "Copy"). Defaults to icon-only. */
  text?: string;
  /** Called when the copy fails; the caller owns how the failure surfaces. */
  onCopyFailed?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  return (
    <button
      type="button"
      className={`tactile-copy-btn ${text ? "with-label" : ""} ${copied ? "copied" : ""}`.trim()}
      aria-label={copied ? "Copied" : label}
      title={copied ? "Copied" : label}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          if (!mountedRef.current) return;
          setCopied(true);
          if (timer.current) clearTimeout(timer.current);
          timer.current = setTimeout(() => {
            if (mountedRef.current) setCopied(false);
          }, 1500);
        } catch {
          if (mountedRef.current) onCopyFailed?.();
        }
      }}
    >
      {text ? (
        <span>{copied ? "Copied" : text}</span>
      ) : copied ? (
        <CheckIcon />
      ) : (
        <CopyIcon />
      )}
    </button>
  );
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Accessible name for the switch. */
  label: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`tactile-toggle ${checked ? "on" : ""}`}
      onClick={() => !disabled && onChange(!checked)}
    >
      <span className="toggle-slider" />
    </button>
  );
}

/**
 * Tactical Number input with draft state and stepper controls:
 * eliminates ugly browser spinner arrows, supports free typing and
 * tactile +/- click adjustments. Clamped on blur/Enter.
 */
/**
 * A draft of "0" is a value, not a missing value. `Number.parseInt(draft, 10) || value`
 * threw every legitimate zero away, so stepping up from 0 jumped back to the previous
 * number and the min/max guards below compared a number the user had already deleted.
 */
export function draftNumber(draft: string, fallback: number): number {
  const parsed = Number.parseInt(draft, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export function NumberField({
  value,
  min,
  max,
  step = 1,
  onCommit,
  disabled,
  label,
  id,
  suffix,
  invalid,
}: {
  value: number;
  min: number;
  max: number;
  step?: number;
  onCommit: (value: number) => void;
  disabled?: boolean;
  label: string;
  id?: string;
  suffix?: string;
  /** The shell rejected the current value; `aria-invalid` is the machine-readable
   *  half, since "which input" must not live only in the message prose. */
  invalid?: boolean;
}) {
  const [draft, setDraft] = useState(String(value));

  // Sync external changes (profile presets, settings hydration).
  useEffect(() => { setDraft(String(value)); }, [value]);

  const commit = (override?: number) => {
    const parsed = override !== undefined ? override : Number.parseInt(draft, 10);
    const next = Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : value;
    setDraft(String(next));
    if (next !== value) onCommit(next);
  };

  const handleStep = (delta: number) => {
    if (disabled) return;
    const current = draftNumber(draft, value);
    commit(current + delta);
  };

  return (
    <div className={`stepper-input-wrapper ${disabled ? "disabled" : ""}`}>
      <button
        type="button"
        className="stepper-btn"
        onClick={() => handleStep(-step)}
        disabled={disabled || (draftNumber(draft, value)) <= min}
        aria-label={`Decrease ${label}`}
      >
        −
      </button>
      <input
        id={id}
        type="number"
        inputMode="numeric"
        min={min}
        max={max}
        step="any"
        value={draft}
        disabled={disabled}
        aria-label={label}
        aria-invalid={invalid || undefined}
        className="clean-number-input"
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => commit()}
        onKeyDown={(e) => { if (e.key === "Enter") commit(); }}
      />
      {suffix && <span className="stepper-suffix">{suffix}</span>}
      <button
        type="button"
        className="stepper-btn"
        onClick={() => handleStep(step)}
        disabled={disabled || (draftNumber(draft, value)) >= max}
        aria-label={`Increase ${label}`}
      >
        +
      </button>
    </div>
  );
}
