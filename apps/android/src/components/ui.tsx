import { useEffect, useState } from "react";

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
  label,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  disabled?: boolean;
  /** Accessible name for the group. */
  label: string;
}) {
  return (
    <div className={`segmented ${disabled ? "disabled" : ""}`} role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button
          type="button"
          role="radio"
          aria-checked={value === option.value}
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
  /** The shell rejected the current value; marks the input for assistive tech,
   *  because "which field" must not live only in the message prose. */
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
        tabIndex={-1}
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
        tabIndex={-1}
      >
        +
      </button>
    </div>
  );
}

export function Badge({
  children,
  variant = "emerald",
  className = "",
}: {
  children: React.ReactNode;
  variant?: "emerald" | "cyan" | "amber" | "coral" | "violet" | "muted";
  className?: string;
}) {
  return (
    // One badge, not a badge inside a badge: the inner `.tactile-badge` gave every
    // pill a second border, second padding and a second uppercase transform, and
    // the class was declared twice with a 4px and a 999px radius, so which one a
    // badge looked like depended on stylesheet order.
    <span className={`tactile-badge ${variant} ${className}`}>
      <span className="tactile-badge-dot" aria-hidden="true" />
      {children}
    </span>
  );
}
