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
      className={`toggle tactile-toggle ${checked ? "on" : ""}`}
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
    const current = Number.parseInt(draft, 10) || value;
    commit(current + delta);
  };

  return (
    <div className={`stepper-input-wrapper ${disabled ? "disabled" : ""}`}>
      <button
        type="button"
        className="stepper-btn dec"
        onClick={() => handleStep(-step)}
        disabled={disabled || (Number.parseInt(draft, 10) || value) <= min}
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
        className="clean-number-input"
        onChange={(e) => setDraft(e.target.value)}
        onBlur={() => commit()}
        onKeyDown={(e) => { if (e.key === "Enter") commit(); }}
      />
      {suffix && <span className="stepper-suffix">{suffix}</span>}
      <button
        type="button"
        className="stepper-btn inc"
        onClick={() => handleStep(step)}
        disabled={disabled || (Number.parseInt(draft, 10) || value) >= max}
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
    <span className={`tactile-badge ${variant} ${className}`}>
      <span className="tactile-badge-dot" aria-hidden="true" />
      <span className="tactile-badge-text">{children}</span>
    </span>
  );
}
