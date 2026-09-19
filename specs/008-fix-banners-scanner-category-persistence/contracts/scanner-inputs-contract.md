# Scanner Inputs CSS & Component Contract

## CSS Classes for Stepper Inputs

```css
.stepper-input-wrapper {
  display: inline-flex;
  align-items: center;
  justify-content: space-between;
  background: #07090b;
  border: 1px solid var(--border-card);
  border-radius: 7px;
  overflow: hidden;
  height: 36px;
  width: 130px;
  transition: border-color 0.15s, box-shadow 0.15s;
}

.stepper-input-wrapper:focus-within {
  border-color: var(--emerald);
  box-shadow: 0 0 0 1px var(--emerald-dim);
}

.stepper-btn {
  width: 32px;
  height: 100%;
  display: grid;
  place-items: center;
  background: rgba(255, 255, 255, 0.03);
  border: 0;
  color: var(--muted);
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  padding: 0;
  flex-shrink: 0;
  transition: background 0.15s, color 0.15s;
}

.stepper-btn:hover:not(:disabled) {
  background: rgba(255, 255, 255, 0.08);
  color: #ffffff;
}

.clean-number-input {
  -moz-appearance: textfield;
  border: 0;
  outline: none;
  background: transparent;
  color: #ffffff;
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 600;
  text-align: center;
  flex: 1;
  min-width: 0;
  padding: 0 4px;
}
```

## Component Step Contract (`NumberField`)

```tsx
<input
  id={id}
  type="number"
  inputMode="numeric"
  min={min}
  max={max}
  step="any"          /* Permits typing any integer without (val - min) % step error */
  value={draft}
  disabled={disabled}
  aria-label={label}
  className="clean-number-input"
  onChange={(e) => setDraft(e.target.value)}
  onBlur={() => commit()}
  onKeyDown={(e) => { if (e.key === "Enter") commit(); }}
/>
```
