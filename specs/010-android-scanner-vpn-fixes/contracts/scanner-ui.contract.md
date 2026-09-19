# Contract: Scanner Discovered Gateways UI Layout

**Feature**: [`specs/010-android-scanner-vpn-fixes`](../spec.md)
**Date**: 2026-09-18

---

## 1. Scope
Defines the visual rendering and responsive layout contract for discovered edge gateway items across mobile and desktop viewport sizes.

---

## 2. Breakpoint Specifications

### Mobile Viewports (`max-width: 680px`)
- **Container (`.discovered-row`)**:
  - `display: flex;`
  - `flex-direction: column;`
  - `align-items: stretch;`
  - `gap: 10px;`
  - `padding: 12px 14px;`
  - `border-radius: 8px;`
  - `border: 1px solid var(--border-card);`
  - `background: var(--panel-nested);`

- **Primary Info Row (`.discovered-info`)**:
  - `display: flex;`
  - `align-items: center;`
  - `justify-content: space-between;`
  - `gap: 10px;`
  - `width: 100%;`
  - `overflow-wrap: normal;`

- **Address Display (`.discovered-info code`)**:
  - `white-space: nowrap;`
  - `font-size: 13px;`
  - `font-family: var(--font-mono);`
  - `font-weight: 550;`
  - `flex: 1;`
  - `min-width: 0;`
  - `overflow: hidden;`
  - `text-overflow: ellipsis;`
  - **Constraint**: MUST NOT wrap mid-word or character-by-character.

- **Action Cluster Row (`.discovered-actions`)**:
  - `display: flex;`
  - `align-items: center;`
  - `justify-content: space-between;`
  - `gap: 10px;`
  - `width: 100%;`

- **Connect Direct Button (`.connect-direct-btn`)**:
  - `flex: 1;`
  - `height: 34px;`
  - `min-height: 34px;`
  - `font-size: 12px;`
  - `border-radius: 6px;`
  - Touch target satisfies mobile minimum accessible touch area.

---

### Desktop Viewports (`min-width: 681px`)
- **Container (`.discovered-row`)**:
  - `display: flex;`
  - `flex-direction: row;`
  - `align-items: center;`
  - `justify-content: space-between;`
  - `gap: 14px;`
  - `padding: 12px 16px;`

- **Address Display (`.discovered-info code`)**:
  - `white-space: nowrap;`
  - `font-size: 12.5px;`
  - `overflow: hidden;`
  - `text-overflow: ellipsis;`
